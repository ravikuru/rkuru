#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import audioop
import base64
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import websockets
from google import genai
from google.genai import types as genai_types

HOST = os.getenv("CALLTURE_GEMINI_WS_HOST", "127.0.0.1")
PORT = int(os.getenv("CALLTURE_GEMINI_WS_PORT", "8788"))
API_KEY = (os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("API_KEY", "").strip())

MODEL = os.getenv("GEMINI_LIVE_MODEL", "gemini-2.5-flash-native-audio-latest").strip()
VOICE = os.getenv("GEMINI_LIVE_VOICE", "Aoede").strip() or "Aoede"
OPENING_PROMPT = os.getenv(
    "GEMINI_DIRECT_OPENING_PROMPT",
    "Say exactly: Hi, this is Callture. How can I help you today?",
).strip()

INPUT_RATE = int(os.getenv("GEMINI_DIRECT_INPUT_RATE", "8000"))
TARGET_INPUT_RATE = int(os.getenv("GEMINI_DIRECT_TARGET_INPUT_RATE", "16000"))
DEFAULT_OUTPUT_RATE = int(os.getenv("GEMINI_DIRECT_OUTPUT_RATE", "24000"))
OUTPUT_STREAM_RATE = max(8000, int(os.getenv("GEMINI_DIRECT_OUTPUT_STREAM_RATE", "8000")))
OUTPUT_GAIN = float(os.getenv("GEMINI_DIRECT_OUTPUT_GAIN", "1.8"))
OUTPUT_AUDIO_TYPE = os.getenv("GEMINI_DIRECT_OUTPUT_AUDIO_TYPE", "rawAudio").strip().casefold()
DEBUG_AUDIO_CHUNKS = max(0, int(os.getenv("GEMINI_DIRECT_DEBUG_AUDIO_CHUNKS", "6")))
OPENING_PROMPT_DELAY_SECONDS = max(0.0, float(os.getenv("GEMINI_DIRECT_OPENING_PROMPT_DELAY_SECONDS", "1.2")))
MAX_SESSION_SECONDS = max(30, int(os.getenv("GEMINI_DIRECT_MAX_SESSION_SECONDS", "1800")))
ENABLE_TEXT_LOG = os.getenv("GEMINI_DIRECT_ENABLE_TEXT_LOG", "0").strip().casefold() in {"1", "true", "yes", "on"}

RATE_RE = re.compile(r"rate=(\d+)")
client = genai.Client(api_key=API_KEY)


def log(message: str) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{ts}] {message}", flush=True)


def safe_token(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z_@.+:#%\\-]", "", (value or ""))[:128]


def output_rate_from_mime(mime_type: str) -> int:
    if not mime_type:
        return DEFAULT_OUTPUT_RATE
    match = RATE_RE.search(mime_type)
    if not match:
        return DEFAULT_OUTPUT_RATE
    try:
        return int(match.group(1))
    except ValueError:
        return DEFAULT_OUTPUT_RATE


@dataclass
class BridgeState:
    call_uuid: str = ""
    caller: str = ""
    did: str = ""
    mix: str = "mono"
    rs_state: Any = None
    out_rs_state: Any = None
    in_audio_log_count: int = 0
    out_audio_log_count: int = 0
    started_at: float = 0.0


def apply_metadata(state: BridgeState, payload_text: str) -> None:
    try:
        payload = json.loads(payload_text)
    except Exception:
        return
    state.call_uuid = safe_token(str(payload.get("uuid", state.call_uuid)))
    state.caller = safe_token(str(payload.get("caller", state.caller)))
    state.did = safe_token(str(payload.get("did", state.did)))
    mix = str(payload.get("mix", state.mix)).strip().casefold()
    if mix in {"mono", "mixed", "stereo"}:
        state.mix = mix


def normalize_input_pcm(chunk: bytes, state: BridgeState) -> bytes:
    raw = chunk
    if state.mix == "stereo":
        # When stereo is provided, downmix both channels to caller mono.
        raw = audioop.tomono(raw, 2, 0.5, 0.5)
    converted, state.rs_state = audioop.ratecv(raw, 2, 1, INPUT_RATE, TARGET_INPUT_RATE, state.rs_state)
    return converted


def normalize_output_pcm(chunk: bytes, input_rate: int, state: BridgeState) -> tuple[bytes, int]:
    raw = chunk[:-1] if len(chunk) % 2 else chunk
    if not raw:
        return b"", OUTPUT_STREAM_RATE
    if abs(OUTPUT_GAIN - 1.0) > 0.01:
        try:
            raw = audioop.mul(raw, 2, OUTPUT_GAIN)
        except Exception:
            pass
    if input_rate != OUTPUT_STREAM_RATE:
        raw, state.out_rs_state = audioop.ratecv(raw, 2, 1, input_rate, OUTPUT_STREAM_RATE, state.out_rs_state)
    return raw, OUTPUT_STREAM_RATE


def _rms16(data: bytes) -> int:
    if not data:
        return 0
    raw = data[:-1] if len(data) % 2 else data
    if not raw:
        return 0
    try:
        return int(audioop.rms(raw, 2))
    except Exception:
        return 0


async def send_stream_audio(websocket: Any, pcm_data: bytes, sample_rate: int, state: BridgeState) -> None:
    if not pcm_data:
        return
    configured_type = OUTPUT_AUDIO_TYPE if OUTPUT_AUDIO_TYPE in {"raw", "rawaudio", "pcmu", "pcma"} else "rawaudio"
    audio_type = "rawAudio" if configured_type in {"raw", "rawaudio"} else configured_type
    out_payload = pcm_data
    out_rate = sample_rate
    if configured_type == "pcmu":
        out_payload = audioop.lin2ulaw(pcm_data, 2)
        out_rate = 8000
    elif configured_type == "pcma":
        out_payload = audioop.lin2alaw(pcm_data, 2)
        out_rate = 8000
    if state.out_audio_log_count < DEBUG_AUDIO_CHUNKS:
        log(
            f"gemini_to_fs_audio uuid={state.call_uuid} type={audio_type} "
            f"sample_rate={out_rate} bytes={len(out_payload)} pcm_rms={_rms16(pcm_data)}"
        )
        state.out_audio_log_count += 1
    payload = {
        "type": "streamAudio",
        "data": {
            "audioDataType": audio_type,
            "sampleRate": out_rate,
            "audioData": base64.b64encode(out_payload).decode("ascii"),
        },
    }
    await websocket.send(json.dumps(payload, separators=(",", ":")))


async def fs_to_gemini(websocket: Any, live_session: Any, state: BridgeState) -> None:
    while True:
        incoming = await websocket.recv()
        if isinstance(incoming, str):
            apply_metadata(state, incoming)
            continue
        if not isinstance(incoming, (bytes, bytearray)):
            continue
        pcm = normalize_input_pcm(bytes(incoming), state)
        if not pcm:
            continue
        if state.in_audio_log_count < DEBUG_AUDIO_CHUNKS:
            log(
                f"fs_to_gemini_audio uuid={state.call_uuid} bytes={len(pcm)} "
                f"pcm_rms={_rms16(pcm)}"
            )
            state.in_audio_log_count += 1
        await live_session.send_realtime_input(
            audio=genai_types.Blob(
                data=pcm,
                mime_type=f"audio/pcm;rate={TARGET_INPUT_RATE}",
            )
        )


async def gemini_to_fs(websocket: Any, live_session: Any, state: BridgeState) -> None:
    async for message in live_session.receive():
        server_content = getattr(message, "server_content", None)
        if not server_content:
            continue
        model_turn = getattr(server_content, "model_turn", None)
        if not model_turn or not getattr(model_turn, "parts", None):
            continue
        for part in model_turn.parts:
            text = getattr(part, "text", None)
            if text and ENABLE_TEXT_LOG:
                log(f"gemini_text uuid={state.call_uuid} text={text[:200]}")
            inline_data = getattr(part, "inline_data", None)
            if inline_data and getattr(inline_data, "data", None):
                out_rate = output_rate_from_mime(getattr(inline_data, "mime_type", ""))
                out_pcm, out_rate = normalize_output_pcm(inline_data.data, out_rate, state)
                await send_stream_audio(websocket, out_pcm, out_rate, state)


async def send_opening_prompt(live_session: Any, state: BridgeState) -> None:
    if not OPENING_PROMPT:
        return
    if OPENING_PROMPT_DELAY_SECONDS:
        await asyncio.sleep(OPENING_PROMPT_DELAY_SECONDS)
    await live_session.send_client_content(
        turns={"role": "user", "parts": [{"text": OPENING_PROMPT}]},
        turn_complete=True,
    )
    log(f"opening_prompt_sent uuid={state.call_uuid}")


async def ws_handler(websocket: Any) -> None:
    state = BridgeState(started_at=time.monotonic())
    log("ws_client_connected")
    if not API_KEY:
        log("ws_client_closed no_api_key")
        await websocket.close(code=1011, reason="Missing API key")
        return

    try:
        config = genai_types.LiveConnectConfig(
            response_modalities=["AUDIO"],
            speech_config=genai_types.SpeechConfig(
                voice_config=genai_types.VoiceConfig(
                    prebuilt_voice_config=genai_types.PrebuiltVoiceConfig(voice_name=VOICE)
                )
            ),
        )
        async with client.aio.live.connect(model=MODEL, config=config) as live_session:
            in_task = asyncio.create_task(fs_to_gemini(websocket, live_session, state))
            out_task = asyncio.create_task(gemini_to_fs(websocket, live_session, state))
            timeout_task = asyncio.create_task(asyncio.sleep(MAX_SESSION_SECONDS))
            prompt_task = asyncio.create_task(send_opening_prompt(live_session, state))

            while True:
                done, _ = await asyncio.wait(
                    {in_task, out_task, timeout_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if timeout_task in done:
                    log(f"ws_session_timeout uuid={state.call_uuid}")
                    break

                if in_task in done:
                    if not in_task.cancelled():
                        exc = in_task.exception()
                        if exc and not isinstance(exc, websockets.exceptions.ConnectionClosed):
                            log(f"ws_task_error uuid={state.call_uuid} err={exc}")
                    break

                if out_task in done:
                    if not out_task.cancelled():
                        exc = out_task.exception()
                        if exc and not isinstance(exc, websockets.exceptions.ConnectionClosed):
                            log(f"ws_task_error uuid={state.call_uuid} err={exc}")
                            break
                    # Some Live sessions end a receive() iterator after a response turn.
                    # Restart output listener so the call can continue bidirectionally.
                    out_task = asyncio.create_task(gemini_to_fs(websocket, live_session, state))

            for task in (in_task, out_task, timeout_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(in_task, out_task, timeout_task, return_exceptions=True)
            if not prompt_task.done():
                prompt_task.cancel()
            await asyncio.gather(prompt_task, return_exceptions=True)
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as exc:
        log(f"ws_handler_error uuid={state.call_uuid} err={exc}")
    finally:
        log(
            f"ws_client_closed uuid={state.call_uuid} did={state.did} "
            f"seconds={int(time.monotonic() - state.started_at)}"
        )


async def main() -> None:
    if not API_KEY:
        raise RuntimeError("GEMINI_API_KEY/API_KEY is required")
    log(f"starting_gemini_direct_bridge host={HOST} port={PORT} model={MODEL}")
    async with websockets.serve(
        ws_handler,
        HOST,
        PORT,
        max_size=None,
        ping_interval=20,
        ping_timeout=20,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

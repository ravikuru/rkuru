#!/usr/bin/env python3
import asyncio
import base64
import datetime
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from google import genai
    from google.genai import types as genai_types
except Exception:
    genai = None
    genai_types = None


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        raw = int(os.getenv(name, str(default)))
    except ValueError:
        raw = default
    return max(minimum, raw)

HOST = "127.0.0.1"
PORT = 9090
LOG_FILE = "/usr/local/freeswitch/log/inbound_socket_agi.log"
PORTAL_DB_PATH = os.getenv("PORTAL_DB_PATH", "/opt/cc_portal/portal.db")
AI_RECORD_DIR = Path(os.getenv("AI_RECORD_DIR", "/tmp/callture_ai"))
AI_NATIVE_CACHE_DIR = Path(os.getenv("AI_NATIVE_CACHE_DIR", "/tmp/callture_ai_native"))
AI_ELEVEN_CACHE_DIR = Path(os.getenv("AI_ELEVEN_CACHE_DIR", "/tmp/callture_ai_eleven"))
MAX_INTENT_ATTEMPTS = _env_int("AI_MAX_INTENT_ATTEMPTS", 2, 1)
DEFAULT_INTENT = os.getenv("AI_DEFAULT_INTENT", "sales").strip().casefold()
DEFAULT_VOICEMAIL_BOX = os.getenv("AI_DEFAULT_VOICEMAIL_BOX", "").strip()
QUEUE_ATTEMPT_SECONDS = _env_int("AI_QUEUE_ATTEMPT_SECONDS", 20, 5)
QUEUE_RETRY_DELAY_MS = _env_int("AI_QUEUE_RETRY_DELAY_MS", 1500, 0)
AI_RECORD_SECONDS = _env_int("AI_RECORD_SECONDS", 6, 3)
AI_WS_STREAM_ENABLED = os.getenv("AI_WS_STREAM_ENABLED", "1").strip().casefold() in {"1", "true", "yes", "on"}
AI_WS_STREAM_URL = os.getenv("AI_WS_STREAM_URL", "ws://127.0.0.1:8788").strip()
AI_WS_STREAM_WAIT_SECONDS = _env_int("AI_WS_STREAM_WAIT_SECONDS", 6, 5)
AI_WS_STREAM_MIX = os.getenv("AI_WS_STREAM_MIX", "mono").strip() or "mono"
AI_WS_STREAM_RATE = os.getenv("AI_WS_STREAM_RATE", "8k").strip() or "8k"
AI_WS_STREAM_TAG = os.getenv("AI_WS_STREAM_TAG", "callture").strip() or "callture"
AI_WS_PRESTREAM_TONE = os.getenv("AI_WS_PRESTREAM_TONE", "1").strip().casefold() in {"1", "true", "yes", "on"}
AI_WS_LOCAL_PROMPT_ENABLED = os.getenv("AI_WS_LOCAL_PROMPT_ENABLED", "0").strip().casefold() in {
    "1",
    "true",
    "yes",
    "on",
}
AI_REALTIME_DIRECT_MODE = os.getenv("AI_REALTIME_DIRECT_MODE", "1").strip().casefold() in {"1", "true", "yes", "on"}
AI_REALTIME_MAX_SECONDS = _env_int("AI_REALTIME_MAX_SECONDS", 900, 30)

ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY", "").strip()
ELEVENLABS_TTS_VOICE_ID = os.getenv("ELEVENLABS_TTS_VOICE_ID", "21m00Tcm4TlvDq8ikWAM").strip()
ELEVENLABS_TTS_MODEL_ID = os.getenv("ELEVENLABS_TTS_MODEL_ID", "eleven_turbo_v2_5").strip()
ELEVENLABS_STT_MODEL_ID = os.getenv("ELEVENLABS_STT_MODEL_ID", "scribe_v1").strip()
GEMINI_INTENT_TIMEOUT_SECONDS = _env_int("GEMINI_INTENT_TIMEOUT_SECONDS", 8, 3)

GEMINI_LIVE_ENABLED = os.getenv("GEMINI_LIVE_ENABLED", "1").strip().casefold() in {"1", "true", "yes", "on"}
GEMINI_LIVE_MODEL = os.getenv("GEMINI_LIVE_MODEL", "gemini-2.5-flash-native-audio-latest").strip()
GEMINI_LIVE_VOICE = os.getenv("GEMINI_LIVE_VOICE", "Aoede").strip() or "Aoede"
GEMINI_LIVE_TIMEOUT_SECONDS = _env_int("GEMINI_LIVE_TIMEOUT_SECONDS", 25, 10)

PROMPT_GREETING_TEXT = os.getenv(
    "AI_GREETING_TEXT",
    "Hi, this is Callture. How can I help you today? You can say sales, support, or billing.",
).strip()
PROMPT_RETRY_TEXT = os.getenv(
    "AI_RETRY_TEXT",
    "Sorry, I did not catch that. Please say sales, support, or billing.",
).strip()
PROMPT_CONNECT_SALES_TEXT = os.getenv(
    "AI_CONNECT_SALES_TEXT",
    "Great, connecting you to sales now.",
).strip()
PROMPT_CONNECT_SUPPORT_TEXT = os.getenv(
    "AI_CONNECT_SUPPORT_TEXT",
    "Sure, connecting you to support now.",
).strip()
PROMPT_CONNECT_BILLING_TEXT = os.getenv(
    "AI_CONNECT_BILLING_TEXT",
    "Okay, connecting you to billing now.",
).strip()
PROMPT_INVALID_TEXT = os.getenv(
    "AI_INVALID_TEXT",
    "I could not route your call right now. Please try again later.",
).strip()
PROMPT_DTMF_FALLBACK_TEXT = os.getenv(
    "AI_DTMF_FALLBACK_TEXT",
    "You can also use your keypad. Press 1 for sales, 2 for support, or 3 for billing.",
).strip()

PROMPT_GREETING = os.getenv(
    "AI_GREETING_WAV",
    "/usr/local/freeswitch/sounds/custom/callture_ai_greeting.wav",
)
PROMPT_RETRY = os.getenv(
    "AI_RETRY_WAV",
    "/usr/local/freeswitch/sounds/custom/callture_ai_retry.wav",
)
PROMPT_CONNECT_SALES = os.getenv(
    "AI_CONNECT_SALES_WAV",
    "/usr/local/freeswitch/sounds/custom/callture_ai_connecting_sales.wav",
)
PROMPT_CONNECT_SUPPORT = os.getenv(
    "AI_CONNECT_SUPPORT_WAV",
    "/usr/local/freeswitch/sounds/custom/callture_ai_connecting_support.wav",
)
PROMPT_CONNECT_BILLING = os.getenv(
    "AI_CONNECT_BILLING_WAV",
    "/usr/local/freeswitch/sounds/custom/callture_ai_connecting_billing.wav",
)
PROMPT_INVALID = os.getenv(
    "AI_INVALID_WAV",
    "/usr/local/freeswitch/sounds/custom/callture_ai_invalid.wav",
)
PROMPT_DTMF_FALLBACK = os.getenv(
    "AI_DTMF_FALLBACK_WAV",
    "/usr/local/freeswitch/sounds/custom/callture_ai_dtmf_fallback.wav",
)

VALID_INTENTS = {"sales", "support", "billing", "invalid"}


def log(message: str) -> None:
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds")
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"[{ts}Z] {message}\n")


def gemini_api_key() -> str:
    return os.getenv("API_KEY", "").strip() or os.getenv("GEMINI_API_KEY", "").strip()


def elevenlabs_api_key() -> str:
    return ELEVENLABS_API_KEY


def _eleven_cache_name(text: str, voice_id: str) -> str:
    digest = hashlib.sha1(f"{voice_id}:{text}".encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"eleven_{digest}.wav"


def _mp3_to_wav_8k(mp3_path: Path, wav_path: Path) -> bool:
    wav_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-i",
                str(mp3_path),
                "-ar",
                "8000",
                "-ac",
                "1",
                "-c:a",
                "pcm_s16le",
                "-af",
                "highpass=f=120,lowpass=f=3400,volume=1.8",
                "-y",
                str(wav_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return wav_path.exists() and wav_path.stat().st_size > 44
    except Exception as exc:
        log(f"elevenlabs_ffmpeg_error err={exc}")
        return False


def generate_elevenlabs_voice_wav(prompt_text: str, *, cacheable: bool = True) -> str:
    if not prompt_text.strip():
        return ""
    api_key = elevenlabs_api_key()
    if not api_key:
        return ""
    if not ELEVENLABS_TTS_VOICE_ID:
        return ""

    AI_ELEVEN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = (
        AI_ELEVEN_CACHE_DIR / _eleven_cache_name(prompt_text, ELEVENLABS_TTS_VOICE_ID)
        if cacheable
        else AI_ELEVEN_CACHE_DIR / f"eleven_live_{uuid.uuid4().hex}.wav"
    )
    if cacheable and out_path.exists() and out_path.stat().st_size > 44:
        return str(out_path)

    endpoint = (
        f"https://api.elevenlabs.io/v1/text-to-speech/{ELEVENLABS_TTS_VOICE_ID}"
        "?output_format=mp3_44100_128"
    )
    payload = {
        "text": prompt_text,
        "model_id": ELEVENLABS_TTS_MODEL_ID or "eleven_turbo_v2_5",
        "voice_settings": {"stability": 0.5, "similarity_boost": 0.8},
    }
    req = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "xi-api-key": api_key,
            "accept": "audio/mpeg",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with tempfile.NamedTemporaryFile(prefix="eleven_", suffix=".mp3", delete=False) as tmpf:
        tmp_mp3 = Path(tmpf.name)
    try:
        with urlopen(req, timeout=20) as resp:
            audio = resp.read()
        if not audio:
            return ""
        tmp_mp3.write_bytes(audio)
        if _mp3_to_wav_8k(tmp_mp3, out_path):
            return str(out_path)
        return ""
    except (HTTPError, URLError, TimeoutError) as exc:
        log(f"elevenlabs_tts_request_failed err={exc}")
        return ""
    except Exception as exc:
        log(f"elevenlabs_tts_error err={exc}")
        return ""
    finally:
        try:
            tmp_mp3.unlink(missing_ok=True)
        except Exception:
            pass


def _native_cache_name(text: str) -> str:
    digest = hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"native_{digest}.wav"


async def _native_audio_from_model_async(prompt_text: str, caller_audio_wav: Path | None = None) -> bytes:
    if genai is None or genai_types is None:
        return b""
    api_key = gemini_api_key()
    if not api_key:
        return b""

    parts: list[dict[str, object]] = [{"text": prompt_text}]
    if caller_audio_wav and caller_audio_wav.exists():
        try:
            parts.append(
                {
                    "inline_data": {
                        "mime_type": "audio/wav",
                        "data": caller_audio_wav.read_bytes(),
                    }
                }
            )
        except Exception as exc:
            log(f"native_audio_input_read_error path={caller_audio_wav} err={exc}")

    cfg = genai_types.LiveConnectConfig(
        response_modalities=["AUDIO"],
        speech_config=genai_types.SpeechConfig(
            voice_config=genai_types.VoiceConfig(
                prebuilt_voice_config=genai_types.PrebuiltVoiceConfig(voice_name=GEMINI_LIVE_VOICE)
            )
        ),
    )
    client = genai.Client(api_key=api_key)
    out = b""
    async with client.aio.live.connect(model=GEMINI_LIVE_MODEL, config=cfg) as session:
        await session.send_client_content(
            turns={"role": "user", "parts": parts},
            turn_complete=True,
        )
        async for msg in session.receive():
            server_content = getattr(msg, "server_content", None)
            if not server_content:
                continue
            model_turn = getattr(server_content, "model_turn", None)
            if model_turn and getattr(model_turn, "parts", None):
                for part in model_turn.parts:
                    inline_data = getattr(part, "inline_data", None)
                    if inline_data and getattr(inline_data, "data", None):
                        out += inline_data.data
            if getattr(server_content, "turn_complete", False):
                break
    return out


def _pcm_24k_to_wav_8k(pcm_data: bytes, wav_path: Path) -> bool:
    if not pcm_data:
        return False
    wav_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="gemini_native_", suffix=".pcm", delete=False) as tmpf:
        tmpf.write(pcm_data)
        tmp_pcm = Path(tmpf.name)
    try:
        subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "s16le",
                "-ar",
                "24000",
                "-ac",
                "1",
                "-i",
                str(tmp_pcm),
                "-ar",
                "8000",
                "-ac",
                "1",
                "-c:a",
                "pcm_s16le",
                "-af",
                "highpass=f=120,lowpass=f=3400,volume=1.8",
                "-y",
                str(wav_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return wav_path.exists() and wav_path.stat().st_size > 44
    except Exception as exc:
        log(f"native_audio_ffmpeg_error err={exc}")
        return False
    finally:
        try:
            tmp_pcm.unlink(missing_ok=True)
        except Exception:
            pass


def generate_native_voice_wav(prompt_text: str, *, cacheable: bool, caller_audio_wav: Path | None = None) -> str:
    if not GEMINI_LIVE_ENABLED:
        return ""
    if not prompt_text.strip():
        return ""
    if not gemini_api_key():
        return ""
    if genai is None or genai_types is None:
        log("native_audio_skip_google_genai_unavailable")
        return ""

    AI_NATIVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = AI_NATIVE_CACHE_DIR / _native_cache_name(prompt_text) if cacheable else AI_NATIVE_CACHE_DIR / f"live_{uuid.uuid4().hex}.wav"
    if cacheable and out_path.exists() and out_path.stat().st_size > 44:
        return str(out_path)
    try:
        pcm_bytes = asyncio.run(
            asyncio.wait_for(
                _native_audio_from_model_async(prompt_text, caller_audio_wav=caller_audio_wav),
                timeout=GEMINI_LIVE_TIMEOUT_SECONDS,
            )
        )
    except Exception as exc:
        log(f"native_audio_model_error model={GEMINI_LIVE_MODEL} err={exc}")
        return ""
    if not pcm_bytes:
        return ""
    if _pcm_24k_to_wav_8k(pcm_bytes, out_path):
        return str(out_path)
    return ""


def speak(conn: socket.socket, text: str, fallback_wav: str, *, cacheable: bool = True, caller_audio_wav: Path | None = None) -> None:
    eleven_path = generate_elevenlabs_voice_wav(text.strip(), cacheable=cacheable)
    if eleven_path:
        send_execute(conn, "playback", eleven_path)
        return
    native_path = generate_native_voice_wav(
        text.strip(),
        cacheable=cacheable,
        caller_audio_wav=caller_audio_wav,
    )
    if native_path:
        send_execute(conn, "playback", native_path)
        return
    if fallback_wav:
        send_execute(conn, "playback", fallback_wav)


_SOCKET_READ_BUFFERS: dict[int, bytearray] = {}


def _frame_header_end(data: bytes) -> tuple[int, int]:
    idx = data.find(b"\r\n\r\n")
    if idx >= 0:
        return idx, 4
    idx = data.find(b"\n\n")
    if idx >= 0:
        return idx, 2
    return -1, 0


def _frame_content_length(header_text: str) -> int:
    for line in header_text.splitlines():
        if not line.lower().startswith("content-length:"):
            continue
        try:
            return max(0, int(line.split(":", 1)[1].strip()))
        except Exception:
            return 0
    return 0


def recv_frame(conn: socket.socket, timeout: int = 10) -> str:
    conn_id = conn.fileno()
    buf = _SOCKET_READ_BUFFERS.setdefault(conn_id, bytearray())
    deadline = time.monotonic() + max(0.1, timeout)
    max_bytes = 1024 * 1024

    while True:
        hdr_idx, hdr_sep_len = _frame_header_end(buf)
        if hdr_idx >= 0:
            header_bytes = bytes(buf[:hdr_idx])
            header_text = header_bytes.decode("utf-8", errors="replace")
            body_len = _frame_content_length(header_text)
            frame_len = hdr_idx + hdr_sep_len + body_len

            while len(buf) < frame_len:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                conn.settimeout(remaining)
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    break

            frame = bytes(buf[:frame_len])
            del buf[:frame_len]
            return frame.decode("utf-8", errors="replace")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            frame = bytes(buf)
            buf.clear()
            return frame.decode("utf-8", errors="replace")
        conn.settimeout(remaining)
        chunk = conn.recv(4096)
        if not chunk:
            frame = bytes(buf)
            buf.clear()
            return frame.decode("utf-8", errors="replace")
        buf.extend(chunk)
        if len(buf) > max_bytes:
            frame = bytes(buf[:max_bytes])
            del buf[:max_bytes]
            return frame.decode("utf-8", errors="replace")


def send_command(conn: socket.socket, command: str, timeout: int = 10) -> str:
    conn.sendall((command.strip() + "\n\n").encode("utf-8"))
    return recv_frame(conn, timeout=timeout)


def send_execute(conn: socket.socket, app: str, app_arg: str = "") -> str:
    lines = [
        "sendmsg",
        "call-command: execute",
        "event-lock: true",
        f"execute-app-name: {app}",
    ]
    if app_arg:
        lines.append(f"execute-app-arg: {app_arg}")
    return send_command(conn, "\n".join(lines))


def send_api(conn: socket.socket, command: str, timeout: int = 10) -> str:
    return send_command(conn, f"api {command}", timeout=timeout)


def uuid_getvar(conn: socket.socket, call_uuid: str, var_name: str) -> str:
    if not call_uuid:
        return ""
    reply = send_api(conn, f"uuid_getvar {call_uuid} {var_name}")
    for line in reply.splitlines():
        if line.startswith("+OK"):
            return line.replace("+OK", "", 1).strip()
    return ""


def uuid_exists(conn: socket.socket, call_uuid: str) -> bool:
    if not call_uuid:
        return True
    for _ in range(2):
        reply = send_api(conn, f"uuid_exists {call_uuid}")
        text = reply.casefold()
        if "true" in text or "+ok true" in text:
            return True
        if "false" in text or "+ok false" in text or "-err" in text:
            return False
        time.sleep(0.05)
    # If response framing was noisy, don't tear down a live call.
    return True


def wait_for_channel_active(conn: socket.socket, call_uuid: str, timeout_seconds: float = 5.0) -> bool:
    # With socket async full and event-lock execute, answer may be asynchronous
    # on some trunks. A short settle delay avoids early-media race conditions.
    if uuid_exists(conn, call_uuid):
        time.sleep(max(0.05, min(timeout_seconds, 0.35)))
    return False


def parse_headers(frame: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in frame.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip().lower()] = v.strip()
    return out


def split_csv(raw_value: str) -> list[str]:
    return [x.strip() for x in (raw_value or "").replace(";", ",").split(",") if x.strip()]


def safe_meta(value: str) -> str:
    # Metadata is embedded in a single API token, so keep it compact and clean.
    return "".join(ch for ch in (value or "") if ch.isalnum() or ch in "+-_.@#%:")[:128]


def dial_target_agent_lookup_key(token: str) -> str | None:
    value = token.strip()
    if not value:
        return None
    lower_value = value.casefold()
    if lower_value.startswith("agent:"):
        candidate = value.split(":", 1)[1].strip()
        return candidate.casefold() if candidate else None
    if value.isdigit():
        return None
    if any(ch in value for ch in ("/", "@", "{", "}", "[", "]", "(", ")", " ")):
        return None
    return value.casefold()


def resolve_agent_dial_targets(raw_targets: str, agent_map: dict[str, str]) -> str:
    resolved: list[str] = []
    for token in split_csv(raw_targets):
        lookup_key = dial_target_agent_lookup_key(token)
        if not lookup_key:
            resolved.append(token)
            continue
        extension = agent_map.get(lookup_key)
        if extension:
            resolved.append(extension)
            log(f"dial_target_agent_resolved token={token} extension={extension}")
            continue
        # Keep unresolved value so legacy/manual targets still work.
        resolved.append(token)
        if token.casefold().startswith("agent:"):
            log(f"dial_target_agent_missing token={token}")
    return ",".join(resolved)


def queue_config_by_intent(intent: str) -> dict[str, str] | None:
    wanted = intent.strip().casefold()
    if wanted not in {"sales", "support", "billing"}:
        return None

    db = Path(PORTAL_DB_PATH)
    if not db.exists():
        return None

    try:
        conn = sqlite3.connect(str(db))
        cur = conn.cursor()
        row = cur.execute(
            """
            SELECT number, name, ring_mode, dial_targets, inbound_numbers, voicemail_box, max_wait_seconds
            FROM queues
            WHERE lower(name) = ?
            ORDER BY number
            LIMIT 1
            """,
            (wanted,),
        ).fetchone()

        if not row:
            row = cur.execute(
                """
                SELECT number, name, ring_mode, dial_targets, inbound_numbers, voicemail_box, max_wait_seconds
                FROM queues
                WHERE lower(name) LIKE ?
                ORDER BY number
                LIMIT 1
                """,
                (f"%{wanted}%",),
            ).fetchone()

        agent_map: dict[str, str] = {}
        for agent_id, extension in cur.execute("SELECT agent_id, extension FROM agents").fetchall():
            agent_key = str(agent_id or "").strip().casefold()
            ext = str(extension or "").strip()
            if not agent_key or not ext:
                continue
            agent_map[agent_key] = ext

        conn.close()
        if not row:
            return None

        resolved_dial_targets = resolve_agent_dial_targets(str(row[3] or "").strip(), agent_map)

        return {
            "number": str(row[0] or "").strip(),
            "name": str(row[1] or "").strip(),
            "ring_mode": str(row[2] or "blast").strip().casefold(),
            "dial_targets": resolved_dial_targets,
            "inbound_numbers": str(row[4] or "").strip(),
            "voicemail_box": str(row[5] or "").strip(),
            "max_wait_seconds": str(row[6] or "300").strip(),
        }
    except Exception as exc:
        log(f"queue_lookup_error intent={intent} err={exc}")
        return None


def fallback_intent(text: str) -> str:
    normalized = text.casefold()
    if any(k in normalized for k in ("sales", "buy", "purchase", "pricing", "quote", "order")):
        return "sales"
    if any(k in normalized for k in ("support", "help", "technical", "tech", "service", "suppirt")):
        return "support"
    if any(k in normalized for k in ("billing", "invoice", "payment", "charge", "refund", "bill")):
        return "billing"
    return "invalid"


def extract_generated_text(body: str) -> str:
    def _from_payload(payload: object) -> str:
        chunks = payload if isinstance(payload, list) else [payload]
        out: list[str] = []
        for chunk in chunks:
            if not isinstance(chunk, dict):
                continue
            for cand in chunk.get("candidates", []) or []:
                if not isinstance(cand, dict):
                    continue
                content = cand.get("content", {})
                if not isinstance(content, dict):
                    continue
                for part in content.get("parts", []) or []:
                    if not isinstance(part, dict):
                        continue
                    txt = part.get("text")
                    if isinstance(txt, str) and txt.strip():
                        out.append(txt.strip())
        return " ".join(out).strip()

    try:
        parsed = json.loads(body)
        text = _from_payload(parsed)
        if text:
            return text
    except json.JSONDecodeError:
        pass

    chunks: list[str] = []
    for line in body.splitlines():
        s = line.strip()
        if not s.startswith("data:"):
            continue
        frag = s.removeprefix("data:").strip()
        if not frag or frag == "[DONE]":
            continue
        try:
            parsed = json.loads(frag)
        except json.JSONDecodeError:
            continue
        text = _from_payload(parsed)
        if text:
            chunks.append(text)
    return " ".join(chunks).strip()


def parse_intent_response(text: str) -> tuple[str, str]:
    cleaned = text.strip()
    if not cleaned:
        return ("invalid", "")
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.replace("json", "", 1).strip()
    try:
        payload = json.loads(cleaned)
        intent = str(payload.get("intent", "invalid")).casefold().strip()
        transcript = str(payload.get("transcript", "")).strip()
        keyword_intent = fallback_intent(transcript or cleaned)
        if keyword_intent != "invalid":
            # Prefer deterministic keyword routing when transcript includes known intents.
            intent = keyword_intent
        elif intent not in VALID_INTENTS:
            intent = "invalid"
        return (intent, transcript)
    except json.JSONDecodeError:
        return (fallback_intent(cleaned), cleaned)


def classify_audio_intent(wav_path: Path) -> tuple[str, str]:
    api_key = gemini_api_key()
    if not api_key:
        log("intent_skip_no_api_key")
        return ("invalid", "")
    if not wav_path.exists():
        log(f"intent_skip_missing_record_file path={wav_path}")
        return ("invalid", "")
    try:
        if wav_path.stat().st_size <= 44:
            log(f"intent_skip_small_record_file path={wav_path} bytes={wav_path.stat().st_size}")
            return ("invalid", "")
    except Exception as exc:
        log(f"intent_stat_error path={wav_path} err={exc}")
        return ("invalid", "")

    model = os.getenv("GEMINI_INTENT_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash"
    fallback_model = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash-lite").strip() or "gemini-2.5-flash-lite"
    endpoint_tmpl = os.getenv(
        "GEMINI_API_ENDPOINT_TEMPLATE",
        "https://aiplatform.googleapis.com/v1/publishers/google/models/{model}:streamGenerateContent",
    )

    instruction = (
        "You are an IVR intent classifier. "
        'Return JSON only: {"intent":"sales|support|billing|invalid","transcript":"..."}. '
        'Choose "sales" when caller asks for sales. '
        'Choose "support" when caller asks for support/help/technical issues. '
        'Choose "billing" when caller asks about invoices/payments/charges/refunds. '
        'Otherwise return "invalid".'
    )

    audio_bytes = wav_path.read_bytes()
    parts = [
        {"text": instruction},
        {
            "inline_data": {
                "mime_type": "audio/wav",
                "data": base64.b64encode(audio_bytes).decode("ascii"),
            }
        },
    ]
    payload = {
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": {"temperature": 0},
    }

    for m in [model, fallback_model]:
        if not m:
            continue
        endpoint = f"{endpoint_tmpl.format(model=m)}?key={api_key}"
        req = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=GEMINI_INTENT_TIMEOUT_SECONDS) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except (HTTPError, URLError, TimeoutError) as exc:
            log(f"gemini_request_failed model={m} err={exc}")
            continue
        generated = extract_generated_text(body)
        intent, transcript = parse_intent_response(generated)
        log(f"gemini_result model={m} intent={intent} transcript={transcript[:120]}")
        return (intent, transcript)

    return ("invalid", "")


def normalize_target(raw: str) -> str:
    target = raw.strip().strip('"').strip("'")
    if not target:
        return ""
    lower_target = target.casefold()
    if lower_target.startswith("sip/"):
        return f"sofia/external/{target[4:]}"
    if lower_target.startswith("pjsip/"):
        return f"sofia/external/{target[6:]}"
    if lower_target.startswith("sofia/"):
        return target
    if "@" in target and "/" not in target:
        return f"sofia/external/{target}"
    if target.isdigit():
        return f"user/{target}"
    if "/" in target:
        return target
    return target


def intent_prompt(intent: str) -> str:
    if intent == "sales":
        return PROMPT_CONNECT_SALES
    if intent == "support":
        return PROMPT_CONNECT_SUPPORT
    if intent == "billing":
        return PROMPT_CONNECT_BILLING
    return PROMPT_CONNECT_SALES


def intent_connect_text(intent: str) -> str:
    if intent == "sales":
        return PROMPT_CONNECT_SALES_TEXT
    if intent == "support":
        return PROMPT_CONNECT_SUPPORT_TEXT
    if intent == "billing":
        return PROMPT_CONNECT_BILLING_TEXT
    return PROMPT_CONNECT_SALES_TEXT


def route_to_voicemail(conn: socket.socket, queue_cfg: dict[str, str], intent: str) -> bool:
    vm_box = (queue_cfg.get("voicemail_box") or "").strip() or DEFAULT_VOICEMAIL_BOX
    if not vm_box:
        return False
    reply = send_execute(conn, "transfer", f"{vm_box} XML default")
    log(
        f"voicemail_transfer_reply={reply.splitlines()[:2]} "
        f"intent={intent} queue={queue_cfg.get('number','')} vm_box={vm_box}"
    )
    return True


def route_to_queue(conn: socket.socket, call_uuid: str, intent: str, queue_cfg: dict[str, str]) -> None:
    speak(conn, intent_connect_text(intent), intent_prompt(intent), cacheable=True)
    # Keep outbound leg in narrowband telephony codecs for interop.
    send_execute(conn, "set", "absolute_codec_string=PCMU,PCMA")
    send_execute(conn, "set", "continue_on_fail=true")

    combined_targets_raw = (queue_cfg.get("dial_targets", "") or "").strip()
    if not combined_targets_raw:
        # Backward compatibility for older queue configs that were saved in inbound_numbers.
        combined_targets_raw = (queue_cfg.get("inbound_numbers", "") or "").strip()
        if combined_targets_raw:
            log(
                f"queue_dial_targets_empty_using_inbound_numbers intent={intent} "
                f"queue={queue_cfg.get('number','')}"
            )
    dial_targets: list[str] = []
    seen: set[str] = set()
    for item in split_csv(combined_targets_raw):
        normalized = normalize_target(item)
        if not normalized:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        dial_targets.append(normalized)
    ring_mode = queue_cfg.get("ring_mode", "blast")
    try:
        total_wait = int(queue_cfg.get("max_wait_seconds", "300") or "300")
    except ValueError:
        total_wait = 300
    total_wait = max(15, total_wait)
    attempt_seconds = max(8, QUEUE_ATTEMPT_SECONDS)

    if dial_targets:
        started = time.time()
        while time.time() - started < total_wait and uuid_exists(conn, call_uuid):
            remaining = int(total_wait - (time.time() - started))
            per_try = max(5, min(attempt_seconds, remaining))
            if per_try <= 0:
                break
            send_execute(conn, "set", f"originate_timeout={per_try}")
            had_attempt = False

            if ring_mode == "sequential":
                for target in dial_targets:
                    if int(total_wait - (time.time() - started)) <= 0:
                        break
                    had_attempt = True
                    send_execute(conn, "set", f"originate_timeout={per_try}")
                    reply = send_execute(conn, "bridge", target)
                    dispo = uuid_getvar(conn, call_uuid, "originate_disposition")
                    bhc = uuid_getvar(conn, call_uuid, "bridge_hangup_cause")
                    log(
                        f"bridge_reply={reply.splitlines()[:2]} intent={intent} "
                        f"queue={queue_cfg.get('number','')} dialstring={target} "
                        f"originate_disposition={dispo} bridge_hangup_cause={bhc}"
                    )
                    # If call no longer exists, handoff happened.
                    if not uuid_exists(conn, call_uuid):
                        return
                    # If answered leg then completed, do not keep retrying.
                    if dispo.casefold() in {"success", "answered"}:
                        return
                    if QUEUE_RETRY_DELAY_MS > 0:
                        time.sleep(QUEUE_RETRY_DELAY_MS / 1000.0)
            else:
                had_attempt = True
                dialstring = ",".join(dial_targets)
                reply = send_execute(conn, "bridge", dialstring)
                dispo = uuid_getvar(conn, call_uuid, "originate_disposition")
                bhc = uuid_getvar(conn, call_uuid, "bridge_hangup_cause")
                log(
                    f"bridge_reply={reply.splitlines()[:2]} intent={intent} "
                    f"queue={queue_cfg.get('number','')} dialstring={dialstring} "
                    f"originate_disposition={dispo} bridge_hangup_cause={bhc}"
                )
                if not uuid_exists(conn, call_uuid):
                    return
                if dispo.casefold() in {"success", "answered"}:
                    return
                if QUEUE_RETRY_DELAY_MS > 0:
                    time.sleep(QUEUE_RETRY_DELAY_MS / 1000.0)

            if not had_attempt:
                break

        if route_to_voicemail(conn, queue_cfg, intent):
            return

    number = queue_cfg.get("number", "")
    if number:
        # Fall back to dialplan queue extension path.
        reply = send_execute(conn, "transfer", f"{number} XML default")
        log(
            f"transfer_default_reply={reply.splitlines()[:2]} "
            f"intent={intent} queue={number}"
        )
        return

    send_execute(conn, "playback", PROMPT_INVALID)
    send_execute(conn, "hangup", "NORMAL_CLEARING")


def collect_intent_via_ws_stream(
    conn: socket.socket,
    call_uuid: str,
    caller: str,
    destination: str,
    *,
    prompt_text: str,
    prompt_wav: str,
) -> tuple[str, str, dict[str, str] | None]:
    if not AI_WS_STREAM_ENABLED or not call_uuid:
        return "invalid", "", None
    if not AI_WS_STREAM_URL:
        log("ws_stream_disabled_empty_url")
        return "invalid", "", None

    # In websocket mode, prompts are preferably produced by the ws bridge.
    if AI_WS_LOCAL_PROMPT_ENABLED:
        speak(conn, prompt_text, prompt_wav, cacheable=True)
        send_execute(conn, "sleep", "200")

    send_api(conn, f"uuid_setvar {call_uuid} callture_intent none")
    send_api(conn, f"uuid_setvar {call_uuid} callture_intent_source none")

    metadata = json.dumps(
        {
            "uuid": safe_meta(call_uuid),
            "caller": safe_meta(caller),
            "did": safe_meta(destination),
            "mix": safe_meta(AI_WS_STREAM_MIX),
            "tag": safe_meta(AI_WS_STREAM_TAG),
        },
        separators=(",", ":"),
    )
    start_cmd = f"uuid_audio_stream {call_uuid} start {AI_WS_STREAM_URL} {AI_WS_STREAM_MIX} {AI_WS_STREAM_RATE} {metadata}"
    start_reply = send_api(conn, start_cmd, timeout=15)
    log(
        f"ws_stream_start uuid={call_uuid} url={AI_WS_STREAM_URL} "
        f"reply={start_reply.splitlines()[:2]}"
    )
    if "+OK" not in start_reply:
        return "invalid", "", None

    deadline = time.time() + AI_WS_STREAM_WAIT_SECONDS
    transcript = ""
    queue_cfg: dict[str, str] | None = None
    intent = "invalid"
    try:
        while time.time() < deadline and uuid_exists(conn, call_uuid):
            current = uuid_getvar(conn, call_uuid, "callture_intent").strip().casefold()
            if current in {"sales", "support", "billing"}:
                intent = current
                transcript = uuid_getvar(conn, call_uuid, "callture_intent_source").strip()
                queue_cfg = queue_config_by_intent(intent)
                log(
                    f"ws_stream_intent uuid={call_uuid} intent={intent} "
                    f"queue={(queue_cfg or {}).get('number','')} source={transcript[:100]}"
                )
                if queue_cfg:
                    return intent, transcript, queue_cfg
            time.sleep(0.25)
    finally:
        stop_reply = send_api(conn, f"uuid_audio_stream {call_uuid} stop", timeout=10)
        log(f"ws_stream_stop uuid={call_uuid} reply={stop_reply.splitlines()[:2]}")

    return "invalid", transcript, None


def run_realtime_direct_voice_bridge(
    conn: socket.socket,
    call_uuid: str,
    caller: str,
    destination: str,
) -> bool:
    if not AI_WS_STREAM_ENABLED or not call_uuid or not AI_WS_STREAM_URL:
        return False

    # v1.0.3+ mod_audio_stream requires STREAM_PLAYBACK for automatic
    # playback of inbound websocket audio to the same channel.
    try:
        set_playback_true = send_api(conn, f"uuid_setvar {call_uuid} STREAM_PLAYBACK true", timeout=5)
        # Some builds interpret boolean-like values differently.
        set_playback_enabled = send_api(conn, f"uuid_setvar {call_uuid} STREAM_PLAYBACK enabled", timeout=5)
        set_playback_active = send_api(conn, f"uuid_setvar {call_uuid} STREAM_PLAYBACK active", timeout=5)
        set_playback_one = send_api(conn, f"uuid_setvar {call_uuid} STREAM_PLAYBACK 1", timeout=5)
        set_buffer = send_api(conn, f"uuid_setvar {call_uuid} STREAM_BUFFER_SIZE 100", timeout=5)
        set_sample_rate = send_api(conn, f"uuid_setvar {call_uuid} STREAM_SAMPLE_RATE {AI_WS_STREAM_RATE}", timeout=5)
        send_api(conn, f"uuid_setvar {call_uuid} STREAM_SUPPRESS_LOG false", timeout=5)
        send_api(conn, f"uuid_setvar {call_uuid} STREAM_GLOBAL_TRACE true", timeout=5)
        playback_value = uuid_getvar(conn, call_uuid, "STREAM_PLAYBACK")
        buffer_value = uuid_getvar(conn, call_uuid, "STREAM_BUFFER_SIZE")
        sample_rate_value = uuid_getvar(conn, call_uuid, "STREAM_SAMPLE_RATE")
        log(
            f"stream_playback_vars uuid={call_uuid} "
            f"set_true={set_playback_true.splitlines()[:2]} "
            f"set_enabled={set_playback_enabled.splitlines()[:2]} "
            f"set_active={set_playback_active.splitlines()[:2]} "
            f"set_one={set_playback_one.splitlines()[:2]} "
            f"set_buffer={set_buffer.splitlines()[:2]} "
            f"set_sample_rate={set_sample_rate.splitlines()[:2]} "
            f"get_playback={playback_value!r} get_buffer={buffer_value!r} get_rate={sample_rate_value!r}"
        )
        try:
            dump_reply = send_api(conn, f"uuid_dump {call_uuid}", timeout=5)
            stream_lines = [
                line.strip()
                for line in dump_reply.splitlines()
                if ("STREAM_" in line) or ("read_codec=" in line) or ("write_codec=" in line)
            ]
            if stream_lines:
                log(f"stream_uuid_dump uuid={call_uuid} lines={stream_lines[:20]}")
        except Exception as dump_exc:
            log(f"stream_uuid_dump_error uuid={call_uuid} err={dump_exc}")
    except Exception as exc:
        log(f"stream_playback_var_set_error uuid={call_uuid} err={exc}")

    # Ensure channel is fully answered before starting media stream.
    # Some upstream carriers drop/ignore early-media RTP, causing silent greetings.
    wait_for_channel_active(conn, call_uuid, timeout_seconds=0.35)
    if AI_WS_PRESTREAM_TONE:
        try:
            tone_reply = send_execute(conn, "playback", "tone_stream://%(300,100,950)")
            log(f"prestream_tone_playback uuid={call_uuid} reply={tone_reply.splitlines()[:2]}")
        except Exception as tone_exc:
            log(f"prestream_tone_error uuid={call_uuid} err={tone_exc}")

    metadata = json.dumps(
        {
            "uuid": safe_meta(call_uuid),
            "caller": safe_meta(caller),
            "did": safe_meta(destination),
            "mode": "direct_voice",
            "mix": safe_meta(AI_WS_STREAM_MIX),
            "tag": safe_meta(AI_WS_STREAM_TAG),
        },
        separators=(",", ":"),
    )
    start_cmd = f"uuid_audio_stream {call_uuid} start {AI_WS_STREAM_URL} {AI_WS_STREAM_MIX} {AI_WS_STREAM_RATE} {metadata}"
    start_reply = send_api(conn, start_cmd, timeout=15)
    log(
        f"realtime_ws_start uuid={call_uuid} url={AI_WS_STREAM_URL} "
        f"reply={start_reply.splitlines()[:2]}"
    )
    if "-err" in start_reply.casefold():
        return False

    started = time.time()
    timed_out = False
    try:
        while uuid_exists(conn, call_uuid):
            if time.time() - started >= AI_REALTIME_MAX_SECONDS:
                timed_out = True
                break
            time.sleep(0.25)
    finally:
        try:
            stop_reply = send_api(conn, f"uuid_audio_stream {call_uuid} stop", timeout=10)
            log(f"realtime_ws_stop uuid={call_uuid} reply={stop_reply.splitlines()[:2]}")
        except Exception as exc:
            log(f"realtime_ws_stop_error uuid={call_uuid} err={exc}")

    if timed_out and uuid_exists(conn, call_uuid):
        send_execute(conn, "hangup", "NORMAL_CLEARING")
    return True


def elevenlabs_transcribe_wav(wav_path: Path) -> str:
    api_key = elevenlabs_api_key()
    if not api_key:
        return ""
    if not wav_path.exists():
        return ""
    try:
        if wav_path.stat().st_size <= 44:
            return ""
    except Exception:
        return ""

    boundary = f"----callture{uuid.uuid4().hex}"
    model_id = ELEVENLABS_STT_MODEL_ID or "scribe_v1"
    audio_data = wav_path.read_bytes()
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(b'Content-Disposition: form-data; name="model_id"\r\n\r\n')
    body.extend(model_id.encode("utf-8"))
    body.extend(b"\r\n")
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        f'Content-Disposition: form-data; name="file"; filename="{wav_path.name}"\r\n'.encode("utf-8")
    )
    body.extend(b"Content-Type: audio/wav\r\n\r\n")
    body.extend(audio_data)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    req = Request(
        "https://api.elevenlabs.io/v1/speech-to-text",
        data=bytes(body),
        headers={
            "xi-api-key": api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=25) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        text = ""
        if isinstance(payload, dict):
            text = str(payload.get("text") or payload.get("transcript") or "").strip()
        return text
    except HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        log(f"elevenlabs_stt_request_failed err={exc} body={body[:240]}")
        return ""
    except (URLError, TimeoutError) as exc:
        log(f"elevenlabs_stt_request_failed err={exc}")
        return ""
    except Exception as exc:
        log(f"elevenlabs_stt_error err={exc}")
        return ""


def capture_intent_wav(conn: socket.socket, call_uuid: str, seconds: int) -> Path | None:
    if not call_uuid:
        return None
    AI_RECORD_DIR.mkdir(parents=True, exist_ok=True)
    wav_path = AI_RECORD_DIR / f"intent_{call_uuid}_{int(time.time())}.wav"
    wait_seconds = max(3, seconds)
    try:
        start_reply = send_api(conn, f"uuid_record {call_uuid} start {wav_path}", timeout=8)
        log(
            f"intent_record_start uuid={call_uuid} wait_seconds={wait_seconds} "
            f"reply={start_reply.splitlines()[:2]} path={wav_path}"
        )
        stop_at = time.monotonic() + wait_seconds
        while time.monotonic() < stop_at and uuid_exists(conn, call_uuid):
            time.sleep(0.2)
    finally:
        try:
            stop_reply = send_api(conn, f"uuid_record {call_uuid} stop {wav_path}", timeout=8)
            log(f"intent_record_stop uuid={call_uuid} reply={stop_reply.splitlines()[:2]}")
        except Exception as exc:
            log(f"intent_record_stop_error uuid={call_uuid} err={exc}")
    try:
        if wav_path.exists() and wav_path.stat().st_size > 4096:
            return wav_path
        if wav_path.exists():
            log(f"intent_record_too_small uuid={call_uuid} bytes={wav_path.stat().st_size} path={wav_path}")
    except Exception:
        return None
    return None


def collect_intent_with_retry(
    conn: socket.socket,
    call_uuid: str,
    caller: str,
    destination: str,
) -> tuple[str, str, dict[str, str] | None]:
    prompts = [
        (PROMPT_GREETING_TEXT, PROMPT_GREETING),
        (PROMPT_RETRY_TEXT, PROMPT_RETRY),
    ]
    for attempt_idx, (prompt_text, prompt_wav) in enumerate(prompts, start=1):
        if not uuid_exists(conn, call_uuid):
            break
        speak(conn, prompt_text, prompt_wav, cacheable=True)
        # Short beep to indicate caller should speak now.
        send_execute(conn, "playback", "tone_stream://%(120,0,1250)")
        wav_path = capture_intent_wav(conn, call_uuid, AI_RECORD_SECONDS)
        if not wav_path:
            log(f"intent_capture_empty uuid={call_uuid} attempt={attempt_idx}")
            continue

        transcript = elevenlabs_transcribe_wav(wav_path)
        intent = fallback_intent(transcript)
        if intent == "invalid":
            # Keep Gemini as a classifier fallback if transcript is noisy.
            g_intent, g_transcript = classify_audio_intent(wav_path)
            if g_intent in {"sales", "support", "billing"}:
                intent = g_intent
                if not transcript:
                    transcript = g_transcript
        log(
            f"intent_result uuid={call_uuid} attempt={attempt_idx} "
            f"intent={intent} transcript={transcript[:120]}"
        )
        if intent in {"sales", "support", "billing"}:
            queue_cfg = queue_config_by_intent(intent)
            if queue_cfg:
                return intent, transcript, queue_cfg
    return "invalid", "", None


def collect_dtmf_fallback(
    conn: socket.socket,
    call_uuid: str,
    *,
    play_prompt: bool = True,
) -> tuple[str, dict[str, str] | None]:
    # Ask caller for keypad fallback when speech capture fails.
    if play_prompt:
        speak(conn, PROMPT_DTMF_FALLBACK_TEXT, PROMPT_DTMF_FALLBACK, cacheable=True)
    send_execute(
        conn,
        "read",
        "1 1 silence_stream://1000 ai_menu_digit 5000 #",
    )
    value_reply = send_api(conn, f"uuid_getvar {call_uuid} ai_menu_digit")
    digit = ""
    for line in value_reply.splitlines():
        if line.startswith("+OK"):
            digit = line.replace("+OK", "", 1).strip()
    digit_to_intent = {"1": "sales", "2": "support", "3": "billing"}
    intent = digit_to_intent.get(digit, "invalid")
    queue_cfg = queue_config_by_intent(intent)
    log(f"dtmf_fallback digit={digit!r} intent={intent} queue={(queue_cfg or {}).get('number','')}")
    return intent, queue_cfg


def handle_call(conn: socket.socket, addr) -> None:
    call_uuid = ""
    try:
        connect_reply = send_command(conn, "connect")
        headers = parse_headers(connect_reply)
        call_uuid = (
            headers.get("channel-call-uuid")
            or headers.get("unique-id")
            or headers.get("variable_uuid")
            or ""
        )
        dst = headers.get("variable_destination_number", "")
        caller = headers.get("variable_caller_id_number", "")
        log(f"{addr} incoming caller={caller} destination={dst} call_uuid={call_uuid}")

        send_execute(conn, "answer")
        send_execute(conn, "sleep", "300")

        if AI_REALTIME_DIRECT_MODE:
            ok = run_realtime_direct_voice_bridge(conn, call_uuid, caller, dst)
            if not ok and uuid_exists(conn, call_uuid):
                speak(conn, PROMPT_INVALID_TEXT, PROMPT_INVALID, cacheable=True)
                send_execute(conn, "hangup", "NORMAL_CLEARING")
            return

        if AI_WS_STREAM_ENABLED:
            intent, transcript, target_cfg = collect_intent_via_ws_stream(
                conn,
                call_uuid,
                caller,
                dst,
                prompt_text=PROMPT_GREETING_TEXT,
                prompt_wav=PROMPT_GREETING,
            )
            # One more websocket-only retry.
            if not target_cfg and uuid_exists(conn, call_uuid):
                intent, transcript, target_cfg = collect_intent_via_ws_stream(
                    conn,
                    call_uuid,
                    caller,
                    dst,
                    prompt_text=PROMPT_RETRY_TEXT,
                    prompt_wav=PROMPT_RETRY,
                )
        else:
            intent, transcript, target_cfg = collect_intent_with_retry(conn, call_uuid, caller, dst)

        if intent in {"sales", "support", "billing"} and target_cfg:
            route_to_queue(conn, call_uuid, intent, target_cfg)
            return

        speak(conn, PROMPT_INVALID_TEXT, PROMPT_INVALID, cacheable=True)
        send_execute(conn, "hangup", "NORMAL_CLEARING")
    except Exception as exc:
        # Caller may hang up while AGI is still processing.
        if isinstance(exc, BrokenPipeError) or (isinstance(exc, OSError) and getattr(exc, "errno", None) == 32):
            log(f"call_disconnected {addr} call_uuid={call_uuid}")
        else:
            log(f"ERROR {addr}: {exc}")
            try:
                send_execute(conn, "hangup", "NORMAL_CLEARING")
            except Exception:
                pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    log("Starting inbound_socket_agi server")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    log(f"Listening on {HOST}:{PORT}")

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_call, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()




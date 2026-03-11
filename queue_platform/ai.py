from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import Agent, Call


@dataclass(slots=True)
class RoutingSuggestion:
    suggested_agent_id: str | None
    confidence: float
    reason: str
    proactive_message: str | None = None


class AIRoutingAdvisor:
    """
    Heuristic AI routing layer (drop-in placeholder).

    Replace scoring functions with ML inference while keeping interface stable.
    """

    def __init__(self) -> None:
        self.caller_last_agent: dict[str, str] = {}

    def register_completed_call(self, call: Call) -> None:
        if call.answered_by_agent_id:
            self.caller_last_agent[call.caller_id] = call.answered_by_agent_id

    def suggest_agent(self, call: Call, candidates: list[Agent]) -> RoutingSuggestion:
        if not candidates:
            return RoutingSuggestion(None, 0.0, "No available candidates")

        # Continuity routing first for returning callers.
        known_agent = self.caller_last_agent.get(call.caller_id)
        if known_agent:
            for agent in candidates:
                if agent.agent_id == known_agent:
                    return RoutingSuggestion(
                        suggested_agent_id=agent.agent_id,
                        confidence=0.92,
                        reason="Caller previously handled by same agent",
                    )

        sentiment = call.metadata.get("sentiment")
        if sentiment == "upset":
            de_escalation = [a for a in candidates if "de-escalation" in a.skills]
            if de_escalation:
                picked = max(de_escalation, key=lambda a: len(a.skills))
                return RoutingSuggestion(
                    suggested_agent_id=picked.agent_id,
                    confidence=0.85,
                    reason="Detected upset caller; matched to de-escalation skill",
                    proactive_message="Route this caller to the de-escalation specialist.",
                )

        if call.metadata.get("upsell_candidate") is True:
            sellers = [a for a in candidates if "sales" in a.skills]
            if sellers:
                picked = max(sellers, key=lambda a: a.calls_answered_today)
                return RoutingSuggestion(
                    suggested_agent_id=picked.agent_id,
                    confidence=0.81,
                    reason="Upsell opportunity matched to sales-skilled agent",
                    proactive_message="Prioritize this call for conversion potential.",
                )

        # Balance using longest idle.
        def idle_seconds(agent: Agent) -> float:
            if agent.last_call_end_at is None:
                return 1e12
            return (datetime.now(UTC) - agent.last_call_end_at).total_seconds()

        picked = max(candidates, key=idle_seconds)
        return RoutingSuggestion(
            suggested_agent_id=picked.agent_id,
            confidence=0.70,
            reason="Load balancing to longest-idle available agent",
            proactive_message="Consider transferring a low-priority active call to free this agent.",
        )

    def rank_agents(self, call: Call, candidates: list[Agent]) -> list[dict[str, Any]]:
        ranked: list[dict[str, Any]] = []
        for agent in candidates:
            score = 0.0
            if agent.agent_id == self.caller_last_agent.get(call.caller_id):
                score += 50
            score += len(call.required_skills.intersection(agent.skills)) * 15
            if call.preferred_language and call.preferred_language in agent.languages:
                score += 10
            score += max(0, 100 - agent.calls_answered_today)
            ranked.append({"agent_id": agent.agent_id, "score": round(score, 2)})
        ranked.sort(key=lambda x: x["score"], reverse=True)
        return ranked


@dataclass(slots=True)
class VoiceRouteResult:
    greeting: str
    response_text: str
    intent: str
    target_queue_number: str | None
    target_queue_name: str | None
    used_gemini: bool
    reason: str
    transcript: str | None = None


class GeminiVoiceRouter:
    """
    Voice-first IVR router:
    - Greets caller
    - Uses Gemini to detect intent from utterance/audio
    - Routes "sales" intent to configured Sales queue
    - Falls back to "invalid option"
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 8.0,
    ) -> None:
        self.api_key = (
            api_key
            or os.getenv("GEMINI_API_KEY", "").strip()
            or os.getenv("API_KEY", "").strip()
        )
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-live-2.5-flash-native-audio")
        self.fallback_model = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash-lite")
        self.endpoint_template = os.getenv(
            "GEMINI_API_ENDPOINT_TEMPLATE",
            "https://aiplatform.googleapis.com/v1/publishers/google/models/{model}:streamGenerateContent",
        )
        self.timeout_seconds = timeout_seconds
        self.greeting = "Hi, this is Callture. How can I help you?"
        self.invalid_option = "Sorry, invalid option."

    def route_from_text(self, caller_utterance: str, queues: dict[str, Any]) -> VoiceRouteResult:
        intent, used_gemini, reason = self._detect_intent_from_text(caller_utterance)
        return self._build_route_result(
            intent=intent,
            queues=queues,
            used_gemini=used_gemini,
            reason=reason,
            transcript=caller_utterance.strip() or None,
        )

    def route_from_audio(
        self,
        audio_bytes: bytes,
        mime_type: str,
        queues: dict[str, Any],
    ) -> VoiceRouteResult:
        transcript, intent, used_gemini, reason = self._detect_intent_from_audio(audio_bytes, mime_type)
        return self._build_route_result(
            intent=intent,
            queues=queues,
            used_gemini=used_gemini,
            reason=reason,
            transcript=transcript,
        )

    def _build_route_result(
        self,
        *,
        intent: str,
        queues: dict[str, Any],
        used_gemini: bool,
        reason: str,
        transcript: str | None,
    ) -> VoiceRouteResult:
        if intent == "sales":
            sales_queue = self._find_sales_queue(queues)
            if sales_queue is not None:
                return VoiceRouteResult(
                    greeting=self.greeting,
                    response_text="Connecting you to sales.",
                    intent="sales",
                    target_queue_number=sales_queue.number,
                    target_queue_name=sales_queue.name,
                    used_gemini=used_gemini,
                    reason=reason,
                    transcript=transcript,
                )
        return VoiceRouteResult(
            greeting=self.greeting,
            response_text=self.invalid_option,
            intent="invalid",
            target_queue_number=None,
            target_queue_name=None,
            used_gemini=used_gemini,
            reason=reason,
            transcript=transcript,
        )

    def _find_sales_queue(self, queues: dict[str, Any]) -> Any | None:
        for queue in queues.values():
            if "sales" in queue.name.casefold():
                return queue
        return None

    def _detect_intent_from_text(self, caller_utterance: str) -> tuple[str, bool, str]:
        text = caller_utterance.strip()
        if not text:
            return ("invalid", False, "No utterance captured")
        if self.api_key:
            intent = self._gemini_classify_intent(text=text)
            if intent in {"sales", "invalid"}:
                return (intent, True, "Gemini text intent classification")
        return (self._fallback_intent(text), False, "Keyword fallback intent classification")

    def _detect_intent_from_audio(
        self,
        audio_bytes: bytes,
        mime_type: str,
    ) -> tuple[str | None, str, bool, str]:
        if self.api_key and audio_bytes:
            transcript, intent = self._gemini_classify_intent(audio_bytes=audio_bytes, mime_type=mime_type)
            if intent in {"sales", "invalid"}:
                return (transcript, intent, True, "Gemini audio intent classification")
            if transcript:
                return (transcript, self._fallback_intent(transcript), False, "Fallback keyword over transcript")
        return (None, "invalid", False, "No Gemini key/audio; default invalid")

    def _fallback_intent(self, text: str) -> str:
        normalized = text.casefold()
        sales_keywords = ("sales", "buy", "purchase", "pricing", "quote", "order")
        return "sales" if any(keyword in normalized for keyword in sales_keywords) else "invalid"

    def _gemini_classify_intent(
        self,
        *,
        text: str | None = None,
        audio_bytes: bytes | None = None,
        mime_type: str = "audio/wav",
    ) -> tuple[str | None, str] | str:
        if not self.api_key:
            return ("", "invalid") if audio_bytes else "invalid"

        instruction = (
            "You are an IVR intent classifier.\n"
            'Return JSON only: {"intent":"sales|invalid","transcript":"..."}.\n'
            'Choose "sales" only when the caller is clearly asking for sales.\n'
            'Otherwise return "invalid".'
        )
        parts: list[dict[str, Any]] = [{"text": instruction}]
        if text is not None:
            parts.append({"text": f"Caller utterance: {text}"})
        if audio_bytes is not None:
            parts.append(
                {
                    "inline_data": {
                        "mime_type": mime_type,
                        "data": base64.b64encode(audio_bytes).decode("ascii"),
                    }
                }
            )

        payload = {
            "contents": [{"role": "user", "parts": parts}],
            "generationConfig": {"temperature": 0},
        }
        body = self._call_model(self.model, payload)
        if body is None and self.fallback_model and self.fallback_model != self.model:
            body = self._call_model(self.fallback_model, payload)
        if body is None:
            return ("", "invalid") if audio_bytes is not None else "invalid"

        generated_text = self._extract_generated_text(body)
        parsed = self._parse_intent_payload(generated_text)
        if audio_bytes is not None:
            return (parsed.get("transcript"), parsed.get("intent", "invalid"))
        return parsed.get("intent", "invalid")

    def _call_model(self, model: str, payload: dict[str, Any]) -> str | None:
        endpoint = f"{self.endpoint_template.format(model=model)}?key={self.api_key}"
        request = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as resp:
                return resp.read().decode("utf-8")
        except (URLError, TimeoutError):
            return None
        except HTTPError as exc:
            try:
                error_body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                error_body = ""
            if (
                exc.code == 400
                and "not supported in the streamGenerateContent API" in error_body
            ):
                return None
            return None

    def _extract_generated_text(self, api_response_body: str) -> str:
        # streamGenerateContent may return:
        # - a single JSON object
        # - a JSON list of chunk objects
        # - SSE-like "data: {...}" lines
        # This extractor supports all three.
        direct_text = self._extract_text_from_json_payload(api_response_body)
        if direct_text:
            return direct_text

        parts: list[str] = []
        for line in api_response_body.splitlines():
            cleaned = line.strip()
            if not cleaned.startswith("data:"):
                continue
            fragment = cleaned.removeprefix("data:").strip()
            if not fragment or fragment == "[DONE]":
                continue
            piece = self._extract_text_from_json_payload(fragment)
            if piece:
                parts.append(piece)
        return "".join(parts).strip()

    def _extract_text_from_json_payload(self, payload_str: str) -> str:
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            return ""

        chunks = payload if isinstance(payload, list) else [payload]
        texts: list[str] = []
        for chunk in chunks:
            try:
                candidates = chunk.get("candidates", [])
                for candidate in candidates:
                    content = candidate.get("content", {})
                    for part in content.get("parts", []):
                        text = part.get("text")
                        if isinstance(text, str) and text:
                            texts.append(text)
            except AttributeError:
                continue
        return "".join(texts).strip()

    def _parse_intent_payload(self, generated_text: str) -> dict[str, str]:
        if not generated_text:
            return {"intent": "invalid", "transcript": ""}
        cleaned = generated_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.replace("json", "", 1).strip()
        try:
            parsed = json.loads(cleaned)
            intent = str(parsed.get("intent", "invalid")).casefold().strip()
            transcript = str(parsed.get("transcript", "")).strip()
            return {
                "intent": "sales" if intent == "sales" else "invalid",
                "transcript": transcript,
            }
        except json.JSONDecodeError:
            fallback_intent = self._fallback_intent(cleaned)
            return {"intent": fallback_intent, "transcript": cleaned}

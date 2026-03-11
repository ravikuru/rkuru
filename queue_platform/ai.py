from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

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

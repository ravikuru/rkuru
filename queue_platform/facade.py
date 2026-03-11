from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from .ai import AIRoutingAdvisor
from .analytics import AnalyticsService
from .dashboard import DashboardService
from .models import Agent, Call, QueueConfig
from .service import QueueEngine


class ContactCenterPlatform:
    """Unified entry point for queue control, dashboard, and analytics."""

    def __init__(self) -> None:
        self.engine = QueueEngine()
        self.dashboard = DashboardService(self.engine)
        self.analytics = AnalyticsService(self.engine)
        self.ai = AIRoutingAdvisor()

    def configure_queue(self, queue_config: QueueConfig) -> None:
        self.engine.add_queue(queue_config)

    def configure_agent(self, agent: Agent) -> None:
        self.engine.add_agent(agent)

    def add_agent_to_queue(self, queue_number: str, agent_id: str) -> None:
        self.engine.add_member(queue_number, agent_id)

    def ingest_incoming_call(
        self,
        queue_number: str,
        caller_id: str,
        destination_number: str,
        source_ip: str,
        metadata: dict[str, Any] | None = None,
    ) -> Call:
        return self.engine.enqueue_call(
            queue_number=queue_number,
            caller_id=caller_id,
            destination_number=destination_number,
            source_ip=source_ip,
            metadata=metadata,
            required_skills=set((metadata or {}).get("required_skills", [])),
            preferred_language=(metadata or {}).get("preferred_language"),
        )

    def execute_cycle(self) -> None:
        """
        Process one scheduler cycle:
        - route queued calls
        - expire waits / overflow / voicemail
        - update wrap-up timers
        """
        self.engine.tick()
        # Sync history into AI layer.
        for call in self.engine.completed_calls[-20:]:
            self.ai.register_completed_call(call)

    def ai_routing_preview(self, call: Call) -> dict[str, Any]:
        queue = self.engine.queues[call.queue_number]
        candidates = [
            a
            for a in self.engine.agents.values()
            if queue.number in a.queue_memberships and a.status.value == "available"
        ]
        suggestion = self.ai.suggest_agent(call, candidates)
        ranking = self.ai.rank_agents(call, candidates)
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "suggestion": asdict(suggestion),
            "ranking": ranking,
        }

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from .models import Agent, Call, MonitoringMode, QueueConfig, QueueEvent
from .queue_functions import QueueFunctions


class QueueEngine:
    """In-memory queue orchestration engine with FreeSWITCH-friendly semantics."""

    def __init__(self) -> None:
        self._lock = RLock()
        self.queues: dict[str, QueueConfig] = {}
        self.agents: dict[str, Agent] = {}
        self.waiting_calls: dict[str, deque[Call]] = defaultdict(deque)
        self.active_calls: dict[str, Call] = {}
        self.completed_calls: list[Call] = []
        self.events: list[QueueEvent] = []
        self.wrap_up_until: dict[str, datetime] = {}
        self.voicemail_records: list[dict[str, Any]] = []
        self.caller_agent_history: dict[str, str] = {}
        self.queue_functions = QueueFunctions(
            lock=self._lock,
            queues=self.queues,
            agents=self.agents,
            waiting_calls=self.waiting_calls,
            active_calls=self.active_calls,
            completed_calls=self.completed_calls,
            wrap_up_until=self.wrap_up_until,
            voicemail_records=self.voicemail_records,
            caller_agent_history=self.caller_agent_history,
            emit=self._emit,
            emit_agent_event=self._emit_agent_event,
        )

    # -----------------------
    # Queue and member setup.
    # -----------------------
    def add_queue(self, config: QueueConfig) -> None:
        self.queue_functions.add_queue(config)

    def add_agent(self, agent: Agent) -> None:
        with self._lock:
            self.agents[agent.agent_id] = agent

    def add_member(self, queue_number: str, agent_id: str) -> None:
        self.queue_functions.add_member(queue_number, agent_id)

    def remove_member(self, queue_number: str, agent_id: str) -> None:
        self.queue_functions.remove_member(queue_number, agent_id)

    def bulk_members_from_csv(self, csv_path: str) -> int:
        return self.queue_functions.bulk_members_from_csv(csv_path)

    # -----------------------
    # Call lifecycle.
    # -----------------------
    def enqueue_call(
        self,
        queue_number: str,
        caller_id: str,
        destination_number: str,
        source_ip: str,
        *,
        required_skills: set[str] | None = None,
        preferred_language: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Call:
        return self.queue_functions.enqueue_call(
            queue_number=queue_number,
            caller_id=caller_id,
            destination_number=destination_number,
            source_ip=source_ip,
            required_skills=required_skills,
            preferred_language=preferred_language,
            metadata=metadata,
        )

    def route_calls(self) -> None:
        self.queue_functions.route_calls()

    def answer_call(self, agent_id: str, call_id: str) -> bool:
        return self.queue_functions.answer_call(agent_id, call_id)

    def complete_call(self, call_id: str, disposition: str = "completed") -> bool:
        return self.queue_functions.complete_call(call_id, disposition)

    def tick(self) -> None:
        self.queue_functions.tick()

    # -----------------------
    # Monitoring and controls.
    # -----------------------
    def start_monitoring(self, supervisor_id: str, call_id: str, mode: MonitoringMode) -> bool:
        with self._lock:
            call = self.active_calls.get(call_id)
            if not call:
                return False
            session = {"supervisor_id": supervisor_id, "mode": mode.value}
            call.monitoring_sessions.append(session)
            self._emit(call, "monitoring_started", session)
            return True

    def switch_agent_queue(self, agent_id: str, from_queue: str, to_queue: str) -> bool:
        with self._lock:
            agent = self.agents.get(agent_id)
            if not agent:
                return False
            if from_queue in agent.queue_memberships:
                agent.queue_memberships.remove(from_queue)
            agent.queue_memberships.add(to_queue)
            self._emit_agent_event(agent_id, "queue_switched", {"from": from_queue, "to": to_queue})
            return True

    # -----------------------
    # Summaries/helpers.
    # -----------------------
    def queue_snapshot(self, queue_number: str) -> dict[str, Any]:
        return self.queue_functions.queue_snapshot(queue_number)

    def export_state(self) -> dict[str, Any]:
        state = self.queue_functions.export_state()
        with self._lock:
            state["events"] = [asdict(event) for event in self.events]
        return state

    def _emit(self, call: Call, event_type: str, details: dict[str, Any]) -> None:
        self.events.append(
            QueueEvent(
                at=datetime.now(UTC),
                call_id=call.call_id,
                queue_number=call.queue_number,
                event_type=event_type,
                details=details,
            )
        )

    def _emit_agent_event(self, agent_id: str, event_type: str, details: dict[str, Any] | None = None) -> None:
        self.events.append(
            QueueEvent(
                at=datetime.now(UTC),
                call_id=f"agent:{agent_id}",
                queue_number="agent",
                event_type=event_type,
                details=details or {},
            )
        )

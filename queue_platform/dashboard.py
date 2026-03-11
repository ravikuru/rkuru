from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .models import AgentStatus, MonitoringMode
from .service import QueueEngine


class DashboardService:
    def __init__(self, engine: QueueEngine) -> None:
        self.engine = engine
        self.layouts: dict[str, list[dict[str, Any]]] = {}

    def queue_depth(self, queue_number: str) -> int:
        return len(self.engine.waiting_calls[queue_number])

    def longest_wait_seconds(self, queue_number: str) -> int:
        waiting = self.engine.waiting_calls[queue_number]
        if not waiting:
            return 0
        return int((datetime.now(UTC) - waiting[0].created_at).total_seconds())

    def service_level(self, queue_number: str, target_seconds: int = 20) -> float:
        answered = [
            c
            for c in self.engine.completed_calls
            if c.queue_number == queue_number and c.answered_at is not None
        ]
        if not answered:
            return 100.0
        within = [
            c for c in answered if (c.answered_at - c.created_at).total_seconds() <= target_seconds
        ]
        return round((len(within) / len(answered)) * 100.0, 2)

    def abandon_rate(self, queue_number: str) -> float:
        calls = [c for c in self.engine.completed_calls if c.queue_number == queue_number]
        if not calls:
            return 0.0
        abandoned = [c for c in calls if c.state.value in {"abandoned", "rejected"}]
        return round((len(abandoned) / len(calls)) * 100.0, 2)

    def agent_details(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for agent in self.engine.agents.values():
            rows.append(
                {
                    "agent_id": agent.agent_id,
                    "extension": agent.extension,
                    "status": agent.status.value,
                    "queues": sorted(agent.queue_memberships),
                    "calls_answered_today": agent.calls_answered_today,
                    "talk_seconds_today": agent.total_talk_seconds,
                    "idle_seconds_today": agent.total_idle_seconds,
                }
            )
        return rows

    def talk_vs_idle(self, agent_id: str) -> dict[str, int]:
        agent = self.engine.agents[agent_id]
        return {"talk_seconds": agent.total_talk_seconds, "idle_seconds": agent.total_idle_seconds}

    def call_count_leaderboard(self) -> list[dict[str, Any]]:
        agents = sorted(
            self.engine.agents.values(),
            key=lambda a: a.calls_answered_today,
            reverse=True,
        )
        return [
            {
                "agent_id": a.agent_id,
                "extension": a.extension,
                "calls_answered_today": a.calls_answered_today,
            }
            for a in agents
        ]

    def queue_monitor_view(self, queue_number: str) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        waiting = self.engine.waiting_calls[queue_number]
        return [
            {
                "call_id": c.call_id,
                "caller_id": c.caller_id,
                "wait_seconds": int((now - c.created_at).total_seconds()),
                "state": c.state.value,
            }
            for c in waiting
        ]

    def one_click_monitor(self, supervisor_id: str, call_id: str, mode: MonitoringMode) -> bool:
        return self.engine.start_monitoring(supervisor_id, call_id, mode)

    def switch_agent_queue(self, agent_id: str, from_queue: str, to_queue: str) -> bool:
        return self.engine.switch_agent_queue(agent_id, from_queue, to_queue)

    def wallboard(self, queue_number: str) -> dict[str, Any]:
        return {
            "queue_number": queue_number,
            "queue_depth": self.queue_depth(queue_number),
            "longest_wait_seconds": self.longest_wait_seconds(queue_number),
            "service_level_20s": self.service_level(queue_number, 20),
            "abandon_rate": self.abandon_rate(queue_number),
            "agents_available": len(
                [
                    a
                    for a in self.engine.agents.values()
                    if queue_number in a.queue_memberships and a.status == AgentStatus.AVAILABLE
                ]
            ),
        }

    def save_layout(self, view_name: str, widgets: list[dict[str, Any]]) -> None:
        # Widgets can hold x/y/w/h for drag-and-drop UI editors.
        self.layouts[view_name] = widgets

    def multi_queue_view(self, queue_numbers: list[str]) -> dict[str, dict[str, Any]]:
        return {q: self.wallboard(q) for q in queue_numbers}

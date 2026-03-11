from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from statistics import mean
from typing import Any

from .service import QueueEngine


class AnalyticsService:
    def __init__(self, engine: QueueEngine) -> None:
        self.engine = engine

    def live_report(self) -> dict[str, Any]:
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "queue_health": {
                q: len(calls) for q, calls in self.engine.waiting_calls.items()
            },
            "active_calls": len(self.engine.active_calls),
            "agents": len(self.engine.agents),
        }

    def performance_metrics(self, queue_number: str) -> dict[str, Any]:
        calls = [c for c in self.engine.completed_calls if c.queue_number == queue_number]
        answered = [c for c in calls if c.answered_at and c.completed_at]
        waits = [(c.answered_at - c.created_at).total_seconds() for c in answered]
        talks = [(c.completed_at - c.answered_at).total_seconds() for c in answered]
        abandons = [c for c in calls if c.state.value in {"abandoned", "rejected"}]
        return {
            "queue_number": queue_number,
            "total_calls": len(calls),
            "answered_calls": len(answered),
            "abandoned_calls": len(abandons),
            "abandon_rate": round((len(abandons) / len(calls)) * 100.0, 2) if calls else 0.0,
            "avg_wait_seconds": round(mean(waits), 2) if waits else 0.0,
            "avg_talk_seconds": round(mean(talks), 2) if talks else 0.0,
        }

    def overflow_overview(self) -> dict[str, Any]:
        overflowed = [c for c in self.engine.completed_calls if c.overflow_count > 0]
        by_queue: dict[str, int] = defaultdict(int)
        for call in overflowed:
            by_queue[call.queue_number] += 1
        return {"total_overflowed_calls": len(overflowed), "destination_counts": dict(by_queue)}

    def queue_details_widget(self, queue_number: str) -> dict[str, Any]:
        metrics = self.performance_metrics(queue_number)
        waiting = self.engine.waiting_calls[queue_number]
        metrics.update({"currently_waiting": len(waiting)})
        return metrics

    def agent_productivity(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for agent in self.engine.agents.values():
            rows.append(
                {
                    "agent_id": agent.agent_id,
                    "extension": agent.extension,
                    "calls_answered_today": agent.calls_answered_today,
                    "total_talk_seconds": agent.total_talk_seconds,
                    "efficiency_score": round(
                        agent.calls_answered_today / (agent.total_talk_seconds / 60.0 + 1.0), 2
                    ),
                }
            )
        rows.sort(key=lambda r: r["calls_answered_today"], reverse=True)
        return rows

    def overall_call_statistics(self) -> dict[str, Any]:
        calls = self.engine.completed_calls
        answered = [c for c in calls if c.answered_at and c.completed_at]
        talks = [(c.completed_at - c.answered_at).total_seconds() for c in answered]
        return {
            "total_calls": len(calls),
            "active_calls": len(self.engine.active_calls),
            "average_handle_time_seconds": round(mean(talks), 2) if talks else 0.0,
            "by_queue": {
                queue_number: len([c for c in calls if c.queue_number == queue_number])
                for queue_number in self.engine.queues
            },
        }

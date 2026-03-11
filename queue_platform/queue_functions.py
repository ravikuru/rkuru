from __future__ import annotations

import csv
import uuid
from collections import deque
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any, Callable

from .models import Agent, AgentStatus, Call, CallState, QueueConfig
from .router import pick_agents_for_call, pick_overflow_queue


class QueueFunctions:
    """
    Dedicated queue behavior class.

    QueueEngine composes this class so queue logic can evolve independently.
    """

    def __init__(
        self,
        *,
        lock: RLock,
        queues: dict[str, QueueConfig],
        agents: dict[str, Agent],
        waiting_calls: dict[str, deque[Call]],
        active_calls: dict[str, Call],
        completed_calls: list[Call],
        wrap_up_until: dict[str, datetime],
        voicemail_records: list[dict[str, Any]],
        caller_agent_history: dict[str, str],
        emit: Callable[[Call, str, dict[str, Any]], None],
        emit_agent_event: Callable[[str, str, dict[str, Any] | None], None],
    ) -> None:
        self._lock = lock
        self.queues = queues
        self.agents = agents
        self.waiting_calls = waiting_calls
        self.active_calls = active_calls
        self.completed_calls = completed_calls
        self.wrap_up_until = wrap_up_until
        self.voicemail_records = voicemail_records
        self.caller_agent_history = caller_agent_history
        self._emit = emit
        self._emit_agent_event = emit_agent_event

    def add_queue(self, config: QueueConfig) -> None:
        with self._lock:
            self.queues[config.number] = config

    def add_member(self, queue_number: str, agent_id: str) -> None:
        with self._lock:
            queue = self.queues[queue_number]
            agent = self.agents[agent_id]
            agent.queue_memberships.add(queue.number)

    def remove_member(self, queue_number: str, agent_id: str) -> None:
        with self._lock:
            if agent_id not in self.agents:
                return
            self.agents[agent_id].queue_memberships.discard(queue_number)

    def bulk_members_from_csv(self, csv_path: str) -> int:
        count = 0
        with self._lock:
            with open(csv_path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    aid = row["agent_id"].strip()
                    if aid not in self.agents:
                        self.agents[aid] = Agent(
                            agent_id=aid,
                            extension=row.get("extension", aid).strip(),
                            status=AgentStatus(row.get("status", AgentStatus.AVAILABLE.value)),
                            skills={s for s in row.get("skills", "").split("|") if s},
                            languages={l for l in row.get("languages", "").split("|") if l},
                        )
                    queue_number = row["queue_number"].strip()
                    self.add_member(queue_number, aid)
                    count += 1
        return count

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
        with self._lock:
            now = datetime.now(UTC)
            queue = self.queues[queue_number]
            call = Call(
                call_id=str(uuid.uuid4()),
                caller_id=caller_id,
                destination_number=destination_number,
                source_ip=source_ip,
                queue_number=queue.number,
                created_at=now,
                required_skills=required_skills or set(),
                preferred_language=preferred_language,
                metadata=metadata or {},
                recording_enabled=queue.record_calls,
            )
            self._emit(call, "call_enqueued", {"greeting": queue.greeting_file, "hold_music": queue.hold_music})

            if len(self.waiting_calls[queue.number]) >= queue.max_queue_size:
                overflow_target = pick_overflow_queue(queue, self.queues)
                if overflow_target:
                    call.overflow_count += 1
                    call.queue_number = overflow_target.number
                    call.state = CallState.OVERFLOWED
                    self._emit(call, "call_overflowed", {"to_queue": overflow_target.number})
                    self.waiting_calls[overflow_target.number].append(call)
                    return call
                call.state = CallState.REJECTED
                self._emit(call, "call_rejected_queue_full", {})
                self.completed_calls.append(call)
                return call

            self.waiting_calls[queue.number].append(call)
            return call

    def route_calls(self) -> None:
        with self._lock:
            now = datetime.now(UTC)
            for queue_number, queue in self.queues.items():
                self._expire_waiting_calls(queue, now)
                if not self.waiting_calls[queue_number]:
                    continue
                call = self.waiting_calls[queue_number][0]
                picks = pick_agents_for_call(queue, call, self.agents, now)
                if not picks:
                    continue

                call.state = CallState.OFFERED
                call.offered_at = now
                call.offered_agent_ids = [a.agent_id for a in picks]
                self._emit(call, "call_offered", {"agent_ids": call.offered_agent_ids})

                if queue.strategy.value != "ring-all":
                    self.answer_call(picks[0].agent_id, call.call_id)

    def answer_call(self, agent_id: str, call_id: str) -> bool:
        with self._lock:
            queue_calls = [c for queue in self.waiting_calls.values() for c in queue if c.call_id == call_id]
            if not queue_calls:
                return False
            call = queue_calls[0]
            queue = self.queues[call.queue_number]
            agent = self.agents[agent_id]
            if agent.status != AgentStatus.AVAILABLE:
                return False

            self.waiting_calls[queue.number] = deque(c for c in self.waiting_calls[queue.number] if c.call_id != call_id)
            call.state = CallState.ACTIVE
            call.answered_by_agent_id = agent_id
            call.answered_at = datetime.now(UTC)
            agent.status = AgentStatus.BUSY
            agent.current_call_id = call.call_id
            self.active_calls[call.call_id] = call
            self._emit(
                call,
                "call_answered",
                {
                    "agent_id": agent_id,
                    "recording": queue.record_calls,
                    "wait_announcement_enabled": queue.announce_wait,
                },
            )
            return True

    def complete_call(self, call_id: str, disposition: str = "completed") -> bool:
        with self._lock:
            call = self.active_calls.pop(call_id, None)
            if call is None:
                return False
            now = datetime.now(UTC)
            queue = self.queues[call.queue_number]
            agent = self.agents[call.answered_by_agent_id] if call.answered_by_agent_id else None
            call.state = CallState.COMPLETED
            call.disposition = disposition
            call.completed_at = now

            if agent:
                talk_seconds = max(int((now - (call.answered_at or now)).total_seconds()), 0)
                agent.total_talk_seconds += talk_seconds
                agent.calls_answered_today += 1
                agent.status = AgentStatus.WRAP_UP
                agent.current_call_id = None
                self.wrap_up_until[agent.agent_id] = now + timedelta(seconds=queue.wrap_up_seconds)
                self.caller_agent_history[call.caller_id] = agent.agent_id
            self._emit(call, "call_completed", {"disposition": disposition})
            self.completed_calls.append(call)
            return True

    def tick(self) -> None:
        with self._lock:
            now = datetime.now(UTC)
            for agent_id, until in list(self.wrap_up_until.items()):
                if now >= until:
                    agent = self.agents.get(agent_id)
                    if agent and agent.status == AgentStatus.WRAP_UP:
                        agent.status = AgentStatus.AVAILABLE
                        agent.last_call_end_at = now
                        self._emit_agent_event(agent_id, "agent_wrap_up_complete", None)
                    self.wrap_up_until.pop(agent_id, None)
            self.route_calls()

    def queue_snapshot(self, queue_number: str) -> dict[str, Any]:
        with self._lock:
            queue = self.queues[queue_number]
            waiting = list(self.waiting_calls[queue_number])
            return {
                "queue": asdict(queue),
                "waiting_count": len(waiting),
                "oldest_wait_seconds": (
                    int((datetime.now(UTC) - waiting[0].created_at).total_seconds()) if waiting else 0
                ),
                "active_calls": [c.call_id for c in self.active_calls.values() if c.queue_number == queue_number],
            }

    def export_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "queues": {k: asdict(v) for k, v in self.queues.items()},
                "agents": {k: asdict(v) for k, v in self.agents.items()},
                "waiting_calls": {
                    k: [asdict(c) for c in v]
                    for k, v in self.waiting_calls.items()
                },
                "active_calls": {k: asdict(v) for k, v in self.active_calls.items()},
                "completed_calls": [asdict(c) for c in self.completed_calls],
            }

    def _expire_waiting_calls(self, queue: QueueConfig, now: datetime) -> None:
        waiting = self.waiting_calls[queue.number]
        retained: deque[Call] = deque()
        while waiting:
            call = waiting.popleft()
            waited = (now - call.created_at).total_seconds()
            if waited <= queue.max_wait_seconds:
                retained.append(call)
                continue

            overflow_target = pick_overflow_queue(queue, self.queues)
            if overflow_target and call.overflow_count < 3:
                call.overflow_count += 1
                call.queue_number = overflow_target.number
                call.state = CallState.OVERFLOWED
                self.waiting_calls[overflow_target.number].append(call)
                self._emit(call, "call_overflowed_wait_timeout", {"to_queue": overflow_target.number})
                continue

            if queue.voicemail_box:
                call.state = CallState.VOICEMAIL
                self.voicemail_records.append(
                    {
                        "call_id": call.call_id,
                        "voicemail_box": queue.voicemail_box,
                        "notify_email": queue.voicemail_email_targets,
                        "notify_sms": queue.voicemail_sms_targets,
                        "recorded_at": now.isoformat(),
                    }
                )
                self._emit(call, "call_sent_to_voicemail", {"mailbox": queue.voicemail_box})
            else:
                call.state = CallState.ABANDONED
                self._emit(call, "call_abandoned_wait_timeout", {})
            call.completed_at = now
            self.completed_calls.append(call)
        self.waiting_calls[queue.number] = retained

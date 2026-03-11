from __future__ import annotations

from datetime import datetime
from math import inf

from .models import Agent, AgentStatus, Call, QueueConfig, RoutingStrategy


def _available_members(
    queue: QueueConfig,
    call: Call,
    all_agents: dict[str, Agent],
) -> list[Agent]:
    agents: list[Agent] = []
    for agent in all_agents.values():
        if queue.number not in agent.queue_memberships:
            continue
        if agent.status != AgentStatus.AVAILABLE:
            continue
        agents.append(agent)
    return agents


def _skills_score(call: Call, agent: Agent, now: datetime) -> tuple[float, float]:
    skill_hits = len(call.required_skills.intersection(agent.skills))
    lang_bonus = 1.0 if call.preferred_language and call.preferred_language in agent.languages else 0.0
    if agent.last_call_end_at is None:
        idle_seconds = inf
    else:
        idle_seconds = max((now - agent.last_call_end_at).total_seconds(), 0.0)
    return (skill_hits * 10.0 + lang_bonus * 5.0, idle_seconds)


def pick_agents_for_call(
    queue: QueueConfig,
    call: Call,
    all_agents: dict[str, Agent],
    now: datetime,
) -> list[Agent]:
    candidates = _available_members(queue, call, all_agents)
    if not candidates:
        return []

    strategy = queue.strategy
    if strategy == RoutingStrategy.LONGEST_IDLE:
        candidates.sort(
            key=lambda a: a.last_call_end_at if a.last_call_end_at is not None else datetime.min
        )
        return [candidates[0]]

    if strategy == RoutingStrategy.SIMULTANEOUS:
        candidates.sort(
            key=lambda a: a.last_call_end_at if a.last_call_end_at is not None else datetime.min
        )
        return candidates[: queue.simultaneous_ring_limit]

    if strategy == RoutingStrategy.SEQUENTIAL:
        if queue.sequential_order:
            by_id = {a.agent_id: a for a in candidates}
            ordered = [by_id[aid] for aid in queue.sequential_order if aid in by_id]
            remainder = [a for a in candidates if a.agent_id not in set(queue.sequential_order)]
            return ordered + remainder
        candidates.sort(
            key=lambda a: a.last_call_end_at if a.last_call_end_at is not None else datetime.min
        )
        return candidates

    # Skills-based fallback.
    candidates.sort(key=lambda a: _skills_score(call, a, now), reverse=True)
    return [candidates[0]]


def pick_overflow_queue(current: QueueConfig, available_queues: dict[str, QueueConfig]) -> QueueConfig | None:
    for queue_number in current.overflow_queues[:3]:
        target = available_queues.get(queue_number)
        if target:
            return target
    return None

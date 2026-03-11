from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RoutingStrategy(str, Enum):
    LONGEST_IDLE = "longest-idle-agent"
    SIMULTANEOUS = "ring-all"
    SEQUENTIAL = "top-down"
    SKILLS_BASED = "skills-based"


class AgentStatus(str, Enum):
    AVAILABLE = "available"
    BUSY = "busy"
    WRAP_UP = "wrap-up"
    OFFLINE = "offline"
    DND = "dnd"


class CallState(str, Enum):
    QUEUED = "queued"
    OFFERED = "offered"
    ACTIVE = "active"
    WRAP_UP = "wrap-up"
    ABANDONED = "abandoned"
    OVERFLOWED = "overflowed"
    VOICEMAIL = "voicemail"
    COMPLETED = "completed"
    REJECTED = "rejected"


class MonitoringMode(str, Enum):
    MONITOR = "monitor"
    WHISPER = "whisper"
    BARGE = "barge"
    TAKEOVER = "takeover"


@dataclass(slots=True)
class QueueConfig:
    name: str
    number: str
    strategy: RoutingStrategy = RoutingStrategy.LONGEST_IDLE
    max_wait_seconds: int = 300
    max_queue_size: int = 25
    wrap_up_seconds: int = 30
    greeting_file: str | None = None
    hold_music: str = "local_stream://moh"
    announce_wait: bool = True
    overflow_queues: list[str] = field(default_factory=list)
    voicemail_box: str | None = None
    voicemail_email_targets: list[str] = field(default_factory=list)
    voicemail_sms_targets: list[str] = field(default_factory=list)
    record_calls: bool = True
    simultaneous_ring_limit: int = 10
    sequential_order: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Agent:
    agent_id: str
    extension: str
    status: AgentStatus = AgentStatus.AVAILABLE
    skills: set[str] = field(default_factory=set)
    languages: set[str] = field(default_factory=set)
    last_call_end_at: datetime | None = None
    current_call_id: str | None = None
    queue_memberships: set[str] = field(default_factory=set)
    calls_answered_today: int = 0
    total_talk_seconds: int = 0
    total_idle_seconds: int = 0


@dataclass(slots=True)
class Call:
    call_id: str
    caller_id: str
    destination_number: str
    source_ip: str
    queue_number: str
    created_at: datetime
    state: CallState = CallState.QUEUED
    required_skills: set[str] = field(default_factory=set)
    preferred_language: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    offered_agent_ids: list[str] = field(default_factory=list)
    answered_by_agent_id: str | None = None
    offered_at: datetime | None = None
    answered_at: datetime | None = None
    completed_at: datetime | None = None
    overflow_count: int = 0
    recording_enabled: bool = False
    monitoring_sessions: list[dict[str, str]] = field(default_factory=list)
    disposition: str | None = None


@dataclass(slots=True)
class QueueEvent:
    at: datetime
    call_id: str
    queue_number: str
    event_type: str
    details: dict[str, Any] = field(default_factory=dict)

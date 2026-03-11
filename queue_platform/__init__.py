"""Contact-center queue platform reference implementation."""

from .ai import AIRoutingAdvisor
from .analytics import AnalyticsService
from .dashboard import DashboardService
from .facade import ContactCenterPlatform
from .models import (
    Agent,
    AgentStatus,
    Call,
    CallState,
    MonitoringMode,
    QueueConfig,
    RoutingStrategy,
)
from .service import QueueEngine

__all__ = [
    "AIRoutingAdvisor",
    "AnalyticsService",
    "DashboardService",
    "ContactCenterPlatform",
    "QueueEngine",
    "Agent",
    "AgentStatus",
    "Call",
    "CallState",
    "MonitoringMode",
    "QueueConfig",
    "RoutingStrategy",
]

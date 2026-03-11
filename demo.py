from __future__ import annotations

from datetime import UTC, datetime
from pprint import pprint

from queue_platform import Agent, ContactCenterPlatform, QueueConfig, RoutingStrategy


def build_demo_platform() -> ContactCenterPlatform:
    platform = ContactCenterPlatform()

    platform.configure_queue(
        QueueConfig(
            name="Sales",
            number="7001",
            strategy=RoutingStrategy.LONGEST_IDLE,
            max_wait_seconds=300,
            max_queue_size=25,
            wrap_up_seconds=30,
            greeting_file="sounds/custom/sales_welcome.wav",
            hold_music="local_stream://moh",
            overflow_queues=["7002", "7003"],
            voicemail_box="9001",
            voicemail_email_targets=["manager@example.com"],
            record_calls=True,
        )
    )
    platform.configure_queue(
        QueueConfig(
            name="Support",
            number="7002",
            strategy=RoutingStrategy.SIMULTANEOUS,
            simultaneous_ring_limit=10,
            overflow_queues=["7003"],
            voicemail_box="9002",
            record_calls=True,
        )
    )

    platform.configure_agent(
        Agent(
            agent_id="agent-1001",
            extension="1001",
            skills={"sales", "de-escalation"},
            languages={"en", "fr"},
            last_call_end_at=datetime.now(UTC),
        )
    )
    platform.configure_agent(
        Agent(
            agent_id="agent-1002",
            extension="1002",
            skills={"support", "billing"},
            languages={"en"},
            last_call_end_at=datetime.now(UTC),
        )
    )

    platform.add_agent_to_queue("7001", "agent-1001")
    platform.add_agent_to_queue("7002", "agent-1002")
    platform.add_agent_to_queue("7002", "agent-1001")
    return platform


def main() -> None:
    platform = build_demo_platform()

    print("\n--- Gemini Voice Entry (Sales) ---")
    sales_voice_route = platform.ai_voice_entry(
        caller_id="6475550123",
        destination_number="4163501959",
        source_ip="64.34.222.200",
        caller_utterance="Hi, I need sales please.",
    )
    pprint(sales_voice_route)
    platform.execute_cycle()

    print("\n--- Gemini Voice Entry (Invalid) ---")
    invalid_voice_route = platform.ai_voice_entry(
        caller_id="6475550456",
        destination_number="4163501959",
        source_ip="69.90.209.10",
        caller_utterance="I want technical drawings.",
    )
    pprint(invalid_voice_route)

    call = platform.ingest_incoming_call(
        queue_number="7001",
        caller_id="4163501959",
        destination_number="7001",
        source_ip="69.90.209.70",
        metadata={
            "required_skills": ["sales"],
            "preferred_language": "en",
            "upsell_candidate": True,
        },
    )
    platform.execute_cycle()
    # In a real telephony flow, answer/complete are triggered by signaling events.
    if call.offered_agent_ids:
        platform.engine.answer_call(call.offered_agent_ids[0], call.call_id)
        platform.engine.complete_call(call.call_id, "customer_resolved")
    platform.execute_cycle()

    print("\n--- Wallboard ---")
    pprint(platform.dashboard.wallboard("7001"))
    print("\n--- Queue Monitor ---")
    pprint(platform.dashboard.queue_monitor_view("7001"))
    print("\n--- Performance ---")
    pprint(platform.analytics.performance_metrics("7001"))
    print("\n--- AI Routing Preview ---")
    preview = platform.ai_routing_preview(call)
    pprint(preview)


if __name__ == "__main__":
    main()

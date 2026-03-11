# Contact Center Queue Platform (Python)

Python reference implementation covering queue routing, dashboard metrics, analytics, and an extensible AI-routing advisor.

## Implemented feature coverage

### Queue
- Rotating / longest-idle routing
- Simultaneous routing (ring-all, up to 10 agents)
- Sequential fixed-order routing
- Skills-based routing
- Member management (add/remove/bulk CSV import)
- Call overflow (up to 3 fallback queues)
- Maximum wait time handling
- Queue capacity limits
- After-call wrap-up timer
- Custom greetings + hold music metadata
- Wait announcement flags
- Queue voicemail + email/SMS notification metadata
- Call monitoring modes: monitor/whisper/barge/takeover (session model)
- Call recording enable flag per queue

### Dashboard
- Calls in queue (depth)
- Longest wait time
- SLA %
- Abandon rate
- Agent detail/status view
- Talk time vs idle time
- Call-count leaderboard
- Queue monitor (active waiting caller list)
- One-click monitoring command wrapper
- Queue switching helper
- Wallboard payload
- Drag-and-drop layout persistence model
- Multi-queue wallboard view

### Analytics
- Live report payload
- Historical queue performance metrics
- Overflow overview
- Queue details widget
- Agent productivity report
- Overall call statistics

### Future / AI
- Dynamic agent matching (heuristic)
- Continuity routing by caller history
- Real-time load-aware suggestions
- Proactive intervention messaging hooks

## Quick start

```bash
python3 demo.py
```

## Structure

```text
queue_platform/
  __init__.py
  models.py
  router.py
  service.py
  dashboard.py
  analytics.py
  ai.py
  facade.py
demo.py
```

## Notes

- This project is an application-layer reference implementation.
- Telephony signaling/media execution (e.g., FreeSWITCH ESL event handlers, SIP leg control) should call into `QueueEngine` methods.
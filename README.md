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
- Gemini voice entry routing (Sales intent -> Sales queue)

## Quick start

```bash
python3 demo.py
```

## Gemini voice entry behavior

- Greeting: `Hi, this is Callture. How can I help you?`
- If caller intent is `sales`, route to configured queue with name containing `Sales`.
- Otherwise return: `Sorry, invalid option.`

Implementation entrypoint:

- `ContactCenterPlatform.ai_voice_entry(...)`

Gemini configuration:

- Set `GEMINI_API_KEY` in environment to enable Gemini intent classification.
- `API_KEY` is also accepted for compatibility with curl examples.
- Default model is `gemini-live-2.5-flash-native-audio` (override with `GEMINI_MODEL`).
- Live audio path is enabled by default (`GEMINI_ENABLE_LIVE_AUDIO=1`) and uses the
  Python GenAI Live SDK (`google-genai`) with `client.aio.live.connect(...)`.
- Live SDK API version defaults to `v1alpha` (`GEMINI_LIVE_API_VERSION`).
- Live audio stream chunk size defaults to `4096` bytes (`GEMINI_LIVE_CHUNK_BYTES`).
- Live receive timeout defaults to `10` seconds (`GEMINI_LIVE_RECEIVE_TIMEOUT_SECONDS`).
- For Vertex mode, set `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`.
- If selected model is unsupported by `streamGenerateContent`, router auto-falls back to
  `GEMINI_FALLBACK_MODEL` (default `gemini-2.5-flash-lite`).
- Default endpoint template is Vertex-style:
  `https://aiplatform.googleapis.com/v1/publishers/google/models/{model}:streamGenerateContent`
  (override with `GEMINI_API_ENDPOINT_TEMPLATE`).
- Without an API key, system falls back to keyword intent detection (e.g., "sales", "pricing", "quote").

Install dependency for Live audio mode:

```bash
pip install google-genai
```

## Structure

```text
queue_platform/
  __init__.py
  models.py
  router.py
  queue_functions.py
  service.py
  dashboard.py
  analytics.py
  ai.py
  facade.py
demo.py
```

## Notes

- This project is an application-layer reference implementation.
- Queue-specific behavior is isolated in `QueueFunctions` for easier feature expansion later.
- Telephony signaling/media execution (e.g., FreeSWITCH ESL event handlers, SIP leg control) should call into `QueueEngine` methods.
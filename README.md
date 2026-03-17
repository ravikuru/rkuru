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

### WebRTC Phone
- Browser-based SIP softphone for FreeSWITCH (SIP over WebSocket via JsSIP)
- Outbound and inbound call handling with WebRTC audio
- Full dialpad with DTMF in-call support
- Call controls: mute, hold, blind/attended transfer
- Registration status, call timer, call history
- Live queue dashboard with wallboard metrics from the platform API
- Configurable WebSocket URL, SIP credentials, STUN/TURN servers
- Settings persistence via localStorage
- Keyboard shortcuts (Enter to dial, Escape to hang up)

## Quick start

```bash
# Run the in-memory queue platform demo
python3 demo.py

# Launch the WebRTC phone UI (serves on http://localhost:8080)
python3 webrtc_phone/server.py
```

### FreeSWITCH configuration

The WebRTC phone connects to FreeSWITCH via SIP over WebSocket. Ensure your FreeSWITCH has:

1. **`mod_sofia`** with a WebSocket listener (ws/wss on e.g. port 7443)
2. **SRTP** enabled for the profile
3. **ICE** support configured

Example `sip_profile` additions:
```xml
<param name="ws-binding" value=":5066"/>
<param name="wss-binding" value=":7443"/>
```

Then point the phone's **WebSocket URL** to `wss://your-freeswitch:7443` and register with a valid SIP extension/password.

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
webrtc_phone/
  server.py              # HTTP server + JSON API bridge
  static/
    index.html           # Phone UI
    css/phone.css        # Styling
    js/app.js            # JsSIP SIP/WebRTC integration
demo.py
```

## Notes

- This project is an application-layer reference implementation.
- Queue-specific behavior is isolated in `QueueFunctions` for easier feature expansion later.
- Telephony signaling/media execution (e.g., FreeSWITCH ESL event handlers, SIP leg control) should call into `QueueEngine` methods.
- The WebRTC phone uses only the Python standard library for its server and JsSIP (loaded from CDN) on the client—no npm/node required.
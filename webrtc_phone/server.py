"""Lightweight HTTP server for the WebRTC phone client.

Uses only the Python standard library.  Serves static files from ./static/
and exposes a minimal JSON API that bridges browser requests to the
ContactCenterPlatform (queue status, agent list, etc.).

Usage:
    python3 webrtc_phone/server.py [--port PORT]
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from queue_platform import (
    Agent,
    ContactCenterPlatform,
    QueueConfig,
    RoutingStrategy,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"

platform = ContactCenterPlatform()


def _seed_demo_data() -> None:
    """Pre-populate queues and agents so the dashboard has something to show."""
    platform.configure_queue(
        QueueConfig(
            name="Sales",
            number="7001",
            strategy=RoutingStrategy.LONGEST_IDLE,
            max_wait_seconds=300,
            max_queue_size=25,
            wrap_up_seconds=30,
            overflow_queues=["7002"],
            voicemail_box="9001",
            record_calls=True,
        )
    )
    platform.configure_queue(
        QueueConfig(
            name="Support",
            number="7002",
            strategy=RoutingStrategy.SIMULTANEOUS,
            simultaneous_ring_limit=10,
            voicemail_box="9002",
            record_calls=True,
        )
    )
    for ext, skills, langs in [
        ("1001", {"sales", "de-escalation"}, {"en", "fr"}),
        ("1002", {"support", "billing"}, {"en"}),
        ("1003", {"sales", "support"}, {"en", "es"}),
    ]:
        agent = Agent(
            agent_id=f"agent-{ext}",
            extension=ext,
            skills=skills,
            languages=langs,
            last_call_end_at=datetime.now(UTC),
        )
        platform.configure_agent(agent)
        if "sales" in skills:
            platform.add_agent_to_queue("7001", agent.agent_id)
        if "support" in skills:
            platform.add_agent_to_queue("7002", agent.agent_id)


def _json_serial(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Type {type(obj)} not serialisable")


def _json_response(data: Any) -> bytes:
    return json.dumps(data, default=_json_serial, indent=2).encode()


class PhoneHTTPHandler(BaseHTTPRequestHandler):
    """Serve static assets + JSON API endpoints."""

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            self._serve_file("index.html")
        elif self.path.startswith("/api/"):
            self._handle_api()
        else:
            rel = self.path.lstrip("/")
            self._serve_file(rel)

    def do_POST(self) -> None:
        if self.path.startswith("/api/"):
            self._handle_api()
        else:
            self._send_error(404)

    def _serve_file(self, rel_path: str) -> None:
        target = (STATIC_DIR / rel_path).resolve()
        if not str(target).startswith(str(STATIC_DIR)):
            self._send_error(403)
            return
        if not target.is_file():
            self._send_error(404)
            return
        mime, _ = mimetypes.guess_type(str(target))
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(target.read_bytes())

    def _handle_api(self) -> None:
        if self.path == "/api/queues":
            data = []
            for q in platform.engine.queues.values():
                data.append(asdict(q))
            self._send_json(data)

        elif self.path == "/api/agents":
            data = []
            for a in platform.engine.agents.values():
                data.append(asdict(a))
            self._send_json(data)

        elif self.path.startswith("/api/wallboard/"):
            qnum = self.path.split("/")[-1]
            try:
                wb = platform.dashboard.wallboard(qnum)
                self._send_json(wb)
            except KeyError:
                self._send_json({"error": f"Queue {qnum} not found"}, status=404)

        elif self.path.startswith("/api/performance/"):
            qnum = self.path.split("/")[-1]
            try:
                perf = platform.analytics.performance_metrics(qnum)
                self._send_json(perf)
            except KeyError:
                self._send_json({"error": f"Queue {qnum} not found"}, status=404)

        elif self.path == "/api/state":
            self._send_json(platform.engine.export_state())

        else:
            self._send_json({"error": "Unknown endpoint"}, status=404)

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = _json_response(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int) -> None:
        self.send_response(code)
        self.end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[phone-server] {self.address_string()} - {fmt % args}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="WebRTC Phone Server")
    parser.add_argument("--port", type=int, default=8080, help="HTTP listen port")
    args = parser.parse_args()

    _seed_demo_data()

    server = HTTPServer(("0.0.0.0", args.port), PhoneHTTPHandler)
    print(f"WebRTC Phone server listening on http://0.0.0.0:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()

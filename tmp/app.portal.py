from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import textwrap
import threading
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from fastapi import FastAPI, File, Form, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.websockets import WebSocketState
import websockets

from queue_platform import Agent, ContactCenterPlatform, QueueConfig, RoutingStrategy

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "portal.db"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
FAX_STORAGE_DIR = Path("/usr/local/freeswitch/storage/fax")
FAX_INBOUND_DIR = FAX_STORAGE_DIR / "inbound"
FAX_OUTBOUND_DIR = FAX_STORAGE_DIR / "outbound"
FAX_TIFF_TO_PDF_SCRIPT = "/usr/local/bin/callture_fax_tiff_to_pdf.sh"
FAX_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tga", ".svg"}
FAX_UPLOAD_DIR = Path("/tmp/callture_fax_uploads")
FAX_FIXED_FROM_NUMBER = "6472585272"
FAX_FIXED_FROM_NAME = "Ravi Kuru"
WEBRTC_DEFAULT_EXTENSION = "4166287801"
WEBRTC_DEFAULT_PASSWORD = "telcan2008!"
# Default user-part for outbound WebRTC->external SIP From/Contact headers.
# Override with env var WEBRTC_OUTBOUND_IDENTITY_DEFAULT if needed.
WEBRTC_OUTBOUND_IDENTITY_DEFAULT = os.getenv("WEBRTC_OUTBOUND_IDENTITY_DEFAULT", "6472585272").strip()
REGISTERED_FIRST_OUTBOUND_TRUNK = os.getenv("CC_REGISTERED_FIRST_OUTBOUND_TRUNK", "kamailio6932").strip() or "kamailio6932"
NANP_10_OR_11_DIGIT_EXPR = r"^(1?[2-9]\d{9})$"

APP_SECRET = os.getenv("CC_PORTAL_SECRET", "change-me-now-secret")
DEFAULT_ADMIN_USER = os.getenv("CC_ADMIN_USER", "rkuru")
DEFAULT_ADMIN_PASSWORD = os.getenv("CC_ADMIN_PASSWORD", "Lukshumi2008!")
PROVISION_SIP_SERVER = os.getenv("PROVISION_SIP_SERVER", "").strip()
try:
    PROVISION_SIP_PORT = int(os.getenv("PROVISION_SIP_PORT", "5060"))
except ValueError:
    PROVISION_SIP_PORT = 5060
PROVISION_SIP_TRANSPORT = os.getenv("PROVISION_SIP_TRANSPORT", "udp").strip().lower()


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, value)

SUSPICIOUS_REQUEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(?:\bunion\b\s+\bselect\b|\bor\b\s+1=1|\bdrop\b\s+\btable\b)"),
    re.compile(r"(?i)(?:information_schema|/etc/passwd|wp-admin|phpmyadmin|\.env)"),
    re.compile(r"(?i)(?:<script|%3cscript|javascript:|\.\./|%2e%2e|%00)"),
)
AUTO_BLOCK_ENABLED = os.getenv("CC_SECURITY_AUTOBLOCK_ENABLED", "1").strip() in {"1", "true", "yes", "on"}
AUTO_BLOCK_INTERVAL_SECONDS = _env_int("CC_SECURITY_AUTOBLOCK_INTERVAL_SECONDS", 300, 60)
AUTO_BLOCK_LOOKBACK_MINUTES = _env_int("CC_SECURITY_AUTOBLOCK_LOOKBACK_MINUTES", 5, 1)
AUTO_BLOCK_MIN_EVENTS = _env_int("CC_SECURITY_AUTOBLOCK_MIN_EVENTS", 3, 1)

AUTO_BLOCK_EVENT_TYPES = (
    "suspicious_request_pattern",
    "probing_404",
    "possible_bruteforce",
    "sip_invite_probe",
    "conference_manage_unauthorized",
    "conference_invite_unauthorized",
    "conference_control_unauthorized",
)
SENSITIVE_ACTION_BLOCK_WINDOW_MINUTES = _env_int("CC_SENSITIVE_ACTION_BLOCK_WINDOW_MINUTES", 10, 1)
SENSITIVE_ACTION_BLOCK_THRESHOLD = _env_int("CC_SENSITIVE_ACTION_BLOCK_THRESHOLD", 5, 2)
SIP_INVITE_PROBE_ENABLED = os.getenv("CC_SIP_INVITE_PROBE_ENABLED", "1").strip() in {"1", "true", "yes", "on"}
SIP_INVITE_SCAN_TAIL_BYTES = _env_int("CC_SIP_INVITE_SCAN_TAIL_BYTES", 3_000_000, 250_000)
SIP_INVITE_SCAN_OFFSET_FILE = BASE_DIR / ".sip_invite_scan.offset"
FREESWITCH_LOG_FILE = Path("/usr/local/freeswitch/log/freeswitch.log")
SIP_INVITE_PROBE_RE = re.compile(
    r"sofia/internal/([^@\s]+)@[^\s]+\s+receiving invite from\s+([0-9A-Fa-f:.]+):\d+",
    re.IGNORECASE,
)


app = FastAPI(title="Callture Portal")
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET, max_age=3600 * 12)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

platform = ContactCenterPlatform()
security_autoblock_stop = threading.Event()
security_autoblock_thread: threading.Thread | None = None
WEBRTC_UPSTREAM_LAST_GOOD: str | None = None
WEBRTC_ACTIVE_CLIENTS: dict[str, WebSocket] = {}


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def request_ip(request: Request) -> str:
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        return xff.split(",", 1)[0].strip()
    xreal = (request.headers.get("x-real-ip") or "").strip()
    if xreal:
        return xreal
    return request.client.host if request.client else ""


def request_ip_from_scope(scope: dict[str, Any]) -> str:
    headers = {
        (k.decode("latin-1").lower() if isinstance(k, (bytes, bytearray)) else str(k).lower()):
        (v.decode("latin-1") if isinstance(v, (bytes, bytearray)) else str(v))
        for k, v in (scope.get("headers") or [])
    }
    xff = (headers.get("x-forwarded-for") or "").strip()
    if xff:
        return xff.split(",", 1)[0].strip()
    xreal = (headers.get("x-real-ip") or "").strip()
    if xreal:
        return xreal
    client = scope.get("client") or ()
    if isinstance(client, tuple) and client:
        return str(client[0] or "")
    return ""


def suspicious_request_reason(request: Request) -> str | None:
    target = f"{request.url.path}?{request.url.query}".strip("?")
    for pattern in SUSPICIOUS_REQUEST_PATTERNS:
        if pattern.search(target):
            return pattern.pattern
    return None


def log_security_event(
    request: Request,
    event_type: str,
    *,
    severity: str = "medium",
    username: str = "",
    details: str = "",
) -> None:
    try:
        with closing(db_conn()) as conn:
            conn.execute(
                """
                INSERT INTO security_events(
                    created_at, event_type, severity, ip_address, username,
                    method, path, query_string, user_agent, details
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    datetime.now(UTC).isoformat(),
                    event_type,
                    severity,
                    request_ip(request)[:128],
                    (username or "")[:128],
                    request.method[:16],
                    request.url.path[:512],
                    request.url.query[:2000],
                    (request.headers.get("user-agent") or "")[:512],
                    (details or "")[:2000],
                ),
            )
            conn.commit()
    except Exception:
        # Never block call handling for logging issues.
        pass


def log_bruteforce_if_needed(request: Request) -> None:
    ip = request_ip(request)
    if not ip:
        return
    try:
        with closing(db_conn()) as conn:
            rows = conn.execute(
                """
                SELECT created_at FROM security_events
                WHERE event_type = 'login_failed' AND ip_address = ?
                ORDER BY id DESC
                LIMIT 30
                """,
                (ip,),
            ).fetchall()
        recent = 0
        threshold = datetime.now(UTC) - timedelta(minutes=10)
        for row in rows:
            try:
                ts = datetime.fromisoformat(row["created_at"])
            except Exception:
                continue
            if ts >= threshold:
                recent += 1
        if recent >= 8:
            log_security_event(
                request,
                "possible_bruteforce",
                severity="high",
                details=f"Failed login attempts from IP in 10m: {recent}",
            )
            maybe_block_request_ip_for_event(
                request,
                event_type="possible_bruteforce",
                threshold=3,
                window_minutes=15,
                reason_prefix="Repeated failed login activity",
            )
    except Exception:
        pass


def log_system_security_event(
    event_type: str,
    *,
    severity: str = "medium",
    ip_address: str = "",
    details: str = "",
) -> None:
    try:
        with closing(db_conn()) as conn:
            conn.execute(
                """
                INSERT INTO security_events(
                    created_at, event_type, severity, ip_address, username,
                    method, path, query_string, user_agent, details
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    datetime.now(UTC).isoformat(),
                    event_type,
                    severity,
                    (ip_address or "")[:128],
                    "",
                    "SYSTEM",
                    "/security/autoblock",
                    "",
                    "cc-portal-autoblock",
                    (details or "")[:2000],
                ),
            )
            conn.commit()
    except Exception:
        pass


def normalize_ipv4(ip_raw: str) -> str:
    try:
        return str(ipaddress.ip_address((ip_raw or "").strip()))
    except ValueError:
        return ""


def is_public_ipv4(ip_raw: str) -> bool:
    ip_text = normalize_ipv4(ip_raw)
    if not ip_text:
        return False
    ip_obj = ipaddress.ip_address(ip_text)
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
    )


def iptables_block_ip(ip_text: str) -> bool:
    try:
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip_text, "-j", "DROP"],
            capture_output=True,
            text=True,
        )
        if check.returncode == 0:
            return True
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_text, "-j", "DROP"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except Exception:
        return False


def iptables_unblock_ip(ip_text: str) -> bool:
    removed = False
    try:
        while True:
            check = subprocess.run(
                ["sudo", "iptables", "-C", "INPUT", "-s", ip_text, "-j", "DROP"],
                capture_output=True,
                text=True,
            )
            if check.returncode != 0:
                break
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip_text, "-j", "DROP"],
                check=True,
                capture_output=True,
                text=True,
            )
            removed = True
    except Exception:
        return False
    return removed


def active_whitelist_ips() -> set[str]:
    try:
        with closing(db_conn()) as conn:
            rows = conn.execute("SELECT ip_address FROM whitelist_ips WHERE active = 1").fetchall()
    except Exception:
        return set()
    out: set[str] = set()
    for row in rows:
        ip_text = normalize_ipv4(row["ip_address"] or "")
        if ip_text:
            out.add(ip_text)
    return out


def is_ip_whitelisted(ip_text: str) -> bool:
    return normalize_ipv4(ip_text) in active_whitelist_ips()


def security_redirect_url(return_to: str, message: str) -> str:
    target = (return_to or "security").strip().lower()
    encoded = quote_plus(message or "")
    if target == "dashboard":
        return f"/dashboard?security_message={encoded}" if encoded else "/dashboard"
    return f"/security?message={encoded}" if encoded else "/security"


def mark_ip_blocked(ip_text: str, reason: str, source_event: str, last_seen_at: str) -> None:
    now = datetime.now(UTC).isoformat()
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT block_count FROM blocked_ips WHERE ip_address = ?", (ip_text,)).fetchone()
        if row is None:
            conn.execute(
                """
                INSERT INTO blocked_ips(
                    ip_address, reason, source_event_type, block_count,
                    first_blocked_at, last_blocked_at, last_seen_at, active, unblocked_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (ip_text, reason, source_event, 1, now, now, last_seen_at, 1, ""),
            )
        else:
            conn.execute(
                """
                UPDATE blocked_ips
                SET reason = ?, source_event_type = ?, block_count = COALESCE(block_count, 0) + 1,
                    last_blocked_at = ?, last_seen_at = ?, active = 1, unblocked_at = ''
                WHERE ip_address = ?
                """,
                (reason, source_event, now, last_seen_at, ip_text),
            )
        conn.commit()


def maybe_autoblock_ip(
    ip_text: str,
    *,
    source_event: str,
    reason: str,
    last_seen_at: str | None = None,
) -> bool:
    normalized = normalize_ipv4(ip_text)
    if not is_public_ipv4(normalized):
        return False
    if is_ip_whitelisted(normalized):
        log_system_security_event(
            "ip_block_skipped_whitelist",
            severity="info",
            ip_address=normalized,
            details=f"Skipped block for whitelisted IP (source={source_event})",
        )
        return False
    if not iptables_block_ip(normalized):
        return False
    mark_ip_blocked(normalized, reason, source_event, last_seen_at or datetime.now(UTC).isoformat())
    log_system_security_event(
        "ip_auto_blocked",
        severity="high",
        ip_address=normalized,
        details=reason,
    )
    return True


def maybe_block_request_ip_for_event(
    request: Request,
    *,
    event_type: str,
    threshold: int = SENSITIVE_ACTION_BLOCK_THRESHOLD,
    window_minutes: int = SENSITIVE_ACTION_BLOCK_WINDOW_MINUTES,
    reason_prefix: str = "Repeated unauthorized action",
) -> None:
    ip_text = normalize_ipv4(request_ip(request))
    if not is_public_ipv4(ip_text):
        return
    cutoff = (datetime.now(UTC) - timedelta(minutes=max(1, window_minutes))).isoformat()
    try:
        with closing(db_conn()) as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS hit_count, MAX(created_at) AS last_seen
                FROM security_events
                WHERE event_type = ? AND ip_address = ? AND created_at >= ?
                """,
                (event_type, ip_text, cutoff),
            ).fetchone()
        hit_count = int((row["hit_count"] if row else 0) or 0)
        if hit_count < max(2, threshold):
            return
        maybe_autoblock_ip(
            ip_text,
            source_event=event_type,
            reason=f"{reason_prefix}: {hit_count} events in {window_minutes}m",
            last_seen_at=(row["last_seen"] if row else None) or datetime.now(UTC).isoformat(),
        )
    except Exception:
        return


def parse_proxy_host_for_acl(proxy: str) -> str:
    raw = (proxy or "").strip()
    if not raw:
        return ""
    no_scheme = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", "", raw).lstrip("/")
    if "@" in no_scheme:
        no_scheme = no_scheme.split("@", 1)[1]
    if no_scheme.startswith("[") and "]" in no_scheme:
        return no_scheme[1 : no_scheme.index("]")]
    if ":" in no_scheme:
        return no_scheme.split(":", 1)[0]
    return no_scheme


def trusted_trunk_ips() -> set[str]:
    ips: set[str] = set()
    try:
        with closing(db_conn()) as conn:
            rows = conn.execute(
                """
                SELECT proxy, ip_address
                FROM trunks
                WHERE enabled = 1
                """
            ).fetchall()
        for row in rows:
            proxy_host = parse_proxy_host_for_acl(str(row["proxy"] or ""))
            proxy_ip = normalize_ipv4(proxy_host)
            if proxy_ip:
                ips.add(proxy_ip)
            fixed_ip = normalize_ipv4(str(row["ip_address"] or ""))
            if fixed_ip:
                ips.add(fixed_ip)
    except Exception:
        pass
    return ips


def load_last_sip_scan_offset(file_path: Path) -> int:
    try:
        return int(file_path.read_text(encoding="utf-8").strip() or "0")
    except Exception:
        return -1


def save_last_sip_scan_offset(file_path: Path, offset: int) -> None:
    try:
        file_path.write_text(str(max(0, int(offset))), encoding="utf-8")
    except Exception:
        return


def log_and_block_sip_invite_probes() -> None:
    if not SIP_INVITE_PROBE_ENABLED:
        return
    if not FREESWITCH_LOG_FILE.exists():
        return
    try:
        size = FREESWITCH_LOG_FILE.stat().st_size
    except Exception:
        return
    if size <= 0:
        return
    offset = load_last_sip_scan_offset(SIP_INVITE_SCAN_OFFSET_FILE)
    if offset < 0 or offset > size:
        offset = max(0, size - SIP_INVITE_SCAN_TAIL_BYTES)
    trusted_ips = trusted_trunk_ips()
    whitelisted_ips = active_whitelist_ips()
    try:
        with FREESWITCH_LOG_FILE.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
    except Exception:
        return
    save_last_sip_scan_offset(SIP_INVITE_SCAN_OFFSET_FILE, size)
    if not chunk:
        return
    text = chunk.decode("utf-8", errors="ignore")
    hit_counts: dict[str, int] = {}
    last_target: dict[str, str] = {}
    for line in text.splitlines():
        match = SIP_INVITE_PROBE_RE.search(line)
        if not match:
            continue
        target = (match.group(1) or "").strip()
        ip_text = normalize_ipv4(match.group(2) or "")
        if not is_public_ipv4(ip_text):
            continue
        if ip_text in whitelisted_ips:
            continue
        if ip_text in trusted_ips:
            continue
        hit_counts[ip_text] = hit_counts.get(ip_text, 0) + 1
        if ip_text not in last_target:
            last_target[ip_text] = target
    for ip_text, hits in hit_counts.items():
        target = last_target.get(ip_text, "")
        details = f"SIP invite probe to internal target '{target}' ({hits} hit(s) since last scan)"
        for _ in range(max(1, hits)):
            log_system_security_event(
                "sip_invite_probe",
                severity="high",
                ip_address=ip_text,
                details=details,
            )
        if hits >= max(1, AUTO_BLOCK_MIN_EVENTS):
            maybe_autoblock_ip(
                ip_text,
                source_event="sip_invite_probe",
                reason=f"Auto-block SIP invite probe: {hits} hits since last scan (target {target or 'internal'})",
                last_seen_at=datetime.now(UTC).isoformat(),
            )


def security_autoblock_tick() -> None:
    log_and_block_sip_invite_probes()
    whitelisted_ips = active_whitelist_ips()
    # Re-apply active DB blocks in case firewall restarted.
    with closing(db_conn()) as conn:
        active_rows = conn.execute(
            "SELECT ip_address FROM blocked_ips WHERE active = 1 ORDER BY id DESC LIMIT 2000"
        ).fetchall()
    auto_unblocked_for_whitelist: list[str] = []
    for row in active_rows:
        ip_text = normalize_ipv4(row["ip_address"] or "")
        if not is_public_ipv4(ip_text):
            continue
        if ip_text in whitelisted_ips:
            iptables_unblock_ip(ip_text)
            auto_unblocked_for_whitelist.append(ip_text)
            continue
        iptables_block_ip(ip_text)
    if auto_unblocked_for_whitelist:
        now = datetime.now(UTC).isoformat()
        with closing(db_conn()) as conn:
            for ip_text in auto_unblocked_for_whitelist:
                conn.execute(
                    """
                    UPDATE blocked_ips
                    SET active = 0, unblocked_at = ?, reason = ?
                    WHERE ip_address = ? AND active = 1
                    """,
                    (now, "Auto-unblocked because IP is whitelisted", ip_text),
                )
            conn.commit()

    lookback = (datetime.now(UTC) - timedelta(minutes=AUTO_BLOCK_LOOKBACK_MINUTES)).isoformat()
    placeholders = ",".join("?" for _ in AUTO_BLOCK_EVENT_TYPES)
    sql = (
        f"SELECT ip_address, COUNT(*) AS hit_count, MAX(created_at) AS last_seen "
        f"FROM security_events "
        f"WHERE event_type IN ({placeholders}) AND created_at >= ? "
        f"GROUP BY ip_address HAVING COUNT(*) >= ?"
    )
    params: list[Any] = [*AUTO_BLOCK_EVENT_TYPES, lookback, AUTO_BLOCK_MIN_EVENTS]
    with closing(db_conn()) as conn:
        rows = conn.execute(sql, params).fetchall()

    for row in rows:
        ip_text = normalize_ipv4(row["ip_address"] or "")
        if not is_public_ipv4(ip_text):
            continue
        reason = f"Auto-block scanner/probe: {row['hit_count']} events in {AUTO_BLOCK_LOOKBACK_MINUTES}m"
        maybe_autoblock_ip(
            ip_text,
            source_event="scanner_probe",
            reason=reason,
            last_seen_at=row["last_seen"] or datetime.now(UTC).isoformat(),
        )


def security_autoblock_loop() -> None:
    # First pass immediately after startup.
    try:
        security_autoblock_tick()
    except Exception:
        pass
    while not security_autoblock_stop.wait(AUTO_BLOCK_INTERVAL_SECONDS):
        try:
            security_autoblock_tick()
        except Exception:
            pass


def start_security_autoblock_worker() -> None:
    global security_autoblock_thread
    if not AUTO_BLOCK_ENABLED:
        return
    if security_autoblock_thread and security_autoblock_thread.is_alive():
        return
    security_autoblock_stop.clear()
    security_autoblock_thread = threading.Thread(
        target=security_autoblock_loop,
        name="cc-portal-security-autoblock",
        daemon=True,
    )
    security_autoblock_thread.start()


def hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return digest.hex()


def init_db() -> None:
    with closing(db_conn()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS queues (
                number TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                strategy TEXT NOT NULL,
                max_wait_seconds INTEGER NOT NULL,
                max_queue_size INTEGER NOT NULL,
                wrap_up_seconds INTEGER NOT NULL,
                greeting_file TEXT,
                hold_music TEXT NOT NULL,
                overflow_queues TEXT NOT NULL,
                voicemail_box TEXT,
                record_calls INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                extension TEXT NOT NULL,
                skills TEXT NOT NULL,
                languages TEXT NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_queue_memberships (
                agent_id TEXT NOT NULL,
                queue_number TEXT NOT NULL,
                PRIMARY KEY (agent_id, queue_number)
            );

            CREATE TABLE IF NOT EXISTS fax_routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                direction TEXT NOT NULL,
                did TEXT,
                destination_number TEXT,
                email TEXT,
                gateway TEXT,
                file_path TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                send_status TEXT NOT NULL DEFAULT 'pending',
                failure_reason TEXT NOT NULL DEFAULT '',
                last_result TEXT NOT NULL DEFAULT '',
                last_attempt_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS conferences (
                room_number TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                pin TEXT,
                moderator_pin TEXT,
                max_members INTEGER NOT NULL DEFAULT 50,
                record INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                profile_mode TEXT NOT NULL DEFAULT 'open',
                dtmf_profile TEXT NOT NULL DEFAULT 'default',
                muted_on_entry INTEGER NOT NULL DEFAULT 0,
                entry_tone TEXT NOT NULL DEFAULT '',
                exit_tone TEXT NOT NULL DEFAULT '',
                sample_rate INTEGER NOT NULL DEFAULT 48000,
                energy_level INTEGER NOT NULL DEFAULT 20,
                auto_outcall_numbers TEXT NOT NULL DEFAULT '',
                auto_outcall_trunk TEXT NOT NULL DEFAULT '',
                video_layout TEXT NOT NULL DEFAULT 'speaker'
            );

            CREATE TABLE IF NOT EXISTS vpbx_extensions (
                extension TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                sip_password TEXT NOT NULL,
                voicemail_enabled INTEGER NOT NULL DEFAULT 1,
                context TEXT NOT NULL DEFAULT 'default',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                extension TEXT NOT NULL,
                auth_username TEXT NOT NULL,
                auth_password TEXT NOT NULL,
                user_agent TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                mac_address TEXT NOT NULL DEFAULT '',
                provision_vendor TEXT NOT NULL DEFAULT 'yealink',
                provision_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trunks (
                name TEXT PRIMARY KEY,
                proxy TEXT NOT NULL,
                ip_address TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                realm TEXT,
                from_domain TEXT,
                direction TEXT NOT NULL DEFAULT 'both',
                in_prefix TEXT NOT NULL DEFAULT '',
                inbound_did_pattern TEXT NOT NULL DEFAULT '',
                inbound_match_mode TEXT NOT NULL DEFAULT 'exact',
                dialout_pattern TEXT NOT NULL DEFAULT '',
                outbound_match_mode TEXT NOT NULL DEFAULT 'prefix',
                outbound_prefix TEXT NOT NULL DEFAULT '',
                e164_send_plus INTEGER NOT NULL DEFAULT 0,
                register_enabled INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS inbound_routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                did_pattern TEXT NOT NULL,
                match_mode TEXT NOT NULL DEFAULT 'exact',
                inbound_trunk_name TEXT NOT NULL DEFAULT '',
                destination_type TEXT NOT NULL,
                destination_value TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbound_routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                dial_pattern TEXT NOT NULL,
                match_mode TEXT NOT NULL DEFAULT 'prefix',
                trunk_name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                query_string TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL DEFAULT '',
                source_event_type TEXT NOT NULL DEFAULT '',
                block_count INTEGER NOT NULL DEFAULT 0,
                first_blocked_at TEXT NOT NULL,
                last_blocked_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                unblocked_at TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS whitelist_ips (
                ip_address TEXT PRIMARY KEY,
                note TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
            """
        )

        # Lightweight migrations for queue workflow fields.
        queue_cols = {row["name"] for row in conn.execute("PRAGMA table_info(queues)").fetchall()}
        if "inbound_numbers" not in queue_cols:
            conn.execute("ALTER TABLE queues ADD COLUMN inbound_numbers TEXT NOT NULL DEFAULT ''")
        if "dial_targets" not in queue_cols:
            conn.execute("ALTER TABLE queues ADD COLUMN dial_targets TEXT NOT NULL DEFAULT ''")
        if "ring_mode" not in queue_cols:
            conn.execute("ALTER TABLE queues ADD COLUMN ring_mode TEXT NOT NULL DEFAULT 'blast'")
        if "max_rollovers" not in queue_cols:
            conn.execute("ALTER TABLE queues ADD COLUMN max_rollovers INTEGER NOT NULL DEFAULT 3")
        if "announce_position" not in queue_cols:
            conn.execute("ALTER TABLE queues ADD COLUMN announce_position INTEGER NOT NULL DEFAULT 1")
        if "voicemail_escape_digit" not in queue_cols:
            conn.execute("ALTER TABLE queues ADD COLUMN voicemail_escape_digit TEXT NOT NULL DEFAULT '9'")
        if "rollover_count" not in queue_cols:
            conn.execute("ALTER TABLE queues ADD COLUMN rollover_count INTEGER NOT NULL DEFAULT 0")

        device_cols = {row["name"] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "mac_address" not in device_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN mac_address TEXT NOT NULL DEFAULT ''")
        if "provision_vendor" not in device_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN provision_vendor TEXT NOT NULL DEFAULT 'yealink'")
        if "provision_enabled" not in device_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN provision_enabled INTEGER NOT NULL DEFAULT 1")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac_unique "
            "ON devices(mac_address) WHERE mac_address != ''"
        )
        trunk_cols = {row["name"] for row in conn.execute("PRAGMA table_info(trunks)").fetchall()}
        if "ip_address" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''")
        if "direction" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN direction TEXT NOT NULL DEFAULT 'both'")
        if "outbound_prefix" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN outbound_prefix TEXT NOT NULL DEFAULT ''")
        if "e164_send_plus" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN e164_send_plus INTEGER NOT NULL DEFAULT 0")
        if "in_prefix" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN in_prefix TEXT NOT NULL DEFAULT ''")
        if "inbound_did_pattern" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN inbound_did_pattern TEXT NOT NULL DEFAULT ''")
        if "inbound_match_mode" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN inbound_match_mode TEXT NOT NULL DEFAULT 'exact'")
        if "dialout_pattern" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN dialout_pattern TEXT NOT NULL DEFAULT ''")
        if "outbound_match_mode" not in trunk_cols:
            conn.execute("ALTER TABLE trunks ADD COLUMN outbound_match_mode TEXT NOT NULL DEFAULT 'prefix'")
        inbound_route_cols = {row["name"] for row in conn.execute("PRAGMA table_info(inbound_routes)").fetchall()}
        if "inbound_trunk_name" not in inbound_route_cols:
            conn.execute("ALTER TABLE inbound_routes ADD COLUMN inbound_trunk_name TEXT NOT NULL DEFAULT ''")
        fax_cols = {row["name"] for row in conn.execute("PRAGMA table_info(fax_routes)").fetchall()}
        if "send_status" not in fax_cols:
            conn.execute("ALTER TABLE fax_routes ADD COLUMN send_status TEXT NOT NULL DEFAULT 'pending'")
        if "failure_reason" not in fax_cols:
            conn.execute("ALTER TABLE fax_routes ADD COLUMN failure_reason TEXT NOT NULL DEFAULT ''")
        if "last_result" not in fax_cols:
            conn.execute("ALTER TABLE fax_routes ADD COLUMN last_result TEXT NOT NULL DEFAULT ''")
        if "last_attempt_at" not in fax_cols:
            conn.execute("ALTER TABLE fax_routes ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''")
        conference_cols = {row["name"] for row in conn.execute("PRAGMA table_info(conferences)").fetchall()}
        if "profile_mode" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN profile_mode TEXT NOT NULL DEFAULT 'open'")
        if "dtmf_profile" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN dtmf_profile TEXT NOT NULL DEFAULT 'default'")
        if "muted_on_entry" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN muted_on_entry INTEGER NOT NULL DEFAULT 0")
        if "entry_tone" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN entry_tone TEXT NOT NULL DEFAULT ''")
        if "exit_tone" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN exit_tone TEXT NOT NULL DEFAULT ''")
        if "sample_rate" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN sample_rate INTEGER NOT NULL DEFAULT 48000")
        if "energy_level" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN energy_level INTEGER NOT NULL DEFAULT 20")
        if "auto_outcall_numbers" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN auto_outcall_numbers TEXT NOT NULL DEFAULT ''")
        if "auto_outcall_trunk" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN auto_outcall_trunk TEXT NOT NULL DEFAULT ''")
        if "video_layout" not in conference_cols:
            conn.execute("ALTER TABLE conferences ADD COLUMN video_layout TEXT NOT NULL DEFAULT 'speaker'")
        whitelist_cols = {row["name"] for row in conn.execute("PRAGMA table_info(whitelist_ips)").fetchall()}
        if whitelist_cols and "created_by" not in whitelist_cols:
            conn.execute("ALTER TABLE whitelist_ips ADD COLUMN created_by TEXT NOT NULL DEFAULT ''")
        if whitelist_cols and "active" not in whitelist_cols:
            conn.execute("ALTER TABLE whitelist_ips ADD COLUMN active INTEGER NOT NULL DEFAULT 1")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_ips_active ON whitelist_ips(active)")

        existing = conn.execute("SELECT username FROM users WHERE username = ?", (DEFAULT_ADMIN_USER,)).fetchone()
        if existing is None:
            salt = secrets.token_hex(16)
            pw_hash = hash_password(DEFAULT_ADMIN_PASSWORD, salt)
            now = datetime.now(UTC).isoformat()
            conn.execute(
                "INSERT INTO users(username, salt, password_hash, created_at, updated_at) VALUES(?,?,?,?,?)",
                (DEFAULT_ADMIN_USER, salt, pw_hash, now, now),
            )
        # Remove stale membership rows that reference missing agents/queues.
        conn.execute(
            "DELETE FROM agent_queue_memberships "
            "WHERE agent_id NOT IN (SELECT agent_id FROM agents)"
        )
        conn.execute(
            "DELETE FROM agent_queue_memberships "
            "WHERE queue_number NOT IN (SELECT number FROM queues)"
        )
        conn.commit()


def load_platform() -> None:
    global platform
    p = ContactCenterPlatform()

    with closing(db_conn()) as conn:
        for row in conn.execute("SELECT * FROM queues ORDER BY number"):
            ring_mode = (row["ring_mode"] or "blast").strip().lower()
            strategy = RoutingStrategy.SIMULTANEOUS if ring_mode == "blast" else RoutingStrategy.SEQUENTIAL
            overflow = [x for x in (row["overflow_queues"] or "").split(",") if x][:3]
            p.configure_queue(
                QueueConfig(
                    name=row["name"],
                    number=row["number"],
                    strategy=strategy,
                    max_wait_seconds=row["max_wait_seconds"] or 300,
                    max_queue_size=row["max_queue_size"],
                    wrap_up_seconds=row["wrap_up_seconds"],
                    greeting_file=row["greeting_file"],
                    hold_music=row["hold_music"],
                    overflow_queues=overflow,
                    voicemail_box=row["voicemail_box"],
                    record_calls=bool(row["record_calls"]),
                )
            )

        for row in conn.execute("SELECT * FROM agents ORDER BY agent_id"):
            agent = Agent(
                agent_id=row["agent_id"],
                extension=row["extension"],
                skills={x for x in row["skills"].split(",") if x},
                languages={x for x in row["languages"].split(",") if x},
            )
            p.configure_agent(agent)

        for row in conn.execute("SELECT * FROM agent_queue_memberships"):
            if row["agent_id"] in p.engine.agents and row["queue_number"] in p.engine.queues:
                p.add_agent_to_queue(row["queue_number"], row["agent_id"])

    platform = p


def build_queue_rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        chain = [x.strip() for x in (item.get("overflow_queues") or "").split(",") if x.strip()]
        count = int(item.get("rollover_count") or len(chain) or 0)
        count = max(0, min(count, 3))
        chain = chain[:count]
        vm = item.get("voicemail_box") or "voicemail"
        item["queue_flow"] = " -> ".join([item.get("number", "?"), *chain, f"VM:{vm}"])
        item["rollover_count_effective"] = len(chain)
        out.append(item)
    return out


def normalize_inbound_line(value: str) -> str:
    # Keep DIDs stable for matching even when users type + or spaces.
    cleaned = re.sub(r"\s+", "", (value or "").strip())
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    return cleaned


def parse_inbound_lines(raw_csv: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for token in (raw_csv or "").replace(";", ",").split(","):
        normalized = normalize_inbound_line(token)
        if not normalized:
            continue
        key = normalized.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def parse_csv_values(raw_csv: str) -> list[str]:
    return [x.strip() for x in (raw_csv or "").replace(";", ",").split(",") if x.strip()]


def dial_target_agent_lookup_key(token: str) -> str | None:
    value = token.strip()
    if not value:
        return None
    lower_value = value.casefold()
    if lower_value.startswith("agent:"):
        candidate = value.split(":", 1)[1].strip()
        return candidate.casefold() if candidate else None
    if value.isdigit():
        return None
    if any(ch in value for ch in ("/", "@", "{", "}", "[", "]", "(", ")", " ")):
        return None
    return value.casefold()


def build_inbound_assignment_rows(rows: list[sqlite3.Row]) -> list[dict[str, str]]:
    assignments: list[dict[str, str]] = []
    for row in rows:
        for line in parse_inbound_lines(row["inbound_numbers"] or ""):
            assignments.append(
                {
                    "line": line,
                    "queue_number": row["number"],
                    "queue_name": row["name"],
                }
            )
    assignments.sort(key=lambda item: item["line"])
    return assignments


def normalize_mac_address(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", (value or "").strip())
    if len(compact) != 12:
        return ""
    return compact.upper()


def formatted_mac_address(value: str) -> str:
    mac = normalize_mac_address(value)
    if not mac:
        return ""
    return ":".join(mac[i : i + 2] for i in range(0, 12, 2))


def request_public_base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


def infer_sip_server(request: Request) -> str:
    if PROVISION_SIP_SERVER:
        return PROVISION_SIP_SERVER
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return host.split(":", 1)[0]


def registered_users_from_snapshot(reg_text: str) -> set[str]:
    users: set[str] = set()
    for match in re.findall(r"\b([A-Za-z0-9._-]+)@[A-Za-z0-9._-]+\b", reg_text or ""):
        users.add(match.casefold())
    return users


def build_device_rows(request: Request, rows: list[sqlite3.Row], reg_text: str = "") -> list[dict[str, Any]]:
    base_url = request_public_base_url(request)
    registered_users = registered_users_from_snapshot(reg_text)
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        mac = normalize_mac_address(item.get("mac_address") or "")
        item["mac_address_normalized"] = mac
        item["mac_address_display"] = formatted_mac_address(mac) if mac else "-"
        item["provision_url"] = f"{base_url}/provision/{mac}.cfg" if mac else ""
        auth_user = str(item.get("auth_username") or "").strip().casefold()
        extension = str(item.get("extension") or "").strip().casefold()
        is_enabled = bool(item.get("enabled")) and bool(item.get("provision_enabled"))
        if not is_enabled:
            item["registration_label"] = "Disabled"
            item["registration_class"] = "reg-disabled"
        else:
            is_registered = auth_user in registered_users or extension in registered_users
            item["registration_label"] = "Registered" if is_registered else "Not Registered"
            item["registration_class"] = "reg-on" if is_registered else "reg-off"
        out.append(item)
    return out


def render_yealink_provision_cfg(device: sqlite3.Row, ext_row: sqlite3.Row | None, request: Request) -> str:
    display_name = (
        str((ext_row["display_name"] if ext_row else "") or "").strip()
        or str(device["device_id"] or "").strip()
        or str(device["extension"] or "").strip()
    )
    username = str(device["auth_username"] or "").strip()
    password = str(device["auth_password"] or "").strip()
    extension = str(device["extension"] or "").strip()
    sip_server = infer_sip_server(request)
    transport = (PROVISION_SIP_TRANSPORT or "udp").strip().lower()
    transport_value = {"udp": "0", "tcp": "1", "tls": "2"}.get(transport, "0")
    cfg = textwrap.dedent(
        f"""\
        #!version:1.0.0.1
        account.1.enable = 1
        account.1.label = {display_name}
        account.1.display_name = {display_name}
        account.1.user_name = {username}
        account.1.auth_name = {username}
        account.1.password = {password}
        account.1.register_name = {username}
        account.1.sip_server.1.address = {sip_server}
        account.1.sip_server.1.port = {PROVISION_SIP_PORT}
        account.1.transport = {transport_value}
        account.1.voice_mail.number = *97
        phone_setting.time_format = 1
        features.enhanced_dnd.enable = 1
        linekey.1.type = 15
        linekey.1.line = 1
        linekey.1.value = {extension}
        linekey.1.label = {display_name}
        """
    ).strip()
    return cfg + "\n"


def generate_alnum_password(length: int = 12) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(ch.isalpha() for ch in candidate) and any(ch.isdigit() for ch in candidate):
            return candidate


def normalize_match_mode(mode: str, *, outbound: bool = False) -> str:
    allowed = {"exact", "prefix", "regex"}
    default_mode = "prefix" if outbound else "exact"
    value = (mode or "").strip().lower()
    return value if value in allowed else default_mode


def normalize_trunk_direction(value: str) -> str:
    mode = (value or "").strip().lower()
    if mode == "in":
        return "inbound"
    if mode == "out":
        return "outbound"
    if mode in {"inbound", "outbound", "both"}:
        return mode
    return "both"


def number_match_expression(pattern: str, match_mode: str) -> str:
    raw = (pattern or "").strip()
    if not raw:
        return r"^$"
    mode = normalize_match_mode(match_mode)
    if mode == "regex":
        return raw
    if mode == "prefix":
        return f"^{re.escape(raw)}.*$"
    return f"^{re.escape(raw)}$"


def outbound_match_expression_and_target(pattern: str, match_mode: str) -> tuple[str, str]:
    raw = (pattern or "").strip()
    mode = normalize_match_mode(match_mode, outbound=True)
    if mode == "regex":
        return (raw or r"^$", "${destination_number}")
    if mode == "exact":
        return (f"^{re.escape(raw)}$", "${destination_number}")
    return (f"^{re.escape(raw)}\\d+$", f"${{destination_number:{len(raw)}}}")


def as_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def sanitize_conference_pin(value: str) -> str:
    pin = re.sub(r"\D+", "", (value or "").strip())
    if len(pin) < 2 or len(pin) > 12:
        return ""
    return pin


def sanitize_conference_mode(value: str) -> str:
    mode = (value or "").strip().lower()
    if mode in {"restricted", "webinar", "madboss"}:
        return mode
    return "open"


def sanitize_conference_sample_rate(value: int | str | None) -> int:
    try:
        rate = int(value or 48000)
    except (TypeError, ValueError):
        rate = 48000
    if rate in {8000, 16000, 32000, 48000}:
        return rate
    return 48000


def sanitize_conference_energy_level(value: int | str | None) -> int:
    try:
        level = int(value or 20)
    except (TypeError, ValueError):
        level = 20
    return max(0, min(level, 180))


def parse_outcall_numbers(raw_csv: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for token in (raw_csv or "").replace(";", ",").split(","):
        normalized = re.sub(r"\s+", "", token or "")
        normalized = re.sub(r"[^0-9+*#]", "", normalized)
        if not normalized or not re.search(r"\d", normalized):
            continue
        key = normalized.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def build_conference_app_data(room: str, pin: str | None, flags: list[str] | None = None) -> str:
    clean_flags = [flag.strip() for flag in (flags or []) if flag.strip()]
    room_profile = f"{room}@default"
    safe_pin = sanitize_conference_pin(pin or "")
    if safe_pin and clean_flags:
        return f"{room_profile}+{safe_pin}+flags{{{','.join(clean_flags)}}}"
    if safe_pin:
        return f"{room_profile}+{safe_pin}"
    if clean_flags:
        return f"{room_profile}++flags{{{','.join(clean_flags)}}}"
    return room_profile


def require_user(request: Request) -> str | None:
    return request.session.get("user")


def is_admin_user(user: str | None) -> bool:
    return (user or "").strip() == DEFAULT_ADMIN_USER


def redirect_login() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=303)


def redirect_settings() -> RedirectResponse:
    return RedirectResponse(url="/settings", status_code=303)


def require_admin_or_redirect(request: Request) -> tuple[str | None, RedirectResponse | None]:
    user = require_user(request)
    if not user:
        log_security_event(request, "admin_access_no_session", severity="medium")
        return None, redirect_login()
    if not is_admin_user(user):
        log_security_event(
            request,
            "admin_access_denied",
            severity="medium",
            username=user,
            details="Non-admin user attempted admin-only page",
        )
        return None, redirect_settings()
    return user, None


@app.middleware("http")
async def security_monitor_middleware(request: Request, call_next):
    path = request.url.path or ""
    if path.startswith("/static/"):
        return await call_next(request)

    reason = suspicious_request_reason(request)
    if reason:
        log_security_event(
            request,
            "suspicious_request_pattern",
            severity="high",
            details=f"Matched pattern: {reason}",
        )

    try:
        response = await call_next(request)
    except Exception as exc:
        log_security_event(request, "application_exception", severity="high", details=type(exc).__name__)
        raise

    if response.status_code in {401, 403}:
        log_security_event(request, "http_access_denied", severity="medium", details=f"status={response.status_code}")
    elif response.status_code == 404:
        probe_tokens = (".php", "wp-", "phpmyadmin", ".env", "manager/html", "cgi-bin", "boaform")
        lower_target = f"{path}?{request.url.query}".casefold()
        if any(token in lower_target for token in probe_tokens):
            log_security_event(request, "probing_404", severity="high", details="Potential scanner/probe path")
    elif response.status_code >= 500:
        log_security_event(request, "http_server_error", severity="medium", details=f"status={response.status_code}")

    return response


def fs_cli(command: str) -> str:
    try:
        proc = subprocess.run(
            ["sudo", "/usr/local/freeswitch/bin/fs_cli", "-x", command],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            f"fs_cli timeout after {int(exc.timeout or 30)}s. "
            "Command may still be executing in FreeSWITCH."
        )
    output = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if err:
        return f"{output}\n{err}".strip()
    return output


def infer_webrtc_realm() -> str:
    if PROVISION_SIP_SERVER:
        return PROVISION_SIP_SERVER.split(":", 1)[0].strip()
    domain_lines = (fs_cli("global_getvar domain") or "").strip().splitlines()
    if domain_lines:
        candidate = domain_lines[0].strip()
        if re.fullmatch(r"[A-Za-z0-9.-]+", candidate):
            return candidate
    return "204.29.213.58"


def unique_nonempty(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = (item or "").strip()
        if not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def write_root_file(path: str, content: str) -> None:
    subprocess.run(
        ["sudo", "/usr/bin/tee", path],
        input=content,
        text=True,
        capture_output=True,
        check=True,
    )


def root_file_exists(path: str | Path) -> bool:
    probe = subprocess.run(
        ["sudo", "test", "-f", str(path)],
        capture_output=True,
        text=True,
    )
    return probe.returncode == 0


def ensure_fax_runtime() -> None:
    subprocess.run(
        ["sudo", "mkdir", "-p", str(FAX_INBOUND_DIR), str(FAX_OUTBOUND_DIR)],
        capture_output=True,
        text=True,
        check=True,
    )
    converter = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        src="${1:-}"
        if [[ -z "$src" || ! -f "$src" ]]; then
          exit 0
        fi
        case "${src,,}" in
          *.tif|*.tiff) ;;
          *) exit 0 ;;
        esac
        dst="${src%.*}.pdf"
        if command -v tiff2pdf >/dev/null 2>&1; then
          tiff2pdf -o "$dst" "$src" >/dev/null 2>&1
          exit 0
        fi
        if command -v gs >/dev/null 2>&1; then
          gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile="$dst" "$src" >/dev/null 2>&1
          exit 0
        fi
        if command -v convert >/dev/null 2>&1; then
          convert "$src" "$dst" >/dev/null 2>&1
          exit 0
        fi
        exit 1
        """
    )
    write_root_file(FAX_TIFF_TO_PDF_SCRIPT, converter)
    subprocess.run(
        ["sudo", "chmod", "0755", FAX_TIFF_TO_PDF_SCRIPT],
        capture_output=True,
        text=True,
        check=True,
    )


def fax_receive_actions(fax_tag: str) -> list[str]:
    safe_tag = re.sub(r"[^0-9A-Za-z_-]+", "_", (fax_tag or "fax"))
    base = f"{FAX_INBOUND_DIR}/in_${{strftime(%Y%m%d-%H%M%S)}}_{safe_tag}"
    return [
        '<action application="answer"/>',
        '<action application="set" data="fax_enable_t38=true"/>',
        '<action application="set" data="fax_verbose=true"/>',
        f'<action application="set" data="fax_tiff_path={base}.tif"/>',
        '<action application="rxfax" data="${fax_tiff_path}"/>',
        f'<action application="system" data="{FAX_TIFF_TO_PDF_SCRIPT} ${{fax_tiff_path}}"/>',
        '<action application="hangup" data="NORMAL_CLEARING"/>',
    ]


def prepare_outbound_fax_file(file_path: str, fax_id: int) -> str:
    source = Path((file_path or "").strip())
    if not source.is_absolute():
        source = (BASE_DIR / source).resolve()
    if not source.exists() and not root_file_exists(source):
        raise ValueError(f"Fax source file does not exist: {source}")
    if " " in str(source):
        raise ValueError("Fax file path cannot contain spaces.")
    ensure_fax_runtime()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_tiff = FAX_OUTBOUND_DIR / f"fax_out_{fax_id}_{stamp}.tif"
    suffix = source.suffix.lower()
    if suffix in {".tif", ".tiff"}:
        return str(source)

    errors: list[str] = []
    def gs_to_tiff(in_path: Path) -> tuple[bool, str]:
        gs_cmd = [
            "sudo",
            "gs",
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-sDEVICE=tiffg4",
            "-r204x196",
            f"-sOutputFile={out_tiff}",
            str(in_path),
        ]
        gs_try = subprocess.run(gs_cmd, capture_output=True, text=True)
        if gs_try.returncode == 0 and root_file_exists(out_tiff):
            return True, ""
        return False, (gs_try.stderr or gs_try.stdout or "gs conversion failed").strip()

    # Explicitly support PDF -> TIFF conversion.
    if suffix == ".pdf":
        ok, err = gs_to_tiff(source)
        if ok:
            return str(out_tiff)
        errors.append(err)

    # Explicitly support image -> TIFF conversion.
    elif suffix in FAX_IMAGE_EXTENSIONS:
        ffmpeg_cmd = [
            "sudo",
            "ffmpeg",
            "-y",
            "-i",
            str(source),
            "-vf",
            "format=gray",
            str(out_tiff),
        ]
        ffmpeg_try = subprocess.run(ffmpeg_cmd, capture_output=True, text=True)
        if ffmpeg_try.returncode == 0 and root_file_exists(out_tiff):
            return str(out_tiff)
        errors.append((ffmpeg_try.stderr or ffmpeg_try.stdout or "ffmpeg image conversion failed").strip())

    else:
        ok, err = gs_to_tiff(source)
        if ok:
            return str(out_tiff)
        errors.append(err)

    # Office docs and many other types can be converted via LibreOffice to PDF first.
    temp_dir = Path(f"/tmp/callture_fax_convert_{fax_id}_{stamp}")
    subprocess.run(["sudo", "mkdir", "-p", str(temp_dir)], capture_output=True, text=True, check=True)
    soffice_cmd = [
        "sudo",
        "soffice",
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        str(temp_dir),
        str(source),
    ]
    soffice_try = subprocess.run(soffice_cmd, capture_output=True, text=True)
    pdf_candidates = list(temp_dir.glob("*.pdf"))
    if soffice_try.returncode == 0 and pdf_candidates:
        pdf_path = pdf_candidates[0]
        ok, err = gs_to_tiff(pdf_path)
        if ok:
            return str(out_tiff)
        errors.append(err or "gs PDF conversion failed")
    else:
        errors.append((soffice_try.stderr or soffice_try.stdout or "soffice conversion failed").strip())

    # Optional fallback with ImageMagick when available.
    if shutil.which("convert"):
        magick_cmd = ["sudo", "convert", str(source), str(out_tiff)]
        magick_try = subprocess.run(magick_cmd, capture_output=True, text=True)
        if magick_try.returncode == 0 and root_file_exists(out_tiff):
            return str(out_tiff)
        errors.append((magick_try.stderr or magick_try.stdout or "convert failed").strip())

    err_text = " | ".join([e for e in errors if e])[:500]
    raise ValueError(f"Unable to convert source file to TIFF. {err_text}")


def save_uploaded_fax_file(file_upload: UploadFile) -> str:
    raw_name = Path((file_upload.filename or "").strip()).name or "fax_upload.bin"
    safe_name = re.sub(r"[^0-9A-Za-z._-]+", "_", raw_name).strip("._")
    if not safe_name:
        safe_name = "fax_upload.bin"
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    FAX_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = FAX_UPLOAD_DIR / f"{stamp}_{safe_name}"
    file_upload.file.seek(0)
    with dest.open("wb") as out:
        shutil.copyfileobj(file_upload.file, out)
    return str(dest)


def sanitize_outbound_prefix_for_dialing(prefix: str) -> str:
    raw = re.sub(r"\s+", "", (prefix or "").strip())
    # Keep trunk-entered '#' semantics while making it SIP-URI safe.
    return raw.replace("#", "%23")


def apply_outbound_trunk_prefix(number: str, prefix: str) -> str:
    destination = (number or "").strip()
    raw_prefix = re.sub(r"\s+", "", (prefix or "").strip())
    trunk_prefix = sanitize_outbound_prefix_for_dialing(prefix)
    if not trunk_prefix:
        return destination
    if raw_prefix and destination.startswith(raw_prefix):
        return destination
    return destination if destination.startswith(trunk_prefix) else f"{trunk_prefix}{destination}"


def sip_host_from_proxy(proxy: str) -> str:
    raw = (proxy or "").strip()
    if not raw:
        return ""
    no_scheme = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", "", raw).lstrip("/")
    if "@" in no_scheme:
        no_scheme = no_scheme.split("@", 1)[1]
    no_scheme = no_scheme.split(";", 1)[0].split("/", 1)[0].strip()
    if no_scheme.startswith("[") and "]" in no_scheme:
        return no_scheme[1:no_scheme.index("]")]
    if ":" in no_scheme:
        return no_scheme.split(":", 1)[0]
    return no_scheme


def build_fax_bgapi_originate(gateway: str, destination_number: str, fax_file: str, from_host: str) -> str:
    safe_from_host = sip_host_from_proxy(from_host)
    safe_display_name = FAX_FIXED_FROM_NAME.replace("'", "")
    from_uri = f"sip:{FAX_FIXED_FROM_NUMBER}@{safe_from_host}" if safe_from_host else ""
    vars_block = (
        "{ignore_early_media=true,"
        f"origination_caller_id_number={FAX_FIXED_FROM_NUMBER},"
        f"origination_caller_id_name='{safe_display_name}',"
        f"effective_caller_id_number={FAX_FIXED_FROM_NUMBER},"
        f"effective_caller_id_name='{safe_display_name}',"
        f"sip_from_display='{safe_display_name}',"
        f"sip_from_user={FAX_FIXED_FROM_NUMBER},"
        f"sip_contact_user={FAX_FIXED_FROM_NUMBER}"
        "}"
    )
    if safe_from_host:
        vars_block = vars_block[:-1] + f",sip_from_host={safe_from_host}"
        if from_uri:
            vars_block += f",sip_from_uri={from_uri},sip_invite_from_uri={from_uri}"
        vars_block += "}"
    return (
        "bgapi originate "
        + vars_block
        + "sofia/gateway/"
        + gateway
        + "/"
        + destination_number
        + " &txfax("
        + fax_file
        + ")"
    )


def classify_fax_command_result(result: str) -> tuple[str, str]:
    text = (result or "").strip()
    if text and ("+OK" in text or "Job-UUID" in text):
        return "success", ""
    if not text:
        return "failed", "No response from FreeSWITCH."
    return "failed", text[:500]


def update_fax_send_status(
    conn: sqlite3.Connection,
    fax_id: int,
    *,
    status: str,
    reason: str,
    result: str,
) -> None:
    conn.execute(
        """
        UPDATE fax_routes
        SET send_status = ?, failure_reason = ?, last_result = ?, last_attempt_at = ?
        WHERE id = ?
        """,
        (
            status,
            (reason or "")[:500],
            (result or "")[:2000],
            datetime.now(UTC).isoformat(),
            fax_id,
        ),
    )


def fax_page_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    inbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC").fetchall()
    outbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'outbound' ORDER BY id DESC").fetchall()
    trunks = conn.execute(
        """
        SELECT name, proxy, direction
        FROM trunks
        WHERE enabled = 1
          AND direction IN ('outbound', 'both')
        ORDER BY name
        """
    ).fetchall()
    return {
        "inbound": inbound,
        "outbound": outbound,
        "outbound_trunks": trunks,
    }


def conference_page_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    rooms = conn.execute("SELECT * FROM conferences ORDER BY room_number").fetchall()
    outbound_trunks = conn.execute(
        """
        SELECT name, proxy, outbound_prefix
        FROM trunks
        WHERE enabled = 1
          AND LOWER(COALESCE(direction, 'both')) IN ('outbound', 'both')
        ORDER BY name
        """
    ).fetchall()
    live_summary = fs_cli("conference list")
    return {
        "rooms": rooms,
        "outbound_trunks": outbound_trunks,
        "live_summary": live_summary,
    }


def sync_extension_to_freeswitch(extension: str, display_name: str, sip_password: str, context: str) -> None:
    xml = textwrap.dedent(
        f"""\
        <include>
          <user id="{extension}">
            <params>
              <param name="password" value="{sip_password}"/>
              <param name="vm-password" value="{extension}"/>
            </params>
            <variables>
              <variable name="toll_allow" value="domestic,international,local"/>
              <variable name="accountcode" value="{extension}"/>
              <variable name="user_context" value="{context}"/>
              <variable name="effective_caller_id_name" value="{display_name}"/>
              <variable name="effective_caller_id_number" value="{extension}"/>
              <variable name="outbound_caller_id_name" value="$${{outbound_caller_name}}"/>
              <variable name="outbound_caller_id_number" value="$${{outbound_caller_id}}"/>
              <variable name="callgroup" value="techsupport"/>
            </variables>
          </user>
        </include>
        """
    )
    path = f"/usr/local/freeswitch/conf/directory/default/{extension}.xml"
    write_root_file(path, xml)


def sync_fax_inbound_dialplan() -> None:
    ensure_fax_runtime()
    with closing(db_conn()) as conn:
        rows = conn.execute(
            """
            SELECT did FROM fax_routes
            WHERE direction = 'inbound' AND enabled = 1 AND did IS NOT NULL AND did != ''
            ORDER BY did
            """
        ).fetchall()

    blocks: list[str] = []
    for row in rows:
        did = row["did"]
        actions = " ".join(fax_receive_actions(str(did)))
        blocks.append(
            textwrap.dedent(
                f"""\
                  <extension name="fax_in_{did}">
                    <condition field="destination_number" expression="^{did}$">
                      {actions}
                    </condition>
                  </extension>
                """
            )
        )

    xml = "<include>\n" + ("\n".join(blocks) if blocks else "  <!-- no fax inbound routes configured -->\n") + "</include>\n"
    write_root_file("/usr/local/freeswitch/conf/dialplan/public/30_callture_fax_inbound.xml", xml)
    fs_cli("reloadxml")


def sync_conference_dialplan() -> None:
    with closing(db_conn()) as conn:
        rows = conn.execute(
            """
            SELECT
                room_number, pin, moderator_pin, max_members, record, profile_mode,
                dtmf_profile, muted_on_entry, entry_tone, exit_tone, sample_rate, energy_level
            FROM conferences
            WHERE enabled = 1
            ORDER BY room_number
            """
        ).fetchall()

    blocks: list[str] = []
    for row in rows:
        room = (row["room_number"] or "").strip()
        if not room:
            continue
        room_expr = re.escape(room)
        mode = sanitize_conference_mode(str(row["profile_mode"] or "open"))
        muted_default = bool(row["muted_on_entry"]) or mode in {"webinar", "madboss"}
        member_flags: list[str] = []
        if muted_default:
            member_flags.append("mute")
        if mode == "madboss":
            member_flags.append("mintwo")
        conference_data = build_conference_app_data(room, str(row["pin"] or ""), member_flags)
        max_members = max(2, min(int(row["max_members"] or 50), 1000))
        sample_rate = sanitize_conference_sample_rate(row["sample_rate"] or 48000)
        energy_level = sanitize_conference_energy_level(row["energy_level"] or 20)
        dtmf_profile = (row["dtmf_profile"] or "default").strip() or "default"
        entry_tone = (row["entry_tone"] or "").strip()
        exit_tone = (row["exit_tone"] or "").strip()
        pin = sanitize_conference_pin(str(row["pin"] or ""))
        moderator_pin = sanitize_conference_pin(str(row["moderator_pin"] or ""))
        rec_action = ""
        if int(row["record"]) == 1:
            rec_action = (
                '<action application="set" '
                'data="conference_auto_record=/usr/local/freeswitch/recordings/conf_${strftime(%Y%m%d-%H%M%S)}_'
                + room
                + '.wav"/>'
            )
        pin_actions = ""
        if pin:
            pin_actions += f'<action application="set" data="conference_pin={pin}"/>'
        if moderator_pin:
            pin_actions += f'<action application="set" data="conference_moderator_pin={moderator_pin}"/>'
        entry_action = f'<action application="playback" data="{entry_tone}"/>' if entry_tone else ""
        exit_action = f'<action application="playback" data="{exit_tone}"/>' if exit_tone else ""
        blocks.append(
            textwrap.dedent(
                f"""\
                  <extension name="conference_{room}">
                    <condition field="destination_number" expression="^{room_expr}$">
                      <action application="answer"/>
                      <action application="set" data="conference_max_members={max_members}"/>
                      <action application="set" data="conference_rate={sample_rate}"/>
                      <action application="set" data="conference_energy_level={energy_level}"/>
                      <action application="set" data="conference_controls={dtmf_profile}"/>
                      {pin_actions}
                      {entry_action}
                      {rec_action}
                      <action application="conference" data="{conference_data}"/>
                      {exit_action}
                    </condition>
                  </extension>
                """
            )
        )

    xml = "<include>\n" + ("\n".join(blocks) if blocks else "  <!-- no conference rooms configured -->\n") + "</include>\n"
    write_root_file("/usr/local/freeswitch/conf/dialplan/default/96_callture_conference.xml", xml)
    fs_cli("reloadxml")


def sync_webrtc_internal_user_bridge_dialplan() -> None:
    # For authenticated WebRTC users:
    # 1) Browser sends explicit X-Callture-Target-Host SIP header per call.
    # 2) If target host is remote, route out via external profile.
    # 3) If target host is local domain and 10-digit, bridge to local user.
    local_domain = infer_webrtc_realm()
    local_domain_expr = re.escape(local_domain)
    outbound_identity = re.sub(r"\D+", "", WEBRTC_OUTBOUND_IDENTITY_DEFAULT) or WEBRTC_DEFAULT_EXTENSION
    outbound_from_uri = f"sip:{outbound_identity}@{local_domain}"
    outbound_trunk = re.sub(r"[^0-9A-Za-z_.-]", "", REGISTERED_FIRST_OUTBOUND_TRUNK) or "kamailio6932"
    nanp_expr = NANP_10_OR_11_DIGIT_EXPR
    xml = textwrap.dedent(
        f"""\
        <include>
          <extension name="callture_webrtc_remote_uri_bridge">
            <condition field="${{sip_authorized}}" expression="^true$">
              <condition field="${{sip_h_X-Callture-Target-Host}}" expression="^(?!{local_domain_expr}$)[0-9A-Za-z.-]+$">
                <condition field="destination_number" expression="^([0-9]{{7,15}})$">
                  <action application="bridge" data="[origination_caller_id_number={outbound_identity},effective_caller_id_number={outbound_identity},sip_from_user={outbound_identity},sip_contact_user={outbound_identity},sip_from_host={local_domain},sip_from_uri={outbound_from_uri},sip_invite_from_uri={outbound_from_uri}]sofia/external/$1@${{sip_h_X-Callture-Target-Host}}"/>
                </condition>
              </condition>
            </condition>
          </extension>
          <extension name="callture_webrtc_internal_user_bridge">
            <condition field="${{sip_authorized}}" expression="^true$">
              <condition field="${{sip_h_X-Callture-Target-Host}}" expression="^(?:|{local_domain_expr})$">
                <condition field="destination_number" expression="{nanp_expr}">
                  <action application="set" data="callture_target_user=${{regex(${{destination_number}}|^1?([2-9]\\d{{9}})$|$1)}}"/>
                  <action application="set" data="callture_out_target=1${{callture_target_user}}"/>
                  <condition field="${{user_registered(${{callture_target_user}}@$${{domain}})}}" expression="^true$">
                    <action application="bridge" data="user/${{callture_target_user}}@$${{domain}}"/>
                    <anti-action application="set" data="continue_on_fail=true"/>
                    <anti-action application="set" data="hangup_after_bridge=true"/>
                    <anti-action application="bridge" data="sofia/gateway/{outbound_trunk}/${{callture_out_target}}"/>
                  </condition>
                </condition>
                <condition field="destination_number" expression="^(?!1?[2-9]\\d{{9}}$).+">
                  <action application="hangup" data="CALL_REJECTED"/>
                </condition>
              </condition>
            </condition>
          </extension>
        </include>
        """
    )
    write_root_file("/usr/local/freeswitch/conf/dialplan/default/04_callture_webrtc_internal_bridge.xml", xml)
    fs_cli("reloadxml")


def sync_trunks_to_freeswitch() -> None:
    with closing(db_conn()) as conn:
        rows = conn.execute(
            """
            SELECT name, proxy, ip_address, username, password, realm, from_domain, register_enabled, enabled
            FROM trunks
            WHERE enabled = 1
            ORDER BY name
            """
        ).fetchall()

    gateways: list[str] = []
    for row in rows:
        name = (row["name"] or "").strip()
        proxy = (row["proxy"] or "").strip()
        ip_address = (row["ip_address"] or "").strip()
        username = (row["username"] or "").strip()
        password = (row["password"] or "").strip()
        if not name or not proxy:
            continue
        params: list[str] = [
            f'<param name="proxy" value="{proxy}"/>',
            f'<param name="register" value="{"true" if bool(row["register_enabled"]) else "false"}"/>',
        ]
        if ip_address:
            params.append(f'<param name="outbound-proxy" value="{ip_address}"/>')
        if username:
            params.append(f'<param name="username" value="{username}"/>')
        if password:
            params.append(f'<param name="password" value="{password}"/>')
        realm = (row["realm"] or "").strip()
        if realm:
            params.append(f'<param name="realm" value="{realm}"/>')
        from_domain = (row["from_domain"] or "").strip()
        if from_domain:
            params.append(f'<param name="from-domain" value="{from_domain}"/>')
        gateways.append(
            textwrap.dedent(
                f"""\
                  <gateway name="{name}">
                    {' '.join(params)}
                  </gateway>
                """
            )
        )

    xml = "<include>\n" + ("\n".join(gateways) if gateways else "  <!-- no trunks configured -->\n") + "</include>\n"
    write_root_file("/usr/local/freeswitch/conf/sip_profiles/external/99_callture_trunks.xml", xml)
    fs_cli("reloadxml")
    fs_cli("sofia profile external rescan")


def sync_inbound_routes_dialplan() -> None:
    ensure_fax_runtime()
    with closing(db_conn()) as conn:
        rows = conn.execute(
            """
            SELECT
                r.id,
                r.name,
                r.did_pattern,
                r.match_mode,
                r.inbound_trunk_name,
                r.destination_type,
                r.destination_value,
                t.direction AS trunk_direction,
                t.enabled AS trunk_enabled
            FROM inbound_routes r
            LEFT JOIN trunks t ON t.name = r.inbound_trunk_name
            WHERE r.enabled = 1
            ORDER BY r.id
            """
        ).fetchall()

    blocks: list[str] = []
    for row in rows:
        route_id = int(row["id"])
        route_name = (row["name"] or f"route_{route_id}").strip()
        did_pattern = (row["did_pattern"] or "").strip()
        if not did_pattern:
            continue
        expression = number_match_expression(did_pattern, row["match_mode"] or "exact")
        inbound_trunk_name = (row["inbound_trunk_name"] or "").strip()
        trunk_direction = normalize_trunk_direction(str(row["trunk_direction"] or "both"))
        trunk_enabled = bool(row["trunk_enabled"]) if row["trunk_enabled"] is not None else False
        if inbound_trunk_name and (not trunk_enabled or trunk_direction not in {"inbound", "both"}):
            continue
        destination_type = (row["destination_type"] or "").strip().lower()
        destination_value = (row["destination_value"] or "").strip()
        safe_name = re.sub(r"[^0-9A-Za-z_]+", "_", route_name).strip("_") or f"route_{route_id}"
        actions: list[str] = []
        if destination_type == "queue":
            if not destination_value:
                continue
            actions.append(f'<action application="transfer" data="{destination_value} XML default"/>')
        elif destination_type == "device":
            if not destination_value:
                continue
            actions.append(f'<action application="bridge" data="user/{destination_value}"/>')
        elif destination_type == "vpbx":
            if not destination_value:
                continue
            actions.append(f'<action application="transfer" data="{destination_value} XML default"/>')
        elif destination_type == "fax":
            fax_tag = destination_value or did_pattern or str(route_id)
            actions.extend(fax_receive_actions(fax_tag))
        elif destination_type == "conference":
            if not destination_value:
                continue
            actions.append(f'<action application="conference" data="{destination_value}@default"/>')
        else:
            continue
        condition_field = "destination_number"
        condition_expression = expression
        if inbound_trunk_name:
            did_inner = expression
            if did_inner.startswith("^"):
                did_inner = did_inner[1:]
            if did_inner.endswith("$"):
                did_inner = did_inner[:-1]
            condition_field = "${sip_gateway_name}|${destination_number}"
            condition_expression = f"^{re.escape(inbound_trunk_name)}\\|{did_inner}$"
        block = textwrap.dedent(
            f"""\
              <extension name="callture_in_{route_id}_{safe_name}">
                <condition field="{condition_field}" expression="{condition_expression}">
                  {' '.join(actions)}
                </condition>
              </extension>
            """
        )
        blocks.append(block)

    xml = "<include>\n" + ("\n".join(blocks) if blocks else "  <!-- no inbound routes configured -->\n") + "</include>\n"
    write_root_file("/usr/local/freeswitch/conf/dialplan/public/05_callture_routes_inbound.xml", xml)
    fs_cli("reloadxml")


def sync_outbound_routes_dialplan() -> None:
    with closing(db_conn()) as conn:
        rows = conn.execute(
            """
            SELECT
                r.id,
                r.name,
                r.dial_pattern,
                r.match_mode,
                r.trunk_name,
                t.enabled AS trunk_enabled,
                t.direction AS trunk_direction,
                t.outbound_prefix,
                t.e164_send_plus
            FROM outbound_routes r
            LEFT JOIN trunks t ON t.name = r.trunk_name
            WHERE r.enabled = 1
            ORDER BY r.id
            """
        ).fetchall()

    outbound_trunk = re.sub(r"[^0-9A-Za-z_.-]", "", REGISTERED_FIRST_OUTBOUND_TRUNK) or "kamailio6932"
    blocks: list[str] = [
        textwrap.dedent(
            f"""\
              <extension name="callture_registered_internal_or_kamailio_trunk">
                <condition field="${{sip_authorized}}" expression="^true$">
                  <condition field="destination_number" expression="{NANP_10_OR_11_DIGIT_EXPR}">
                    <action application="set" data="callture_target_user=${{regex(${{destination_number}}|^1?([2-9]\\d{{9}})$|$1)}}"/>
                    <action application="set" data="callture_out_target=1${{callture_target_user}}"/>
                    <condition field="${{user_registered(${{callture_target_user}}@$${{domain}})}}" expression="^true$">
                      <action application="bridge" data="user/${{callture_target_user}}@$${{domain}}"/>
                      <anti-action application="set" data="continue_on_fail=true"/>
                      <anti-action application="set" data="hangup_after_bridge=true"/>
                      <anti-action application="bridge" data="sofia/gateway/{outbound_trunk}/${{callture_out_target}}"/>
                    </condition>
                  </condition>
                  <condition field="destination_number" expression="^(?!1?[2-9]\\d{{9}}$).+">
                    <action application="hangup" data="CALL_REJECTED"/>
                  </condition>
                </condition>
              </extension>
            """
        )
    ]
    for row in rows:
        route_id = int(row["id"])
        route_name = (row["name"] or f"out_{route_id}").strip()
        dial_pattern = (row["dial_pattern"] or "").strip()
        trunk_name = (row["trunk_name"] or "").strip()
        trunk_direction = normalize_trunk_direction(str(row["trunk_direction"] or "both"))
        if not dial_pattern or not trunk_name or not bool(row["trunk_enabled"]) or trunk_direction not in {"outbound", "both"}:
            continue
        expression, out_target = outbound_match_expression_and_target(dial_pattern, row["match_mode"] or "prefix")
        safe_name = re.sub(r"[^0-9A-Za-z_]+", "_", route_name).strip("_") or f"out_{route_id}"
        outbound_prefix = sanitize_outbound_prefix_for_dialing(str(row["outbound_prefix"] or ""))
        send_plus = bool(row["e164_send_plus"])
        actions = [
            '<action application="set" data="continue_on_fail=true"/>',
            '<action application="set" data="hangup_after_bridge=true"/>',
            f'<action application="set" data="callture_out_target={out_target}"/>',
        ]
        if outbound_prefix:
            actions.append(f'<action application="set" data="callture_out_target={outbound_prefix}${{callture_out_target}}"/>')
        if send_plus:
            actions.append(
                '<action application="set" data="callture_out_target=${if(${callture_out_target:0:1} == + ? ${callture_out_target} : +${callture_out_target})}"/>'
            )
        else:
            actions.append(
                '<action application="set" data="callture_out_target=${if(${callture_out_target:0:1} == + ? ${callture_out_target:1} : ${callture_out_target})}"/>'
            )
        actions.append(f'<action application="bridge" data="sofia/gateway/{trunk_name}/${{callture_out_target}}"/>')
        block = textwrap.dedent(
            f"""\
              <extension name="callture_out_{route_id}_{safe_name}">
                <condition field="destination_number" expression="{expression}">
                  {' '.join(actions)}
                </condition>
              </extension>
            """
        )
        blocks.append(block)

    xml = "<include>\n" + ("\n".join(blocks) if blocks else "  <!-- no outbound routes configured -->\n") + "</include>\n"
    write_root_file("/usr/local/freeswitch/conf/dialplan/default/97_callture_outbound_routes.xml", xml)
    fs_cli("reloadxml")


def registration_snapshot() -> str:
    return fs_cli("show registrations")


@app.on_event("startup")
def startup() -> None:
    init_db()
    load_platform()
    sync_trunks_to_freeswitch()
    sync_fax_inbound_dialplan()
    sync_conference_dialplan()
    sync_webrtc_internal_user_bridge_dialplan()
    sync_inbound_routes_dialplan()
    sync_outbound_routes_dialplan()
    start_security_autoblock_worker()


@app.on_event("shutdown")
def shutdown() -> None:
    security_autoblock_stop.set()


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    user = require_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=303) if is_admin_user(user) else redirect_settings()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    user = require_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=303) if is_admin_user(user) else redirect_settings()
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        log_security_event(
            request,
            "login_failed",
            severity="medium",
            username=username.strip(),
            details="Unknown username or invalid password",
        )
        log_bruteforce_if_needed(request)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    candidate = hash_password(password, row["salt"])
    if secrets.compare_digest(candidate, row["password_hash"]):
        request.session["user"] = username
        log_security_event(request, "login_success", severity="info", username=username.strip())
        return RedirectResponse(url="/dashboard", status_code=303) if is_admin_user(username) else redirect_settings()
    log_security_event(
        request,
        "login_failed",
        severity="medium",
        username=username.strip(),
        details="Unknown username or invalid password",
    )
    log_bruteforce_if_needed(request)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    load_platform()
    queue_numbers = sorted(platform.engine.queues.keys())
    wallboards = {q: platform.dashboard.wallboard(q) for q in queue_numbers}
    queue_monitors: dict[str, list[dict[str, Any]]] = {}
    for queue_number in queue_numbers:
        waiting_calls = list(platform.engine.waiting_calls[queue_number])
        rows: list[dict[str, Any]] = []
        for idx, call in enumerate(waiting_calls):
            rows.append(
                {
                    "call_id": call.call_id,
                    "caller_id": call.caller_id,
                    "people_ahead": idx,
                    "wait_seconds": int((datetime.now(UTC) - call.created_at).total_seconds()),
                }
            )
        queue_monitors[queue_number] = rows

    security_message = (request.query_params.get("security_message") or "").strip()
    with closing(db_conn()) as conn:
        queue_settings_rows = conn.execute(
            "SELECT number, announce_position, voicemail_escape_digit FROM queues"
        ).fetchall()
        blocked_ips = conn.execute(
            """
            SELECT ip_address, reason, source_event_type, block_count, last_blocked_at
            FROM blocked_ips
            WHERE active = 1
            ORDER BY last_blocked_at DESC
            LIMIT 25
            """
        ).fetchall()
        whitelist_ips = conn.execute(
            """
            SELECT ip_address, note, created_by, updated_at
            FROM whitelist_ips
            WHERE active = 1
            ORDER BY updated_at DESC
            LIMIT 25
            """
        ).fetchall()
    queue_settings = {
        row["number"]: {
            "announce_position": bool(row["announce_position"]),
            "voicemail_escape_digit": row["voicemail_escape_digit"] or "9",
        }
        for row in queue_settings_rows
    }
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "queue_numbers": queue_numbers,
            "wallboards": wallboards,
            "queue_monitors": queue_monitors,
            "queue_settings": queue_settings,
            "agents": platform.dashboard.agent_details(),
            "live": platform.analytics.live_report(),
            "blocked_ips": blocked_ips,
            "whitelist_ips": whitelist_ips,
            "security_message": security_message,
        },
    )


@app.get("/webrtcphone", response_class=HTMLResponse)
def webrtc_phone_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    sip_host = infer_webrtc_realm()
    with closing(db_conn()) as conn:
        extensions = conn.execute(
            "SELECT extension, display_name FROM vpbx_extensions ORDER BY extension"
        ).fetchall()
    host_header = (request.headers.get("host") or "").strip()
    page_host = host_header or (request.url.netloc or "").strip() or (request.url.hostname or "").strip()
    hostname_only = (request.url.hostname or "").strip() or infer_webrtc_realm()
    ws_host = page_host
    if request.url.scheme == "https":
        # Explicitly target HTTP listener for ws fallback from HTTPS page.
        ws_host = f"{hostname_only}:8088"
    elif ":" not in ws_host and hostname_only:
        ws_host = f"{hostname_only}:8088"
    # Keep ws fallback on 8088 and wss on the TLS endpoint.
    webrtc_ws_url = f"ws://{ws_host}/webrtc/ws" if ws_host else "ws://204.29.213.58:8088/webrtc/ws"
    webrtc_wss_url = f"wss://{hostname_only}:8088/webrtc/ws" if hostname_only else "wss://204.29.213.58:8088/webrtc/ws"
    response = templates.TemplateResponse(
        "webrtcphone.html",
        {
            "request": request,
            "user": user,
            "webrtc_realm": sip_host,
            # Use portal WebSocket proxy by default so clients can register even when
            # direct FreeSWITCH WS/WSS ports are filtered by upstream firewalls.
            "webrtc_wss_url": webrtc_wss_url,
            "webrtc_ws_url": webrtc_ws_url,
            "webrtc_extensions": extensions,
            "webrtc_default_extension": WEBRTC_DEFAULT_EXTENSION,
            "webrtc_default_password": WEBRTC_DEFAULT_PASSWORD,
        },
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/callture")
def callture_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    return RedirectResponse(url="/static/callture/callture.html", status_code=302)


@app.get("/saraphone")
def saraphone_page(request: Request):
    # Backward-compatible alias for the old SaraPhone URL.
    return callture_page(request)


@app.websocket("/webrtc/ws")
async def webrtc_ws_proxy(websocket: WebSocket):
    global WEBRTC_UPSTREAM_LAST_GOOD
    session = websocket.scope.get("session") or {}
    session_user = session.get("user")
    source_ip = request_ip_from_scope(websocket.scope) or (websocket.client.host if websocket.client else "unknown")
    client_key = f"user:{session_user}" if session_user else f"ip:{source_ip}"

    proxy_id = secrets.token_hex(4)
    previous_ws = WEBRTC_ACTIVE_CLIENTS.get(client_key)
    if previous_ws is not None and previous_ws is not websocket:
        try:
            print(f"WebRTC proxy[{proxy_id}] replacing existing socket key={client_key}")
            await previous_ws.close(code=1012, reason="Replaced by newer WebRTC socket")
        except Exception:
            pass
    await websocket.accept(subprotocol="sip")
    WEBRTC_ACTIVE_CLIENTS[client_key] = websocket
    print(
        f"WebRTC proxy[{proxy_id}] accepted client={websocket.client} "
        f"host={websocket.url.hostname} session_user={session_user or '-'}"
    )
    preferred = WEBRTC_UPSTREAM_LAST_GOOD or ""
    upstream_hosts = unique_nonempty(
        [
            preferred,
            infer_webrtc_realm(),
            websocket.url.hostname or "",
            "204.29.213.58",
            "127.0.0.1",
            "localhost",
        ]
    )
    upstream = None
    last_error: Exception | None = None
    try:
        for host in upstream_hosts:
            try:
                upstream = await websockets.connect(
                    f"ws://{host}:5066",
                    subprotocols=["sip"],
                    ping_interval=20,
                    ping_timeout=20,
                    open_timeout=2,
                    close_timeout=2,
                )
                WEBRTC_UPSTREAM_LAST_GOOD = host
                print(f"WebRTC proxy[{proxy_id}] upstream connected host={host}")
                break
            except Exception as exc:
                last_error = exc
        if upstream is None:
            print(f"WebRTC proxy[{proxy_id}] upstream unavailable hosts={upstream_hosts} last_error={last_error}")
            await websocket.close(code=1011, reason="Upstream WS unavailable")
            return

        async def client_to_upstream():
            seen = 0
            try:
                while True:
                    message = await websocket.receive()
                    msg_type = message.get("type")
                    if msg_type == "websocket.disconnect":
                        print(f"WebRTC proxy[{proxy_id}] client disconnected")
                        break
                    if message.get("text") is not None:
                        if seen < 2:
                            first_line = (message["text"] or "").splitlines()[0] if message["text"] else ""
                            print(f"WebRTC proxy[{proxy_id}] c->u text: {first_line[:120]}")
                        seen += 1
                        await upstream.send(message["text"])
                    elif message.get("bytes") is not None:
                        if seen < 2:
                            print(f"WebRTC proxy[{proxy_id}] c->u bytes: {len(message['bytes'])}")
                        seen += 1
                        await upstream.send(message["bytes"])
            except WebSocketDisconnect:
                pass
            except websockets.exceptions.ConnectionClosed:
                pass

        async def upstream_to_client():
            seen = 0
            try:
                while True:
                    incoming = await upstream.recv()
                    if seen < 2:
                        if isinstance(incoming, bytes):
                            print(f"WebRTC proxy[{proxy_id}] u->c bytes: {len(incoming)}")
                        else:
                            first_line = (incoming or "").splitlines()[0] if incoming else ""
                            print(f"WebRTC proxy[{proxy_id}] u->c text: {first_line[:120]}")
                    seen += 1
                    if isinstance(incoming, bytes):
                        await websocket.send_bytes(incoming)
                    else:
                        await websocket.send_text(incoming)
            except websockets.exceptions.ConnectionClosed:
                pass
            except RuntimeError:
                # Avoid websocket.send after websocket.close races.
                pass

        client_task = asyncio.create_task(client_to_upstream())
        upstream_task = asyncio.create_task(upstream_to_client())
        done, pending = await asyncio.wait(
            {client_task, upstream_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc
    except (WebSocketDisconnect, websockets.exceptions.ConnectionClosed):
        pass
    except Exception as exc:
        print(f"WebRTC proxy[{proxy_id}] runtime error: {exc}")
    finally:
        if WEBRTC_ACTIVE_CLIENTS.get(client_key) is websocket:
            WEBRTC_ACTIVE_CLIENTS.pop(client_key, None)
        if upstream is not None:
            try:
                await upstream.close()
            except Exception:
                pass
        if websocket.client_state != WebSocketState.DISCONNECTED:
            try:
                await websocket.close()
            except Exception:
                pass
        print(f"WebRTC proxy[{proxy_id}] closed")


@app.get("/queues", response_class=HTMLResponse)
def queues_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
    queue_rows = build_queue_rows(queues)
    inbound_assignments = build_inbound_assignment_rows(queues)
    return templates.TemplateResponse(
        "queues.html",
        {
            "request": request,
            "user": user,
            "queues": queues,
            "queue_rows": queue_rows,
            "strategies": [s.value for s in RoutingStrategy],
            "ring_modes": ["blast", "sequential"],
            "rollover_counts": [0, 1, 2, 3],
            "message": None,
            "error": None,
            "inbound_assignments": inbound_assignments,
        },
    )


@app.post("/queues", response_class=HTMLResponse)
def create_queue(
    request: Request,
    name: str = Form(...),
    number: str = Form(...),
    ring_mode: str = Form("blast"),
    max_wait_seconds: int = Form(300),
    max_queue_size: int = Form(25),
    wrap_up_seconds: int = Form(30),
    hold_music: str = Form("local_stream://moh"),
    greeting_file: str = Form(""),
    inbound_numbers: str = Form(""),
    dial_targets: str = Form(""),
    rollover_1: str = Form(""),
    rollover_2: str = Form(""),
    rollover_3: str = Form(""),
    rollover_count: int = Form(0),
    voicemail_box: str = Form(""),
    announce_position: str = Form("true"),
    voicemail_escape_digit: str = Form("9"),
    record_calls: str = Form("true"),
    queue_action: str = Form("save_main"),
    second_name: str = Form(""),
    second_ring_mode: str = Form("blast"),
    second_max_wait_seconds: int = Form(300),
    second_max_queue_size: int = Form(25),
    second_wrap_up_seconds: int = Form(30),
    second_numbers: str = Form(""),
    second_dial_targets: str = Form(""),
    second_voicemail_box: str = Form(""),
    second_announce_position: str = Form("true"),
    second_voicemail_escape_digit: str = Form("9"),
    second_record_calls: str = Form("true"),
    third_name: str = Form(""),
    third_ring_mode: str = Form("blast"),
    third_max_wait_seconds: int = Form(300),
    third_max_queue_size: int = Form(25),
    third_wrap_up_seconds: int = Form(30),
    third_numbers: str = Form(""),
    third_dial_targets: str = Form(""),
    third_voicemail_box: str = Form(""),
    third_announce_position: str = Form("true"),
    third_voicemail_escape_digit: str = Form("9"),
    third_record_calls: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    def norm_ring(mode: str) -> tuple[str, str]:
        m = (mode or "blast").strip().lower()
        return m, ("ring-all" if m == "blast" else "top-down")

    def upsert_queue(
        conn: sqlite3.Connection,
        *,
        q_number: str,
        q_name: str,
        q_ring_mode: str,
        q_max_wait: int,
        q_max_queue: int,
        q_wrap: int,
        q_numbers: str,
        q_targets: str,
        q_overflow: list[str],
        q_voicemail: str,
        q_announce: str,
        q_vm_digit: str,
        q_record_calls: str,
    ) -> None:
        ring_mode_norm, strategy = norm_ring(q_ring_mode)
        vm_digit = (q_vm_digit or "9").strip()[:1] or "9"
        q_max_wait = q_max_wait if q_max_wait > 0 else 300
        overflow_csv = ",".join([x for x in q_overflow if x])
        conn.execute(
            """
            INSERT OR REPLACE INTO queues(number, name, strategy, max_wait_seconds, max_queue_size, wrap_up_seconds,
                                          greeting_file, hold_music, overflow_queues, voicemail_box, record_calls,
                                          inbound_numbers, dial_targets, ring_mode, max_rollovers,
                                          announce_position, voicemail_escape_digit, rollover_count)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                q_number,
                q_name,
                strategy,
                q_max_wait,
                q_max_queue,
                q_wrap,
                greeting_file or None,
                hold_music,
                overflow_csv,
                q_voicemail or None,
                1 if q_record_calls.lower() == "true" else 0,
                ",".join(parse_inbound_lines(q_numbers)),
                ",".join([x.strip() for x in q_targets.split(",") if x.strip()]),
                ring_mode_norm,
                3,
                1 if q_announce.lower() == "true" else 0,
                vm_digit,
                min(len([x for x in q_overflow if x]), 3),
            ),
        )

    rollover_count = max(0, min(int(rollover_count), 3))
    second_queue_id = rollover_1.strip()
    third_queue_id = rollover_2.strip()
    fourth_queue_id = rollover_3.strip()

    main_chain_candidates = [second_queue_id, third_queue_id, fourth_queue_id]
    main_chain = [x for x in main_chain_candidates if x][:rollover_count]

    with closing(db_conn()) as conn:
        action = (queue_action or "save_main").strip().lower()
        if action in {"save_second", "save_third"}:
            existing_main = conn.execute("SELECT number FROM queues WHERE number = ?", (number.strip(),)).fetchone()
            if existing_main is None:
                queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
                queue_rows = build_queue_rows(queues)
                inbound_assignments = build_inbound_assignment_rows(queues)
                return templates.TemplateResponse(
                    "queues.html",
                    {
                        "request": request,
                        "user": user,
                        "queues": queues,
                        "queue_rows": queue_rows,
                        "strategies": [s.value for s in RoutingStrategy],
                        "ring_modes": ["blast", "sequential"],
                        "rollover_counts": [0, 1, 2, 3],
                        "message": None,
                        "error": f"Main queue {number.strip()} does not exist yet. Save Main Queue first.",
                        "inbound_assignments": inbound_assignments,
                    },
                )

        planned_lines: dict[str, list[str]] = {}
        planned_names: dict[str, str] = {}
        planned_targets: dict[str, list[str]] = {}

        def plan_queue(queue_number: str, queue_name: str, queue_numbers_raw: str, queue_targets_raw: str) -> None:
            qid = queue_number.strip()
            if not qid:
                return
            planned_lines[qid] = parse_inbound_lines(queue_numbers_raw)
            planned_names[qid] = queue_name.strip() or qid
            planned_targets[qid] = parse_csv_values(queue_targets_raw)

        # Save main queue only when explicitly requested, or if it does not exist yet.
        existing_main = conn.execute("SELECT number FROM queues WHERE number = ?", (number.strip(),)).fetchone()
        if action == "save_main" or existing_main is None:
            plan_queue(number, name, inbound_numbers, dial_targets)

        # One-click button for second queue settings (can differ from main).
        if action in {"save_second", "save_all"} and second_queue_id:
            plan_queue(
                second_queue_id,
                (second_name.strip() or f"{name.strip()} L2"),
                (second_numbers or inbound_numbers),
                (second_dial_targets or dial_targets),
            )

        # One-click button for third queue settings (can differ from main/second).
        if action in {"save_third", "save_all"} and third_queue_id:
            plan_queue(
                third_queue_id,
                (third_name.strip() or f"{name.strip()} L3"),
                (third_numbers or inbound_numbers),
                (third_dial_targets or dial_targets),
            )

        missing_inbound = [qid for qid, lines in planned_lines.items() if not lines]
        if missing_inbound:
            queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
            queue_rows = build_queue_rows(queues)
            inbound_assignments = build_inbound_assignment_rows(queues)
            missing_text = ", ".join(missing_inbound)
            return templates.TemplateResponse(
                "queues.html",
                {
                    "request": request,
                    "user": user,
                    "queues": queues,
                    "queue_rows": queue_rows,
                    "strategies": [s.value for s in RoutingStrategy],
                    "ring_modes": ["blast", "sequential"],
                    "rollover_counts": [0, 1, 2, 3],
                    "message": None,
                    "error": f"Inbound line is required. Add at least one inbound number for queue(s): {missing_text}.",
                    "inbound_assignments": inbound_assignments,
                },
            )

        assigned_owner: dict[str, tuple[str, str]] = {}
        for row in conn.execute("SELECT number, name, inbound_numbers FROM queues ORDER BY number"):
            if row["number"] in planned_lines:
                continue
            for line in parse_inbound_lines(row["inbound_numbers"] or ""):
                assigned_owner.setdefault(line.casefold(), (row["number"], row["name"]))

        conflicts: list[str] = []
        for qid, lines in planned_lines.items():
            for line in lines:
                owner = assigned_owner.get(line.casefold())
                if owner and owner[0] != qid:
                    conflicts.append(f"{line} already belongs to {owner[0]} ({owner[1]})")
                    continue
                assigned_owner[line.casefold()] = (qid, planned_names.get(qid, qid))

        if conflicts:
            queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
            queue_rows = build_queue_rows(queues)
            inbound_assignments = build_inbound_assignment_rows(queues)
            conflict_text = "; ".join(sorted(set(conflicts)))
            return templates.TemplateResponse(
                "queues.html",
                {
                    "request": request,
                    "user": user,
                    "queues": queues,
                    "queue_rows": queue_rows,
                    "strategies": [s.value for s in RoutingStrategy],
                    "ring_modes": ["blast", "sequential"],
                    "rollover_counts": [0, 1, 2, 3],
                    "message": None,
                    "error": f"Inbound line conflict: {conflict_text}. Each inbound line can belong to one queue only.",
                    "inbound_assignments": inbound_assignments,
                },
            )

        agent_rows = conn.execute("SELECT agent_id FROM agents ORDER BY agent_id").fetchall()
        agent_ids = {str(row["agent_id"]).strip().casefold() for row in agent_rows if str(row["agent_id"]).strip()}
        missing_agent_refs: list[str] = []
        for qid, targets in planned_targets.items():
            for token in targets:
                lookup_key = dial_target_agent_lookup_key(token)
                if not lookup_key:
                    continue
                if lookup_key not in agent_ids:
                    missing_agent_refs.append(f"{token} (queue {qid})")

        if missing_agent_refs:
            queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
            queue_rows = build_queue_rows(queues)
            inbound_assignments = build_inbound_assignment_rows(queues)
            missing_agent_text = ", ".join(sorted(set(missing_agent_refs)))
            return templates.TemplateResponse(
                "queues.html",
                {
                    "request": request,
                    "user": user,
                    "queues": queues,
                    "queue_rows": queue_rows,
                    "strategies": [s.value for s in RoutingStrategy],
                    "ring_modes": ["blast", "sequential"],
                    "rollover_counts": [0, 1, 2, 3],
                    "message": None,
                    "error": (
                        "Queue Dial Numbers has unknown agent references: "
                        f"{missing_agent_text}. Create/save those agents first."
                    ),
                    "inbound_assignments": inbound_assignments,
                },
            )

        if action == "save_main" or existing_main is None:
            upsert_queue(
                conn,
                q_number=number.strip(),
                q_name=name.strip(),
                q_ring_mode=ring_mode,
                q_max_wait=max_wait_seconds,
                q_max_queue=max_queue_size,
                q_wrap=wrap_up_seconds,
                q_numbers=inbound_numbers,
                q_targets=dial_targets,
                q_overflow=main_chain,
                q_voicemail=voicemail_box,
                q_announce=announce_position,
                q_vm_digit=voicemail_escape_digit,
                q_record_calls=record_calls,
            )

        # One-click button for second queue settings (can differ from main).
        if action in {"save_second", "save_all"} and second_queue_id:
            second_overflow: list[str] = []
            if rollover_count >= 2 and third_queue_id:
                second_overflow.append(third_queue_id)
            if rollover_count >= 3 and fourth_queue_id:
                second_overflow.append(fourth_queue_id)
            upsert_queue(
                conn,
                q_number=second_queue_id,
                q_name=(second_name.strip() or f"{name.strip()} L2"),
                q_ring_mode=second_ring_mode,
                q_max_wait=second_max_wait_seconds,
                q_max_queue=second_max_queue_size,
                q_wrap=second_wrap_up_seconds,
                q_numbers=(second_numbers or inbound_numbers),
                q_targets=(second_dial_targets or dial_targets),
                q_overflow=second_overflow,
                q_voicemail=(second_voicemail_box or voicemail_box),
                q_announce=second_announce_position,
                q_vm_digit=second_voicemail_escape_digit,
                q_record_calls=second_record_calls,
            )

        # One-click button for third queue settings (can differ from main/second).
        if action in {"save_third", "save_all"} and third_queue_id:
            third_overflow: list[str] = []
            if rollover_count >= 3 and fourth_queue_id:
                third_overflow.append(fourth_queue_id)
            upsert_queue(
                conn,
                q_number=third_queue_id,
                q_name=(third_name.strip() or f"{name.strip()} L3"),
                q_ring_mode=third_ring_mode,
                q_max_wait=third_max_wait_seconds,
                q_max_queue=third_max_queue_size,
                q_wrap=third_wrap_up_seconds,
                q_numbers=(third_numbers or inbound_numbers),
                q_targets=(third_dial_targets or dial_targets),
                q_overflow=third_overflow,
                q_voicemail=(third_voicemail_box or voicemail_box),
                q_announce=third_announce_position,
                q_vm_digit=third_voicemail_escape_digit,
                q_record_calls=third_record_calls,
            )

        conn.commit()

        queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()

    load_platform()
    queue_rows = build_queue_rows(queues)
    inbound_assignments = build_inbound_assignment_rows(queues)
    return templates.TemplateResponse(
        "queues.html",
        {
            "request": request,
            "user": user,
            "queues": queues,
            "queue_rows": queue_rows,
            "strategies": [s.value for s in RoutingStrategy],
            "ring_modes": ["blast", "sequential"],
            "rollover_counts": [0, 1, 2, 3],
            "message": (
                f"Queue {number} saved. Use buttons to one-click save second/third queue settings. "
                "If next queue is not set, flow goes to voicemail."
            ),
            "error": None,
            "inbound_assignments": inbound_assignments,
        },
    )


@app.post("/queues/seed-default", response_class=HTMLResponse)
def seed_default_queues(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    defaults = [
        ("Sales", "7001", "blast"),
        ("Support", "7002", "blast"),
        ("Billing", "7003", "sequential"),
        ("Personal", "7004", "sequential"),
    ]
    with closing(db_conn()) as conn:
        for idx, (name, number, ring_mode) in enumerate(defaults, start=1):
            strategy = "ring-all" if ring_mode == "blast" else "top-down"
            chain_list = [d[1] for d in defaults[idx:idx + 3]]
            overflow_chain = ",".join(chain_list)
            conn.execute(
                """
                INSERT OR REPLACE INTO queues(number, name, strategy, max_wait_seconds, max_queue_size, wrap_up_seconds,
                                              greeting_file, hold_music, overflow_queues, voicemail_box, record_calls,
                                              inbound_numbers, dial_targets, ring_mode, max_rollovers,
                                              announce_position, voicemail_escape_digit, rollover_count)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    number,
                    name,
                    strategy,
                    300,
                    25,
                    30,
                    None,
                    "local_stream://moh",
                    overflow_chain,
                    f"90{idx:02d}",
                    1,
                    "",
                    "",
                    ring_mode,
                    3,
                    1,
                    "9",
                    len(chain_list),
                ),
            )
        conn.commit()

        queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
        queue_rows = build_queue_rows(queues)
        inbound_assignments = build_inbound_assignment_rows(queues)

    load_platform()
    return templates.TemplateResponse(
        "queues.html",
        {
            "request": request,
            "user": user,
            "queues": queues,
            "queue_rows": queue_rows,
            "strategies": [s.value for s in RoutingStrategy],
            "ring_modes": ["blast", "sequential"],
            "rollover_counts": [0, 1, 2, 3],
            "message": "Seeded Sales/Support/Billing/Personal queues with 5-minute timeout and rollover max 3.",
            "error": None,
            "inbound_assignments": inbound_assignments,
        },
    )


@app.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        agents = conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()
        memberships = conn.execute("SELECT * FROM agent_queue_memberships").fetchall()
        queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()

    member_map: dict[str, list[str]] = {}
    for row in memberships:
        member_map.setdefault(row["agent_id"], []).append(row["queue_number"])

    return templates.TemplateResponse(
        "agents.html",
        {
            "request": request,
            "user": user,
            "agents": agents,
            "queues": queues,
            "member_map": member_map,
            "message": None,
            "error": None,
        },
    )


@app.post("/agents", response_class=HTMLResponse)
def create_agent(
    request: Request,
    agent_id: str = Form(...),
    extension: str = Form(...),
    skills: str = Form(""),
    languages: str = Form("en"),
    queue_numbers: str = Form(""),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    skills_norm = ",".join([x.strip() for x in skills.split(",") if x.strip()])
    lang_norm = ",".join([x.strip() for x in languages.split(",") if x.strip()])
    queues_norm = parse_csv_values(queue_numbers)

    with closing(db_conn()) as conn:
        queue_rows = conn.execute("SELECT number FROM queues ORDER BY number").fetchall()
        valid_queue_ids = {row["number"] for row in queue_rows}
        invalid_queues = [q for q in queues_norm if q not in valid_queue_ids]
        if not queues_norm:
            agents = conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()
            memberships = conn.execute("SELECT * FROM agent_queue_memberships").fetchall()
            queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
            member_map: dict[str, list[str]] = {}
            for row in memberships:
                member_map.setdefault(row["agent_id"], []).append(row["queue_number"])
            return templates.TemplateResponse(
                "agents.html",
                {
                    "request": request,
                    "user": user,
                    "agents": agents,
                    "queues": queues,
                    "member_map": member_map,
                    "message": None,
                    "error": "Assign at least one queue to the agent (no dangling agents).",
                },
            )
        if invalid_queues:
            agents = conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()
            memberships = conn.execute("SELECT * FROM agent_queue_memberships").fetchall()
            queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()
            member_map: dict[str, list[str]] = {}
            for row in memberships:
                member_map.setdefault(row["agent_id"], []).append(row["queue_number"])
            invalid_text = ", ".join(sorted(set(invalid_queues)))
            return templates.TemplateResponse(
                "agents.html",
                {
                    "request": request,
                    "user": user,
                    "agents": agents,
                    "queues": queues,
                    "member_map": member_map,
                    "message": None,
                    "error": f"Unknown queue number(s): {invalid_text}",
                },
            )
        conn.execute(
            "INSERT OR REPLACE INTO agents(agent_id, extension, skills, languages, status) VALUES(?,?,?,?,?)",
            (agent_id, extension, skills_norm, lang_norm, "available"),
        )
        conn.execute("DELETE FROM agent_queue_memberships WHERE agent_id = ?", (agent_id,))
        for q in queues_norm:
            conn.execute(
                "INSERT OR REPLACE INTO agent_queue_memberships(agent_id, queue_number) VALUES(?,?)",
                (agent_id, q),
            )
        conn.commit()

    load_platform()
    with closing(db_conn()) as conn:
        agents = conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()
        memberships = conn.execute("SELECT * FROM agent_queue_memberships").fetchall()
        queues = conn.execute("SELECT * FROM queues ORDER BY number").fetchall()

    member_map: dict[str, list[str]] = {}
    for row in memberships:
        member_map.setdefault(row["agent_id"], []).append(row["queue_number"])

    return templates.TemplateResponse(
        "agents.html",
        {
            "request": request,
            "user": user,
            "agents": agents,
            "queues": queues,
            "member_map": member_map,
            "message": f"Agent {agent_id} saved.",
            "error": None,
        },
    )


def routes_page_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    inbound_routes = conn.execute("SELECT * FROM inbound_routes ORDER BY id DESC").fetchall()
    outbound_routes = conn.execute("SELECT * FROM outbound_routes ORDER BY id DESC").fetchall()
    trunks = conn.execute("SELECT * FROM trunks ORDER BY name").fetchall()
    inbound_trunks = [t for t in trunks if (t["direction"] or "both") in {"inbound", "both"}]
    outbound_trunks = [t for t in trunks if (t["direction"] or "both") in {"outbound", "both"}]
    queues = conn.execute("SELECT number, name FROM queues ORDER BY number").fetchall()
    devices = conn.execute("SELECT device_id, extension, auth_username FROM devices ORDER BY device_id").fetchall()
    vpbx_extensions = conn.execute("SELECT extension, display_name FROM vpbx_extensions ORDER BY extension").fetchall()
    fax_inbound = conn.execute(
        "SELECT id, did FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC"
    ).fetchall()
    conferences = conn.execute(
        "SELECT room_number, display_name FROM conferences WHERE enabled = 1 ORDER BY room_number"
    ).fetchall()
    return {
        "inbound_routes": inbound_routes,
        "outbound_routes": outbound_routes,
        "trunks": trunks,
        "inbound_trunks": inbound_trunks,
        "outbound_trunks": outbound_trunks,
        "queues": queues,
        "devices": devices,
        "vpbx_extensions": vpbx_extensions,
        "fax_inbound": fax_inbound,
        "conferences": conferences,
    }


def trunks_page_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    trunks = conn.execute("SELECT * FROM trunks ORDER BY name").fetchall()
    inbound_trunks = [t for t in trunks if (t["direction"] or "both") in {"inbound", "both"}]
    outbound_trunks = [t for t in trunks if (t["direction"] or "both") in {"outbound", "both"}]
    return {
        "trunks": trunks,
        "inbound_trunks": inbound_trunks,
        "outbound_trunks": outbound_trunks,
    }


def upsert_trunk_record(
    conn: sqlite3.Connection,
    *,
    name: str,
    proxy: str,
    direction: str,
    in_prefix: str,
    inbound_did_pattern: str,
    inbound_match_mode: str,
    out_prefix: str,
    dialout_pattern: str,
    outbound_match_mode: str,
    enabled: bool,
) -> str:
    trunk_name = name.strip()
    proxy_value = proxy.strip()
    direction_value = normalize_trunk_direction(direction)
    inbound_prefix_value = in_prefix.strip()
    did_pattern_value = inbound_did_pattern.strip()
    outbound_prefix_value = out_prefix.strip()
    dial_pattern_value = dialout_pattern.strip()
    inbound_mode_value = normalize_match_mode(inbound_match_mode)
    outbound_mode_value = normalize_match_mode(outbound_match_mode, outbound=True)
    default_pattern = r"^(1?\d{10})$"
    if direction_value == "inbound" and not did_pattern_value:
        did_pattern_value = default_pattern
    if direction_value == "outbound" and not dial_pattern_value:
        dial_pattern_value = default_pattern
    existing = conn.execute("SELECT * FROM trunks WHERE name = ?", (trunk_name,)).fetchone()
    created_at = (existing["created_at"] if existing else datetime.now(UTC).isoformat())
    existing_in_prefix = (existing["in_prefix"] if existing else "") or ""
    existing_in_pattern = (existing["inbound_did_pattern"] if existing else "") or ""
    existing_in_mode = (existing["inbound_match_mode"] if existing else "exact") or "exact"
    existing_out_prefix = (existing["outbound_prefix"] if existing else "") or ""
    existing_out_pattern = (existing["dialout_pattern"] if existing else "") or ""
    existing_out_mode = (existing["outbound_match_mode"] if existing else "prefix") or "prefix"
    save_in_prefix = inbound_prefix_value if direction_value == "inbound" else existing_in_prefix
    save_in_pattern = did_pattern_value if direction_value == "inbound" else existing_in_pattern
    save_in_mode = inbound_mode_value if direction_value == "inbound" else existing_in_mode
    save_out_prefix = outbound_prefix_value if direction_value == "outbound" else existing_out_prefix
    save_out_pattern = dial_pattern_value if direction_value == "outbound" else existing_out_pattern
    save_out_mode = outbound_mode_value if direction_value == "outbound" else existing_out_mode
    conn.execute(
        """
        INSERT OR REPLACE INTO trunks(
            name, proxy, ip_address, username, password, realm, from_domain,
            direction, in_prefix, inbound_did_pattern, inbound_match_mode,
            dialout_pattern, outbound_match_mode, outbound_prefix,
            e164_send_plus, register_enabled, enabled, created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            trunk_name,
            proxy_value,
            proxy_value,
            "",
            "",
            "",
            "",
            direction_value,
            save_in_prefix,
            save_in_pattern,
            save_in_mode,
            save_out_pattern,
            save_out_mode,
            save_out_prefix,
            0,
            0,
            1 if enabled else 0,
            created_at,
        ),
    )
    conn.commit()
    return trunk_name


@app.get("/routes", response_class=HTMLResponse)
def routes_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        payload = routes_page_payload(conn)
    return templates.TemplateResponse(
        "routes.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": None,
            "error": None,
        },
    )


@app.get("/trunks", response_class=HTMLResponse)
def trunks_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        payload = trunks_page_payload(conn)
    return templates.TemplateResponse(
        "trunks.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": None,
            "error": None,
        },
    )


@app.post("/trunks/inbound", response_class=HTMLResponse)
def trunks_inbound_create(
    request: Request,
    name: str = Form(...),
    proxy: str = Form(...),
    in_prefix: str = Form(""),
    inbound_did_pattern: str = Form(""),
    inbound_match_mode: str = Form("exact"),
    enabled: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    trunk_name = name.strip()
    proxy_value = proxy.strip()
    if not trunk_name or not proxy_value:
        with closing(db_conn()) as conn:
            payload = trunks_page_payload(conn)
        return templates.TemplateResponse(
            "trunks.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Trunk ID and Proxy / SIP Host/IP are required.",
            },
        )
    with closing(db_conn()) as conn:
        saved_name = upsert_trunk_record(
            conn,
            name=trunk_name,
            proxy=proxy_value,
            direction="inbound",
            in_prefix=in_prefix,
            inbound_did_pattern=inbound_did_pattern,
            inbound_match_mode=inbound_match_mode,
            out_prefix="",
            dialout_pattern="",
            outbound_match_mode="prefix",
            enabled=as_bool(enabled),
        )
        payload = trunks_page_payload(conn)
    sync_trunks_to_freeswitch()
    sync_inbound_routes_dialplan()
    sync_outbound_routes_dialplan()
    return templates.TemplateResponse(
        "trunks.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Inbound trunk {saved_name} saved.",
            "error": None,
        },
    )


@app.post("/trunks/outbound", response_class=HTMLResponse)
def trunks_outbound_create(
    request: Request,
    name: str = Form(...),
    proxy: str = Form(...),
    out_prefix: str = Form(""),
    dialout_pattern: str = Form(""),
    outbound_match_mode: str = Form("prefix"),
    enabled: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    trunk_name = name.strip()
    proxy_value = proxy.strip()
    out_prefix_value = out_prefix.strip()
    if not trunk_name or not proxy_value:
        with closing(db_conn()) as conn:
            payload = trunks_page_payload(conn)
        return templates.TemplateResponse(
            "trunks.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Trunk ID and Proxy / SIP Host/IP are required.",
            },
        )
    if not out_prefix_value:
        with closing(db_conn()) as conn:
            payload = trunks_page_payload(conn)
        return templates.TemplateResponse(
            "trunks.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Outbound Prefix is required for outbound trunk.",
            },
        )
    with closing(db_conn()) as conn:
        saved_name = upsert_trunk_record(
            conn,
            name=trunk_name,
            proxy=proxy_value,
            direction="outbound",
            in_prefix="",
            inbound_did_pattern="",
            inbound_match_mode="exact",
            out_prefix=out_prefix_value,
            dialout_pattern=dialout_pattern,
            outbound_match_mode=outbound_match_mode,
            enabled=as_bool(enabled),
        )
        payload = trunks_page_payload(conn)
    sync_trunks_to_freeswitch()
    sync_inbound_routes_dialplan()
    sync_outbound_routes_dialplan()
    return templates.TemplateResponse(
        "trunks.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Outbound trunk {saved_name} saved.",
            "error": None,
        },
    )


@app.post("/trunks/delete", response_class=HTMLResponse)
def trunks_delete(
    request: Request,
    name: str = Form(...),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    trunk_name = name.strip()
    if not trunk_name:
        with closing(db_conn()) as conn:
            payload = trunks_page_payload(conn)
        return templates.TemplateResponse(
            "trunks.html",
            {"request": request, "user": user, **payload, "message": None, "error": "Trunk name is required for delete."},
        )
    with closing(db_conn()) as conn:
        existing = conn.execute("SELECT name FROM trunks WHERE name = ?", (trunk_name,)).fetchone()
        if existing is None:
            payload = trunks_page_payload(conn)
            return templates.TemplateResponse(
                "trunks.html",
                {"request": request, "user": user, **payload, "message": None, "error": f"Trunk {trunk_name} was not found."},
            )
        conn.execute("DELETE FROM inbound_routes WHERE inbound_trunk_name = ?", (trunk_name,))
        conn.execute("DELETE FROM outbound_routes WHERE trunk_name = ?", (trunk_name,))
        conn.execute("DELETE FROM trunks WHERE name = ?", (trunk_name,))
        conn.commit()
        payload = trunks_page_payload(conn)
    sync_trunks_to_freeswitch()
    sync_inbound_routes_dialplan()
    sync_outbound_routes_dialplan()
    return templates.TemplateResponse(
        "trunks.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Trunk {trunk_name} removed.",
            "error": None,
        },
    )


@app.post("/routes/trunks", response_class=HTMLResponse)
def route_trunk_create(
    request: Request,
    name: str = Form(...),
    proxy: str = Form(...),
    direction: str = Form("inbound"),
    in_prefix: str = Form(""),
    did_pattern: str = Form(""),
    inbound_did_pattern: str = Form(""),
    inbound_match_mode: str = Form("exact"),
    out_prefix: str = Form(""),
    dial_pattern: str = Form(""),
    dialout_pattern: str = Form(""),
    outbound_match_mode: str = Form("prefix"),
    # Kept for backward compatibility with older form payloads.
    ip_address: str = Form(""),
    outbound_prefix_selection: str = Form(""),
    outbound_prefix_custom: str = Form(""),
    enabled: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    trunk_name = name.strip()
    proxy_value = proxy.strip()
    direction_value = normalize_trunk_direction(direction)
    inbound_prefix_value = in_prefix.strip()
    did_pattern_value = did_pattern.strip() or inbound_did_pattern.strip()
    outbound_prefix_value = (out_prefix or "").strip() or (outbound_prefix_custom or "").strip() or (outbound_prefix_selection or "").strip()
    dial_pattern_value = dial_pattern.strip() or dialout_pattern.strip()
    inbound_mode_value = normalize_match_mode(inbound_match_mode)
    outbound_mode_value = normalize_match_mode(outbound_match_mode, outbound=True)
    ip_value = ip_address.strip() or proxy_value
    default_pattern = r"^(1?\d{10})$"
    if direction_value == "inbound" and not did_pattern_value:
        did_pattern_value = default_pattern
    if direction_value == "outbound" and not dial_pattern_value:
        dial_pattern_value = default_pattern
    if not trunk_name or not proxy_value:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {"request": request, "user": user, **payload, "message": None, "error": "Trunk name and proxy are required."},
        )
    with closing(db_conn()) as conn:
        existing = conn.execute("SELECT * FROM trunks WHERE name = ?", (trunk_name,)).fetchone()
        created_at = (existing["created_at"] if existing else datetime.now(UTC).isoformat())
        existing_in_prefix = (existing["in_prefix"] if existing else "") or ""
        existing_in_pattern = (existing["inbound_did_pattern"] if existing else "") or ""
        existing_in_mode = (existing["inbound_match_mode"] if existing else "exact") or "exact"
        existing_out_prefix = (existing["outbound_prefix"] if existing else "") or ""
        existing_out_pattern = (existing["dialout_pattern"] if existing else "") or ""
        existing_out_mode = (existing["outbound_match_mode"] if existing else "prefix") or "prefix"
        save_in_prefix = inbound_prefix_value if direction_value == "inbound" else existing_in_prefix
        save_in_pattern = did_pattern_value if direction_value == "inbound" else existing_in_pattern
        save_in_mode = inbound_mode_value if direction_value == "inbound" else existing_in_mode
        save_out_prefix = outbound_prefix_value if direction_value == "outbound" else existing_out_prefix
        save_out_pattern = dial_pattern_value if direction_value == "outbound" else existing_out_pattern
        save_out_mode = outbound_mode_value if direction_value == "outbound" else existing_out_mode
        conn.execute(
            """
            INSERT OR REPLACE INTO trunks(
                name, proxy, ip_address, username, password, realm, from_domain,
                direction, in_prefix, inbound_did_pattern, inbound_match_mode,
                dialout_pattern, outbound_match_mode, outbound_prefix,
                e164_send_plus, register_enabled, enabled, created_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                trunk_name,
                proxy_value,
                ip_value,
                "",
                "",
                "",
                "",
                direction_value,
                save_in_prefix,
                save_in_pattern,
                save_in_mode,
                save_out_pattern,
                save_out_mode,
                save_out_prefix,
                0,
                0,
                1 if as_bool(enabled) else 0,
                created_at,
            ),
        )
        conn.commit()
        payload = routes_page_payload(conn)

    sync_trunks_to_freeswitch()
    sync_outbound_routes_dialplan()
    return templates.TemplateResponse(
        "routes.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Trunk {trunk_name} saved and synced.",
            "error": None,
        },
    )


@app.post("/routes/trunks/delete", response_class=HTMLResponse)
def route_trunk_delete(
    request: Request,
    name: str = Form(...),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    trunk_name = name.strip()
    if not trunk_name:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {"request": request, "user": user, **payload, "message": None, "error": "Trunk name is required for delete."},
        )

    with closing(db_conn()) as conn:
        existing = conn.execute("SELECT name FROM trunks WHERE name = ?", (trunk_name,)).fetchone()
        if existing is None:
            payload = routes_page_payload(conn)
            return templates.TemplateResponse(
                "routes.html",
                {"request": request, "user": user, **payload, "message": None, "error": f"Trunk {trunk_name} was not found."},
            )

        # Keep route tables clean when a trunk is removed.
        conn.execute("DELETE FROM inbound_routes WHERE inbound_trunk_name = ?", (trunk_name,))
        conn.execute("DELETE FROM outbound_routes WHERE trunk_name = ?", (trunk_name,))
        conn.execute("DELETE FROM trunks WHERE name = ?", (trunk_name,))
        conn.commit()
        payload = routes_page_payload(conn)

    sync_trunks_to_freeswitch()
    sync_inbound_routes_dialplan()
    sync_outbound_routes_dialplan()
    return templates.TemplateResponse(
        "routes.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Trunk {trunk_name} removed.",
            "error": None,
        },
    )


@app.post("/routes/dialplan", response_class=HTMLResponse)
def dialplan_route_create(
    request: Request,
    file_type: str = Form("inbound"),
    country_code: str = Form("1"),
    destination_number: str = Form(""),
    inbound_trunk_name: str = Form(""),
    application: str = Form("queue"),
    action_value: str = Form(""),
    route_id: str = Form(""),
    route_kind: str = Form("inbound"),
    outbound_pattern: str = Form(""),
    outbound_match_mode: str = Form("regex"),
    outbound_trunk_name: str = Form(""),
    enabled: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    route_type = (file_type or "").strip().lower()
    if route_type not in {"inbound", "outbound"}:
        route_type = "inbound"

    edit_route_id = int(route_id) if str(route_id or "").strip().isdigit() else 0
    edit_kind = (route_kind or "").strip().lower()
    if edit_kind not in {"inbound", "outbound"}:
        edit_kind = route_type

    if route_type == "outbound":
        outbound_default_pattern = r"^1\d{10}$"
        dial_value = (outbound_pattern or "").strip() or outbound_default_pattern
        mode_value = normalize_match_mode(outbound_match_mode, outbound=True)
        trunk_value = (outbound_trunk_name or "").strip()
        if not dial_value:
            with closing(db_conn()) as conn:
                payload = routes_page_payload(conn)
            return templates.TemplateResponse(
                "routes.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": "Dialout Number / Pattern is required for outbound file type.",
                },
            )
        if not trunk_value:
            with closing(db_conn()) as conn:
                payload = routes_page_payload(conn)
            return templates.TemplateResponse(
                "routes.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": "Outbound trunk is required.",
                },
            )
        with closing(db_conn()) as conn:
            trunk = conn.execute(
                "SELECT name, direction, enabled FROM trunks WHERE name = ?",
                (trunk_value,),
            ).fetchone()
            if trunk is None:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Outbound trunk {trunk_value} does not exist.",
                    },
                )
            trunk_direction = normalize_trunk_direction(str(trunk["direction"] or "outbound"))
            if not bool(trunk["enabled"]) or trunk_direction not in {"outbound", "both"}:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Outbound trunk {trunk_value} is not enabled for outbound usage.",
                    },
                )
            route_name = f"Dialplan Out {dial_value} -> trunk:{trunk_value}"
            if edit_route_id and edit_kind == "outbound":
                existing = conn.execute("SELECT id FROM outbound_routes WHERE id = ?", (edit_route_id,)).fetchone()
                if existing is None:
                    payload = routes_page_payload(conn)
                    return templates.TemplateResponse(
                        "routes.html",
                        {
                            "request": request,
                            "user": user,
                            **payload,
                            "message": None,
                            "error": f"Outbound route {edit_route_id} not found for edit.",
                        },
                    )
                conn.execute(
                    """
                    UPDATE outbound_routes
                    SET name = ?, dial_pattern = ?, match_mode = ?, trunk_name = ?, enabled = ?
                    WHERE id = ?
                    """,
                    (
                        route_name,
                        dial_value,
                        mode_value,
                        trunk_value,
                        1 if as_bool(enabled) else 0,
                        edit_route_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO outbound_routes(name, dial_pattern, match_mode, trunk_name, enabled, created_at)
                    VALUES(?,?,?,?,?,?)
                    """,
                    (
                        route_name,
                        dial_value,
                        mode_value,
                        trunk_value,
                        1 if as_bool(enabled) else 0,
                        datetime.now(UTC).isoformat(),
                    ),
                )
            conn.commit()
            payload = routes_page_payload(conn)

        sync_outbound_routes_dialplan()
        return templates.TemplateResponse(
            "routes.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": (
                    f"Dialplan {'updated' if (edit_route_id and edit_kind == 'outbound') else 'saved'}: "
                    f"outbound {dial_value} (trunk: {trunk_value})"
                ),
                "error": None,
            },
        )

    cc_digits = re.sub(r"\D+", "", (country_code or "").strip()) or "1"
    dst_digits = re.sub(r"\D+", "", (destination_number or "").strip())
    if not dst_digits:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Destination number is required for inbound dialplan file type.",
            },
        )
    did_value = dst_digits if dst_digits.startswith(cc_digits) else f"{cc_digits}{dst_digits}"

    app_key = (application or "").strip().lower()
    app_map = {
        "queue": "queue",
        "fax in": "fax",
        "fax_in": "fax",
        "fax": "fax",
        "vpbx": "vpbx",
        "conference": "conference",
    }
    dest_type = app_map.get(app_key)
    if dest_type is None:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Applications must be one of: queue, fax in, vPBX, conference.",
            },
        )

    dest_value = (action_value or "").strip()
    if dest_type in {"queue", "vpbx", "conference"} and not dest_value:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Action is required for the selected application.",
            },
        )
    if dest_type == "fax" and not dest_value:
        # Default fax action to DID if no explicit fax inbound DID chosen.
        dest_value = did_value
    with closing(db_conn()) as conn:
        trunk_filter = (inbound_trunk_name or "").strip()
        if trunk_filter:
            trunk = conn.execute(
                "SELECT name, direction, enabled FROM trunks WHERE name = ?",
                (trunk_filter,),
            ).fetchone()
            if trunk is None:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Inbound trunk {trunk_filter} does not exist.",
                    },
                )
            trunk_direction = normalize_trunk_direction(str(trunk["direction"] or "inbound"))
            if not bool(trunk["enabled"]) or trunk_direction not in {"inbound", "both"}:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Inbound trunk {trunk_filter} is not enabled for inbound usage.",
                    },
                )

        if dest_type == "queue":
            item = conn.execute("SELECT number FROM queues WHERE number = ?", (dest_value,)).fetchone()
            if item is None:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Queue {dest_value} does not exist.",
                    },
                )
        elif dest_type == "vpbx":
            item = conn.execute("SELECT extension FROM vpbx_extensions WHERE extension = ?", (dest_value,)).fetchone()
            if item is None:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"vPBX extension {dest_value} does not exist.",
                    },
                )
        elif dest_type == "conference":
            item = conn.execute(
                "SELECT room_number FROM conferences WHERE room_number = ? AND enabled = 1",
                (dest_value,),
            ).fetchone()
            if item is None:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Conference room {dest_value} does not exist or is disabled.",
                    },
                )
        elif dest_type == "fax":
            item = conn.execute(
                "SELECT did FROM fax_routes WHERE direction = 'inbound' AND did = ?",
                (dest_value,),
            ).fetchone()
            if item is None:
                # Keep fax routing usable even if Fax In page has not been configured.
                dest_value = did_value

        route_name = f"Dialplan In {did_value} -> {dest_type}:{dest_value}"
        if edit_route_id and edit_kind == "inbound":
            existing = conn.execute("SELECT id FROM inbound_routes WHERE id = ?", (edit_route_id,)).fetchone()
            if existing is None:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Inbound route {edit_route_id} not found for edit.",
                    },
                )
            conn.execute(
                """
                UPDATE inbound_routes
                SET name = ?, did_pattern = ?, match_mode = ?, inbound_trunk_name = ?,
                    destination_type = ?, destination_value = ?, enabled = ?
                WHERE id = ?
                """,
                (
                    route_name,
                    did_value,
                    "exact",
                    trunk_filter,
                    dest_type,
                    dest_value,
                    1 if as_bool(enabled) else 0,
                    edit_route_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO inbound_routes(
                    name, did_pattern, match_mode, inbound_trunk_name, destination_type, destination_value, enabled, created_at
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    route_name,
                    did_value,
                    "exact",
                    trunk_filter,
                    dest_type,
                    dest_value,
                    1 if as_bool(enabled) else 0,
                    datetime.now(UTC).isoformat(),
                ),
            )
        conn.commit()
        payload = routes_page_payload(conn)

    sync_inbound_routes_dialplan()
    return templates.TemplateResponse(
        "routes.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": (
                f"Dialplan {'updated' if (edit_route_id and edit_kind == 'inbound') else 'saved'}: inbound {did_value} "
                f"{'(all trunks)' if not trunk_filter else f'(trunk: {trunk_filter})'} "
                f"-> {dest_type} {dest_value}"
            ),
            "error": None,
        },
    )


@app.post("/routes/inbound", response_class=HTMLResponse)
def inbound_route_create(
    request: Request,
    name: str = Form(...),
    did_pattern: str = Form(...),
    match_mode: str = Form("exact"),
    inbound_trunk_name: str = Form(""),
    destination_type: str = Form(...),
    destination_value: str = Form(""),
    enabled: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    mode = normalize_match_mode(match_mode)
    dest_type = (destination_type or "").strip().lower()
    if dest_type not in {"queue", "device", "fax", "vpbx", "conference"}:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {"request": request, "user": user, **payload, "message": None, "error": "Invalid inbound destination type."},
        )
    route_name = name.strip() or f"Inbound {did_pattern.strip()}"
    did_value = did_pattern.strip()
    dest_value = destination_value.strip()
    trunk_filter = inbound_trunk_name.strip()
    if not did_value:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {"request": request, "user": user, **payload, "message": None, "error": "Inbound DID/pattern is required."},
        )
    if dest_type != "fax" and not dest_value:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Destination value is required for queue/device/vPBX/conference routes.",
            },
        )

    with closing(db_conn()) as conn:
        if trunk_filter:
            trunk = conn.execute(
                "SELECT direction FROM trunks WHERE name = ? AND enabled = 1",
                (trunk_filter,),
            ).fetchone()
            if trunk is None:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Inbound trunk ID {trunk_filter} does not exist or is disabled.",
                    },
                )
            trunk_direction = normalize_trunk_direction(str(trunk["direction"] or "both"))
            if trunk_direction not in {"inbound", "both"}:
                payload = routes_page_payload(conn)
                return templates.TemplateResponse(
                    "routes.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Trunk {trunk_filter} is not enabled for inbound usage.",
                    },
                )
        conn.execute(
            """
            INSERT INTO inbound_routes(
                name, did_pattern, match_mode, inbound_trunk_name, destination_type, destination_value, enabled, created_at
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                route_name,
                did_value,
                mode,
                trunk_filter,
                dest_type,
                dest_value,
                1 if as_bool(enabled) else 0,
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()
        payload = routes_page_payload(conn)

    sync_inbound_routes_dialplan()
    return templates.TemplateResponse(
        "routes.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Inbound route {route_name} saved.",
            "error": None,
        },
    )


@app.post("/routes/outbound", response_class=HTMLResponse)
def outbound_route_create(
    request: Request,
    name: str = Form(...),
    dial_pattern: str = Form(...),
    match_mode: str = Form("prefix"),
    trunk_name: str = Form(...),
    enabled: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    route_name = name.strip() or f"Outbound {dial_pattern.strip()}"
    dial_value = dial_pattern.strip()
    trunk_value = trunk_name.strip()
    mode = normalize_match_mode(match_mode, outbound=True)
    if not dial_value or not trunk_value:
        with closing(db_conn()) as conn:
            payload = routes_page_payload(conn)
        return templates.TemplateResponse(
            "routes.html",
            {"request": request, "user": user, **payload, "message": None, "error": "Dial pattern and trunk are required."},
        )

    with closing(db_conn()) as conn:
        trunk = conn.execute(
            "SELECT name, direction FROM trunks WHERE name = ?",
            (trunk_value,),
        ).fetchone()
        if trunk is None:
            payload = routes_page_payload(conn)
            return templates.TemplateResponse(
                "routes.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": f"Selected trunk {trunk_value} does not exist. Create trunk first.",
                },
            )
        trunk_direction = normalize_trunk_direction(str(trunk["direction"] or "both"))
        if trunk_direction not in {"outbound", "both"}:
            payload = routes_page_payload(conn)
            return templates.TemplateResponse(
                "routes.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": f"Selected trunk {trunk_value} is not enabled for outbound usage.",
                },
            )
        conn.execute(
            """
            INSERT INTO outbound_routes(name, dial_pattern, match_mode, trunk_name, enabled, created_at)
            VALUES(?,?,?,?,?,?)
            """,
            (
                route_name,
                dial_value,
                mode,
                trunk_value,
                1 if as_bool(enabled) else 0,
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()
        payload = routes_page_payload(conn)

    sync_outbound_routes_dialplan()
    return templates.TemplateResponse(
        "routes.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Outbound route {route_name} saved.",
            "error": None,
        },
    )


@app.get("/fax", response_class=HTMLResponse)
def fax_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        payload = fax_page_payload(conn)
    return templates.TemplateResponse(
        "fax.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": None,
            "send_result": None,
        },
    )


@app.post("/fax/inbound", response_class=HTMLResponse)
def fax_inbound_create(
    request: Request,
    did: str = Form(...),
    email: str = Form(""),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT INTO fax_routes(direction, did, email, enabled, created_at)
            VALUES('inbound', ?, ?, 1, ?)
            """,
            (did.strip(), email.strip(), datetime.now(UTC).isoformat()),
        )
        conn.commit()
    sync_fax_inbound_dialplan()
    return RedirectResponse(url="/fax", status_code=303)


@app.post("/fax/outbound", response_class=HTMLResponse)
def fax_outbound_create(
    request: Request,
    destination_number: str = Form(...),
    gateway: str = Form(...),
    file_path: str = Form(""),
    file_upload: UploadFile | None = File(default=None),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    source_path = (file_path or "").strip()
    if file_upload is not None and (file_upload.filename or "").strip():
        try:
            source_path = save_uploaded_fax_file(file_upload)
        except Exception as exc:
            with closing(db_conn()) as conn:
                inbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC").fetchall()
                outbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'outbound' ORDER BY id DESC").fetchall()
                trunks = conn.execute(
                    "SELECT name, proxy, direction FROM trunks WHERE enabled = 1 AND direction IN ('outbound', 'both') ORDER BY name"
                ).fetchall()
            return templates.TemplateResponse(
                "fax.html",
                {
                    "request": request,
                    "user": user,
                    "inbound": inbound,
                    "outbound": outbound,
                    "outbound_trunks": trunks,
                    "message": f"Upload failed: {exc}",
                    "send_result": None,
                },
            )
    if not source_path:
        with closing(db_conn()) as conn:
            inbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC").fetchall()
            outbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'outbound' ORDER BY id DESC").fetchall()
            trunks = conn.execute(
                "SELECT name, proxy, direction FROM trunks WHERE enabled = 1 AND direction IN ('outbound', 'both') ORDER BY name"
            ).fetchall()
        return templates.TemplateResponse(
            "fax.html",
            {
                "request": request,
                "user": user,
                "inbound": inbound,
                "outbound": outbound,
                "outbound_trunks": trunks,
                "message": "Please upload a file or provide a file path.",
                "send_result": None,
            },
        )

    with closing(db_conn()) as conn:
        trunk_name = gateway.strip()
        trunk = conn.execute(
            "SELECT name, direction, outbound_prefix, proxy FROM trunks WHERE name = ? AND enabled = 1",
            (trunk_name,),
        ).fetchone()
        if trunk is None:
            inbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC").fetchall()
            outbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'outbound' ORDER BY id DESC").fetchall()
            trunks = conn.execute(
                "SELECT name, proxy, direction FROM trunks WHERE enabled = 1 AND direction IN ('outbound', 'both') ORDER BY name"
            ).fetchall()
            return templates.TemplateResponse(
                "fax.html",
                {
                    "request": request,
                    "user": user,
                    "inbound": inbound,
                    "outbound": outbound,
                    "outbound_trunks": trunks,
                    "message": f"Selected trunk {trunk_name} does not exist or is disabled.",
                    "send_result": None,
                },
            )
        trunk_direction = normalize_trunk_direction(str(trunk["direction"] or "outbound"))
        if trunk_direction not in {"outbound", "both"}:
            inbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC").fetchall()
            outbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'outbound' ORDER BY id DESC").fetchall()
            trunks = conn.execute(
                "SELECT name, proxy, direction FROM trunks WHERE enabled = 1 AND direction IN ('outbound', 'both') ORDER BY name"
            ).fetchall()
            return templates.TemplateResponse(
                "fax.html",
                {
                    "request": request,
                    "user": user,
                    "inbound": inbound,
                    "outbound": outbound,
                    "outbound_trunks": trunks,
                    "message": f"Selected trunk {trunk_name} is not outbound-enabled.",
                    "send_result": None,
                },
            )
        fax_target_number = apply_outbound_trunk_prefix(destination_number.strip(), str(trunk["outbound_prefix"] or ""))
        conn.execute(
            """
            INSERT INTO fax_routes(
                direction, destination_number, gateway, file_path, enabled,
                send_status, failure_reason, last_result, last_attempt_at, created_at
            )
            VALUES('outbound', ?, ?, ?, 1, 'pending', '', '', '', ?)
            """,
            (destination_number.strip(), trunk_name, source_path, datetime.now(UTC).isoformat()),
        )
        fax_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.commit()
        row = conn.execute(
            "SELECT * FROM fax_routes WHERE id = ? AND direction = 'outbound'",
            (fax_id,),
        ).fetchone()
        inbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC").fetchall()
        outbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'outbound' ORDER BY id DESC").fetchall()
        trunks = conn.execute(
            "SELECT name, proxy, direction FROM trunks WHERE enabled = 1 AND direction IN ('outbound', 'both') ORDER BY name"
        ).fetchall()

    if row is None:
        return templates.TemplateResponse(
            "fax.html",
            {
                "request": request,
                "user": user,
                "inbound": inbound,
                "outbound": outbound,
                "outbound_trunks": trunks,
                "message": "Fax job not found after save.",
                "send_result": None,
            },
        )

    try:
        fax_file = prepare_outbound_fax_file(str(row["file_path"] or ""), int(row["id"]))
    except Exception as exc:
        with closing(db_conn()) as conn:
            update_fax_send_status(
                conn,
                int(row["id"]),
                status="failed",
                reason=f"Conversion failed: {exc}",
                result=f"conversion_error: {exc}",
            )
            conn.commit()
            payload = fax_page_payload(conn)
        return templates.TemplateResponse(
            "fax.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": f"Outbound fax file error: {exc}",
                "send_result": None,
            },
        )

    cmd = build_fax_bgapi_originate(
        str(row["gateway"] or ""),
        fax_target_number,
        fax_file,
        str(trunk["proxy"] or ""),
    )
    result = fs_cli(cmd)
    status, reason = classify_fax_command_result(result)
    with closing(db_conn()) as conn:
        update_fax_send_status(
            conn,
            int(row["id"]),
            status=status,
            reason=reason,
            result=result,
        )
        conn.commit()
        payload = fax_page_payload(conn)
    return templates.TemplateResponse(
        "fax.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": "Fax send command queued." if status == "success" else "Fax send command failed.",
            "send_result": result,
        },
    )


@app.post("/fax/outbound/send", response_class=HTMLResponse)
def fax_outbound_send(
    request: Request,
    fax_id: int = Form(...),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT * FROM fax_routes WHERE id = ? AND direction = 'outbound'",
            (fax_id,),
        ).fetchone()
        trunk = None
        if row is not None:
            trunk = conn.execute(
                "SELECT name, direction, enabled, outbound_prefix, proxy FROM trunks WHERE name = ?",
                (str(row["gateway"] or "").strip(),),
            ).fetchone()
        inbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'inbound' ORDER BY id DESC").fetchall()
        outbound = conn.execute("SELECT * FROM fax_routes WHERE direction = 'outbound' ORDER BY id DESC").fetchall()
        trunks = conn.execute(
            "SELECT name, proxy, direction FROM trunks WHERE enabled = 1 AND direction IN ('outbound', 'both') ORDER BY name"
        ).fetchall()

    if row is None:
        return templates.TemplateResponse(
            "fax.html",
            {
                "request": request,
                "user": user,
                "inbound": inbound,
                "outbound": outbound,
                "outbound_trunks": trunks,
                "message": "Fax job not found",
                "send_result": None,
            },
        )
    if trunk is None:
        with closing(db_conn()) as conn:
            update_fax_send_status(
                conn,
                int(row["id"]),
                status="failed",
                reason=f"Trunk not found: {row['gateway']}",
                result="trunk_not_found",
            )
            conn.commit()
            payload = fax_page_payload(conn)
        return templates.TemplateResponse(
            "fax.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": f"Outbound trunk {row['gateway']} not found.",
                "send_result": None,
            },
        )
    trunk_direction = normalize_trunk_direction(str(trunk["direction"] or "outbound"))
    if not bool(trunk["enabled"]) or trunk_direction not in {"outbound", "both"}:
        with closing(db_conn()) as conn:
            update_fax_send_status(
                conn,
                int(row["id"]),
                status="failed",
                reason=f"Trunk not outbound-enabled: {row['gateway']}",
                result="trunk_not_outbound_enabled",
            )
            conn.commit()
            payload = fax_page_payload(conn)
        return templates.TemplateResponse(
            "fax.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": f"Outbound trunk {row['gateway']} is not enabled for outbound.",
                "send_result": None,
            },
        )
    fax_target_number = apply_outbound_trunk_prefix(str(row["destination_number"] or ""), str(trunk["outbound_prefix"] or ""))

    try:
        fax_file = prepare_outbound_fax_file(str(row["file_path"] or ""), int(row["id"]))
    except Exception as exc:
        with closing(db_conn()) as conn:
            update_fax_send_status(
                conn,
                int(row["id"]),
                status="failed",
                reason=f"Conversion failed: {exc}",
                result=f"conversion_error: {exc}",
            )
            conn.commit()
            payload = fax_page_payload(conn)
        return templates.TemplateResponse(
            "fax.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": f"Outbound fax file error: {exc}",
                "send_result": None,
            },
        )

    cmd = build_fax_bgapi_originate(
        str(row["gateway"] or ""),
        fax_target_number,
        fax_file,
        str(trunk["proxy"] or ""),
    )
    result = fs_cli(cmd)
    status, reason = classify_fax_command_result(result)
    with closing(db_conn()) as conn:
        update_fax_send_status(
            conn,
            int(row["id"]),
            status=status,
            reason=reason,
            result=result,
        )
        conn.commit()
        payload = fax_page_payload(conn)
    return templates.TemplateResponse(
        "fax.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": "Outbound fax send command queued." if status == "success" else "Outbound fax send failed.",
            "send_result": result,
        },
    )


@app.get("/conference", response_class=HTMLResponse)
def conference_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        payload = conference_page_payload(conn)
    return templates.TemplateResponse(
        "conference.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": None,
            "error": None,
            "send_result": "",
            "control_result": "",
        },
    )


@app.post("/conference", response_class=HTMLResponse)
def conference_create(
    request: Request,
    room_number: str = Form(...),
    display_name: str = Form(...),
    pin: str = Form(""),
    moderator_pin: str = Form(""),
    max_members: int = Form(50),
    record: str = Form("false"),
    enabled: str = Form("true"),
    profile_mode: str = Form("open"),
    dtmf_profile: str = Form("default"),
    muted_on_entry: str = Form("false"),
    entry_tone: str = Form(""),
    exit_tone: str = Form(""),
    sample_rate: int = Form(48000),
    energy_level: int = Form(20),
    auto_outcall_numbers: str = Form(""),
    auto_outcall_trunk: str = Form(""),
    video_layout: str = Form("speaker"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        log_security_event(
            request,
            "conference_manage_unauthorized",
            severity="high",
            details="Unauthorized conference create/update attempt",
        )
        maybe_block_request_ip_for_event(
            request,
            event_type="conference_manage_unauthorized",
            reason_prefix="Repeated unauthorized conference management",
        )
        return denied
    room = (room_number or "").strip()
    name = (display_name or "").strip()
    if not room or not name:
        with closing(db_conn()) as conn:
            payload = conference_page_payload(conn)
        return templates.TemplateResponse(
            "conference.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Room Number and Display Name are required.",
                "send_result": "",
                "control_result": "",
            },
        )
    pin_value = sanitize_conference_pin(pin)
    mod_pin_value = sanitize_conference_pin(moderator_pin)
    profile_value = sanitize_conference_mode(profile_mode)
    dtmf_value = re.sub(r"[^0-9A-Za-z_.-]", "", (dtmf_profile or "default").strip()) or "default"
    entry_tone_value = (entry_tone or "").strip()
    exit_tone_value = (exit_tone or "").strip()
    sample_rate_value = sanitize_conference_sample_rate(sample_rate)
    energy_value = sanitize_conference_energy_level(energy_level)
    room_auto_numbers = ",".join(parse_outcall_numbers(auto_outcall_numbers))
    room_auto_trunk = (auto_outcall_trunk or "").strip()
    video_layout_value = (video_layout or "speaker").strip() or "speaker"
    max_members_value = max(2, min(int(max_members or 50), 1000))
    enabled_value = 1 if as_bool(enabled) else 0
    record_value = 1 if as_bool(record) else 0
    muted_value = 1 if as_bool(muted_on_entry) else 0
    with closing(db_conn()) as conn:
        if room_auto_trunk:
            trunk = conn.execute(
                """
                SELECT name
                FROM trunks
                WHERE name = ?
                  AND enabled = 1
                  AND LOWER(COALESCE(direction, 'both')) IN ('outbound', 'both')
                """,
                (room_auto_trunk,),
            ).fetchone()
            if trunk is None:
                payload = conference_page_payload(conn)
                return templates.TemplateResponse(
                    "conference.html",
                    {
                        "request": request,
                        "user": user,
                        **payload,
                        "message": None,
                        "error": f"Auto outcall trunk '{room_auto_trunk}' is not available for outbound.",
                        "send_result": "",
                        "control_result": "",
                    },
                )
        conn.execute(
            """
            INSERT OR REPLACE INTO conferences(
                room_number, display_name, pin, moderator_pin, max_members, record, enabled,
                profile_mode, dtmf_profile, muted_on_entry, entry_tone, exit_tone, sample_rate,
                energy_level, auto_outcall_numbers, auto_outcall_trunk, video_layout
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                room,
                name,
                pin_value or None,
                mod_pin_value or None,
                max_members_value,
                record_value,
                enabled_value,
                profile_value,
                dtmf_value,
                muted_value,
                entry_tone_value,
                exit_tone_value,
                sample_rate_value,
                energy_value,
                room_auto_numbers,
                room_auto_trunk,
                video_layout_value,
            ),
        )
        conn.commit()
        payload = conference_page_payload(conn)
    sync_conference_dialplan()
    return templates.TemplateResponse(
        "conference.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Conference room {room} saved.",
            "error": None,
            "send_result": "",
            "control_result": "",
        },
    )


@app.post("/conference/delete", response_class=HTMLResponse)
def conference_delete(request: Request, room_number: str = Form(...)):
    user, denied = require_admin_or_redirect(request)
    if denied:
        log_security_event(
            request,
            "conference_manage_unauthorized",
            severity="high",
            details="Unauthorized conference delete attempt",
        )
        maybe_block_request_ip_for_event(
            request,
            event_type="conference_manage_unauthorized",
            reason_prefix="Repeated unauthorized conference management",
        )
        return denied
    room = (room_number or "").strip()
    with closing(db_conn()) as conn:
        conn.execute("DELETE FROM conferences WHERE room_number = ?", (room,))
        conn.commit()
        payload = conference_page_payload(conn)
    sync_conference_dialplan()
    return templates.TemplateResponse(
        "conference.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Conference room {room} removed.",
            "error": None,
            "send_result": "",
            "control_result": "",
        },
    )


@app.post("/conference/control", response_class=HTMLResponse)
def conference_control(
    request: Request,
    room_number: str = Form(...),
    action: str = Form(...),
    member_id: str = Form(""),
    level: str = Form(""),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        log_security_event(
            request,
            "conference_control_unauthorized",
            severity="high",
            details="Unauthorized conference control attempt",
        )
        maybe_block_request_ip_for_event(
            request,
            event_type="conference_control_unauthorized",
            reason_prefix="Repeated unauthorized conference control",
        )
        return denied
    room = (room_number or "").strip()
    member = re.sub(r"\D+", "", (member_id or "").strip())
    action_key = (action or "").strip().lower()
    conf_name = f"{room}@default"
    command = ""
    if action_key in {"list", "lock", "unlock"}:
        command = f"conference {conf_name} {action_key}"
    elif action_key in {"mute", "unmute", "deaf", "undeaf", "kick"}:
        if not member:
            with closing(db_conn()) as conn:
                payload = conference_page_payload(conn)
            return templates.TemplateResponse(
                "conference.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": "Member ID is required for this action.",
                    "send_result": "",
                    "control_result": "",
                },
            )
        command = f"conference {conf_name} {action_key} {member}"
    elif action_key in {"volume_in", "volume_out", "energy"}:
        if not member:
            with closing(db_conn()) as conn:
                payload = conference_page_payload(conn)
            return templates.TemplateResponse(
                "conference.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": "Member ID is required for volume/energy actions.",
                    "send_result": "",
                    "control_result": "",
                },
            )
        try:
            level_int = int((level or "").strip())
        except ValueError:
            level_int = 1
        if action_key in {"volume_in", "volume_out"}:
            level_int = max(-10, min(level_int, 10))
        else:
            level_int = max(0, min(level_int, 180))
        command = f"conference {conf_name} {action_key} {member} {level_int}"
    else:
        with closing(db_conn()) as conn:
            payload = conference_page_payload(conn)
        return templates.TemplateResponse(
            "conference.html",
            {
                "request": request,
                "user": user,
                **payload,
                "message": None,
                "error": "Unsupported conference control action.",
                "send_result": "",
                "control_result": "",
            },
        )
    control_result = fs_cli(command)
    with closing(db_conn()) as conn:
        payload = conference_page_payload(conn)
    return templates.TemplateResponse(
        "conference.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": "Conference control command executed.",
            "error": None,
            "send_result": "",
            "control_result": control_result,
        },
    )


@app.post("/conference/outcall", response_class=HTMLResponse)
def conference_outcall(
    request: Request,
    room_number: str = Form(...),
    trunk_name: str = Form(""),
    numbers_csv: str = Form(""),
    role: str = Form("member"),
    muted: str = Form("false"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        log_security_event(
            request,
            "conference_invite_unauthorized",
            severity="high",
            details="Unauthorized conference outcall attempt",
        )
        maybe_block_request_ip_for_event(
            request,
            event_type="conference_invite_unauthorized",
            reason_prefix="Repeated unauthorized conference invite/outcall",
        )
        return denied
    room = (room_number or "").strip()
    selected_role = (role or "member").strip().lower()
    muted_join = as_bool(muted)
    with closing(db_conn()) as conn:
        room_row = conn.execute(
            "SELECT * FROM conferences WHERE room_number = ? AND enabled = 1",
            (room,),
        ).fetchone()
        if room_row is None:
            payload = conference_page_payload(conn)
            return templates.TemplateResponse(
                "conference.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": f"Conference room {room} is not found or disabled.",
                    "send_result": "",
                    "control_result": "",
                },
            )
        effective_trunk = (trunk_name or "").strip() or (room_row["auto_outcall_trunk"] or "").strip()
        trunk_row = conn.execute(
            """
            SELECT *
            FROM trunks
            WHERE name = ?
              AND enabled = 1
              AND LOWER(COALESCE(direction, 'both')) IN ('outbound', 'both')
            """,
            (effective_trunk,),
        ).fetchone()
        if trunk_row is None:
            payload = conference_page_payload(conn)
            return templates.TemplateResponse(
                "conference.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": f"Outbound trunk '{effective_trunk}' is not available.",
                    "send_result": "",
                    "control_result": "",
                },
            )
        requested_numbers = numbers_csv or str(room_row["auto_outcall_numbers"] or "")
        numbers = parse_outcall_numbers(requested_numbers)
        if not numbers:
            payload = conference_page_payload(conn)
            return templates.TemplateResponse(
                "conference.html",
                {
                    "request": request,
                    "user": user,
                    **payload,
                    "message": None,
                    "error": "Provide at least one outcall number.",
                    "send_result": "",
                    "control_result": "",
                },
            )
        flags: list[str] = []
        if selected_role == "moderator":
            flags.append("moderator")
        if muted_join:
            flags.append("mute")
        app_data = build_conference_app_data(room, str(room_row["pin"] or ""), flags)
        originate_results: list[str] = []
        for number in numbers:
            target = apply_outbound_trunk_prefix(number, str(trunk_row["outbound_prefix"] or ""))
            cmd = (
                "bgapi originate "
                "{ignore_early_media=true,"
                f"origination_caller_id_number={FAX_FIXED_FROM_NUMBER},"
                "origination_caller_id_name='Conference Invite'}"
                f"sofia/gateway/{effective_trunk}/{target} "
                f"&conference({app_data})"
            )
            result = fs_cli(cmd)
            originate_results.append(f"{number} -> {target}: {result}")
        payload = conference_page_payload(conn)
    return templates.TemplateResponse(
        "conference.html",
        {
            "request": request,
            "user": user,
            **payload,
            "message": f"Conference outcall command sent to {len(numbers)} participant(s).",
            "error": None,
            "send_result": "\n".join(originate_results),
            "control_result": "",
        },
    )


@app.get("/vpbx", response_class=HTMLResponse)
def vpbx_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        exts = conn.execute("SELECT * FROM vpbx_extensions ORDER BY extension").fetchall()
    return templates.TemplateResponse(
        "vpbx.html",
        {"request": request, "user": user, "extensions": exts, "message": None},
    )


@app.post("/vpbx/extensions", response_class=HTMLResponse)
def vpbx_extension_create(
    request: Request,
    extension: str = Form(...),
    display_name: str = Form(...),
    sip_password: str = Form(...),
    voicemail_enabled: str = Form("true"),
    context: str = Form("default"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO vpbx_extensions(extension, display_name, sip_password, voicemail_enabled, context, created_at)
            VALUES(?,?,?,?,?,?)
            """,
            (
                extension.strip(),
                display_name.strip(),
                sip_password.strip(),
                1 if voicemail_enabled.lower() == "true" else 0,
                context.strip() or "default",
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM vpbx_extensions WHERE extension = ?",
            (extension.strip(),),
        ).fetchone()
        exts = conn.execute("SELECT * FROM vpbx_extensions ORDER BY extension").fetchall()

    sync_extension_to_freeswitch(row["extension"], row["display_name"], row["sip_password"], row["context"])
    fs_cli("reloadxml")
    return templates.TemplateResponse(
        "vpbx.html",
        {"request": request, "user": user, "extensions": exts, "message": f"Extension {extension} saved and synced to FreeSWITCH."},
    )


@app.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    with closing(db_conn()) as conn:
        devices = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
    reg_text = registration_snapshot()
    device_rows = build_device_rows(request, devices, reg_text)
    return templates.TemplateResponse(
        "devices.html",
        {
            "request": request,
            "user": user,
            "devices": devices,
            "device_rows": device_rows,
            "reg_text": reg_text,
            "provision_base_url": f"{request_public_base_url(request)}/provision/<MAC>.cfg",
            "provision_server_url": f"{request_public_base_url(request)}/provision",
            "message": None,
            "error": None,
        },
    )


@app.post("/devices", response_class=HTMLResponse)
def devices_create(
    request: Request,
    device_id: str = Form(...),
    mac_address: str = Form(...),
    extension: str = Form(...),
    auth_username: str = Form(""),
    auth_password: str = Form(""),
    user_agent: str = Form(""),
    provision_vendor: str = Form("yealink"),
    provision_enabled: str = Form("true"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    ext_value = extension.strip()
    # Enforce user ID = extension for consistent provisioning/registration.
    auth_user_value = ext_value
    mac_norm = normalize_mac_address(mac_address)
    if not mac_norm:
        with closing(db_conn()) as conn:
            devices = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
        reg_text = registration_snapshot()
        return templates.TemplateResponse(
            "devices.html",
            {
                "request": request,
                "user": user,
                "devices": devices,
                "device_rows": build_device_rows(request, devices, reg_text),
                "reg_text": reg_text,
                "provision_base_url": f"{request_public_base_url(request)}/provision/<MAC>.cfg",
                "provision_server_url": f"{request_public_base_url(request)}/provision",
                "message": None,
                "error": "MAC address format is invalid. Use 12 hex digits (example: A1B2C3D4E5F6).",
            },
        )
    with closing(db_conn()) as conn:
        generated_password = False
        password_value = auth_password.strip()
        if not password_value:
            password_value = generate_alnum_password(12)
            generated_password = True
        auto_created_extension = False
        ext_row = conn.execute(
            "SELECT extension, display_name, context FROM vpbx_extensions WHERE extension = ?",
            (ext_value,),
        ).fetchone()
        if ext_row is None:
            conn.execute(
                """
                INSERT INTO vpbx_extensions(extension, display_name, sip_password, voicemail_enabled, context, created_at)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    ext_value,
                    f"Desk {ext_value}",
                    password_value,
                    1,
                    "default",
                    datetime.now(UTC).isoformat(),
                ),
            )
            ext_row = conn.execute(
                "SELECT extension, display_name, context FROM vpbx_extensions WHERE extension = ?",
                (ext_value,),
            ).fetchone()
            auto_created_extension = True
        existing_mac_owner = conn.execute(
            "SELECT device_id FROM devices WHERE mac_address = ? LIMIT 1",
            (mac_norm,),
        ).fetchone()
        if existing_mac_owner and str(existing_mac_owner["device_id"]) != device_id.strip():
            devices = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
            reg_text = registration_snapshot()
            return templates.TemplateResponse(
                "devices.html",
                {
                    "request": request,
                    "user": user,
                    "devices": devices,
                    "device_rows": build_device_rows(request, devices, reg_text),
                    "reg_text": reg_text,
                    "provision_base_url": f"{request_public_base_url(request)}/provision/<MAC>.cfg",
                    "provision_server_url": f"{request_public_base_url(request)}/provision",
                    "message": None,
                    "error": (
                        f"MAC {formatted_mac_address(mac_norm)} is already assigned to "
                        f"device {existing_mac_owner['device_id']}."
                    ),
                },
            )
        conn.execute(
            """
            INSERT OR REPLACE INTO devices(
                device_id, extension, auth_username, auth_password, user_agent,
                enabled, created_at, mac_address, provision_vendor, provision_enabled
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                device_id.strip(),
                ext_value,
                auth_user_value,
                password_value,
                user_agent.strip(),
                1,
                datetime.now(UTC).isoformat(),
                mac_norm,
                (provision_vendor or "yealink").strip().lower() or "yealink",
                1 if as_bool(provision_enabled) else 0,
            ),
        )
        conn.execute(
            "UPDATE vpbx_extensions SET sip_password = ? WHERE extension = ?",
            (password_value, ext_value),
        )
        conn.commit()
        devices = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
    sync_extension_to_freeswitch(
        str(ext_row["extension"] or "").strip(),
        str(ext_row["display_name"] or "").strip() or str(ext_row["extension"] or "").strip(),
        password_value,
        str(ext_row["context"] or "").strip() or "default",
    )
    fs_cli("reloadxml")
    reg_text = registration_snapshot()
    password_note = (
        f" Generated 12-char password: {password_value}"
        if generated_password
        else ""
    )
    extension_note = (
        f" Extension {ext_value} was auto-created in vPBX."
        if auto_created_extension
        else ""
    )
    return templates.TemplateResponse(
        "devices.html",
        {
            "request": request,
            "user": user,
            "devices": devices,
            "device_rows": build_device_rows(request, devices, reg_text),
            "reg_text": reg_text,
            "provision_base_url": f"{request_public_base_url(request)}/provision/<MAC>.cfg",
            "provision_server_url": f"{request_public_base_url(request)}/provision",
            "message": (
                f"Device {device_id} saved (user ID set to extension {ext_value}). "
                f"Provision URL ready for MAC {mac_norm}.{extension_note}{password_note}"
            ),
            "error": None,
        },
    )


@app.get("/provision/y000000000000.cfg", response_class=PlainTextResponse)
def provision_yealink_common_cfg():
    # Yealink phones request this base file when Server URL is set.
    return PlainTextResponse("#!version:1.0.0.1\n", status_code=200, media_type="text/plain; charset=utf-8")


@app.get("/provision/y000000000000.boot", response_class=PlainTextResponse)
def provision_yealink_boot():
    return PlainTextResponse("", status_code=200, media_type="text/plain; charset=utf-8")


@app.get("/provision/{mac_address}.cfg", response_class=PlainTextResponse)
def provision_mac_cfg(mac_address: str, request: Request):
    mac_norm = normalize_mac_address(mac_address)
    if not mac_norm:
        return PlainTextResponse("invalid_mac\n", status_code=400)

    with closing(db_conn()) as conn:
        device = conn.execute(
            """
            SELECT * FROM devices
            WHERE mac_address = ? AND enabled = 1 AND provision_enabled = 1
            LIMIT 1
            """,
            (mac_norm,),
        ).fetchone()
        if device is None:
            return PlainTextResponse("not_found\n", status_code=404)
        ext_row = conn.execute(
            "SELECT * FROM vpbx_extensions WHERE extension = ? LIMIT 1",
            (str(device["extension"] or "").strip(),),
        ).fetchone()

    vendor = str(device["provision_vendor"] or "yealink").strip().lower()
    if vendor not in {"yealink", "generic"}:
        vendor = "yealink"

    cfg = render_yealink_provision_cfg(device, ext_row, request)
    return PlainTextResponse(cfg, status_code=200, media_type="text/plain; charset=utf-8")


@app.get("/security", response_class=HTMLResponse)
def security_logs_page(request: Request):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    limit_raw = (request.query_params.get("limit") or "300").strip()
    try:
        limit = max(50, min(int(limit_raw), 1000))
    except ValueError:
        limit = 300

    message = (request.query_params.get("message") or "").strip()
    blocked_ip_query = (request.query_params.get("blocked_ip") or "").strip()
    blocked_ip_exact = normalize_ipv4(blocked_ip_query) if blocked_ip_query else ""
    blocked_lookup: dict[str, str] | None = None
    whitelist_ip_query = (request.query_params.get("whitelist_ip") or "").strip()

    with closing(db_conn()) as conn:
        rows = conn.execute(
            """
            SELECT created_at, event_type, severity, ip_address, username, method, path, details
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        if blocked_ip_query:
            blocked_ips = conn.execute(
                """
                SELECT ip_address, reason, source_event_type, block_count, first_blocked_at, last_blocked_at, last_seen_at
                FROM blocked_ips
                WHERE active = 1 AND ip_address LIKE ?
                ORDER BY last_blocked_at DESC
                """,
                (f"%{blocked_ip_query}%",),
            ).fetchall()
        else:
            blocked_ips = conn.execute(
                """
                SELECT ip_address, reason, source_event_type, block_count, first_blocked_at, last_blocked_at, last_seen_at
                FROM blocked_ips
                WHERE active = 1
                ORDER BY last_blocked_at DESC
                """
            ).fetchall()

        if blocked_ip_query:
            row = conn.execute(
                """
                SELECT ip_address, active, reason, first_blocked_at, last_blocked_at, unblocked_at
                FROM blocked_ips
                WHERE ip_address = ?
                LIMIT 1
                """,
                (blocked_ip_exact or blocked_ip_query,),
            ).fetchone()
            if row is None:
                blocked_lookup = {
                    "status": "never",
                    "text": f"{blocked_ip_query}: not found in block history.",
                }
            elif int(row["active"] or 0) == 1:
                blocked_lookup = {
                    "status": "blocked",
                    "text": f"{row['ip_address']} is currently BLOCKED.",
                }
            else:
                blocked_lookup = {
                    "status": "unblocked",
                    "text": f"{row['ip_address']} was blocked before but is currently unblocked.",
                }
        if whitelist_ip_query:
            whitelist_ips = conn.execute(
                """
                SELECT ip_address, note, created_by, created_at, updated_at
                FROM whitelist_ips
                WHERE active = 1 AND ip_address LIKE ?
                ORDER BY updated_at DESC
                """,
                (f"%{whitelist_ip_query}%",),
            ).fetchall()
        else:
            whitelist_ips = conn.execute(
                """
                SELECT ip_address, note, created_by, created_at, updated_at
                FROM whitelist_ips
                WHERE active = 1
                ORDER BY updated_at DESC
                """
            ).fetchall()

    return templates.TemplateResponse(
        "security.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "blocked_ips": blocked_ips,
            "limit": limit,
            "message": message,
            "blocked_ip_query": blocked_ip_query,
            "blocked_lookup": blocked_lookup,
            "whitelist_ips": whitelist_ips,
            "whitelist_ip_query": whitelist_ip_query,
        },
    )


@app.post("/security/unblock", response_class=HTMLResponse)
def security_unblock_ip(
    request: Request,
    ip_address: str = Form(...),
    return_to: str = Form("security"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    ip_text = normalize_ipv4(ip_address)
    if not ip_text:
        return RedirectResponse(url=security_redirect_url(return_to, "Invalid IP address"), status_code=303)

    removed = iptables_unblock_ip(ip_text)
    with closing(db_conn()) as conn:
        conn.execute(
            "UPDATE blocked_ips SET active = 0, unblocked_at = ? WHERE ip_address = ?",
            (datetime.now(UTC).isoformat(), ip_text),
        )
        conn.commit()

    log_system_security_event(
        "ip_unblocked_by_admin",
        severity="info",
        ip_address=ip_text,
        details=f"Unblocked by {user}; iptables_removed={removed}",
    )
    return RedirectResponse(url=security_redirect_url(return_to, f"Unblocked {ip_text}"), status_code=303)


@app.post("/security/block", response_class=HTMLResponse)
def security_block_ip(
    request: Request,
    ip_address: str = Form(...),
    reason: str = Form(""),
    return_to: str = Form("security"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    ip_text = normalize_ipv4(ip_address)
    if not ip_text:
        return RedirectResponse(url=security_redirect_url(return_to, "Invalid IP address"), status_code=303)
    try:
        if ipaddress.ip_address(ip_text).version != 4:
            return RedirectResponse(
                url=security_redirect_url(return_to, "Only IPv4 addresses are supported for firewall block"),
                status_code=303,
            )
    except ValueError:
        return RedirectResponse(url=security_redirect_url(return_to, "Invalid IP address"), status_code=303)

    reason_text = (reason or "").strip()[:255] or "Manual firewall block by admin"
    if not iptables_block_ip(ip_text):
        log_system_security_event(
            "ip_block_failed_by_admin",
            severity="medium",
            ip_address=ip_text,
            details=f"Block failed for {ip_text} requested by {user}",
        )
        return RedirectResponse(url=security_redirect_url(return_to, f"Failed to block {ip_text} on firewall"), status_code=303)

    now = datetime.now(UTC).isoformat()
    removed_from_whitelist = False
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT active FROM whitelist_ips WHERE ip_address = ? LIMIT 1",
            (ip_text,),
        ).fetchone()
        if row is not None and int(row["active"] or 0) == 1:
            conn.execute(
                "UPDATE whitelist_ips SET active = 0, updated_at = ? WHERE ip_address = ?",
                (now, ip_text),
            )
            removed_from_whitelist = True
        conn.commit()
    mark_ip_blocked(ip_text, reason_text, "admin_manual_block", now)
    log_system_security_event(
        "ip_blocked_by_admin",
        severity="high",
        ip_address=ip_text,
        details=(
            f"Blocked by {user}; reason={reason_text}; "
            f"removed_from_whitelist={'yes' if removed_from_whitelist else 'no'}"
        ),
    )

    message = f"Blocked {ip_text} on firewall"
    if removed_from_whitelist:
        message += " (removed from whitelist)"
    return RedirectResponse(url=security_redirect_url(return_to, message), status_code=303)


@app.post("/security/whitelist/add", response_class=HTMLResponse)
def security_whitelist_add(
    request: Request,
    ip_address: str = Form(...),
    note: str = Form(""),
    return_to: str = Form("security"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    ip_text = normalize_ipv4(ip_address)
    if not ip_text:
        return RedirectResponse(url=security_redirect_url(return_to, "Invalid IP address"), status_code=303)

    now = datetime.now(UTC).isoformat()
    note_text = (note or "").strip()[:255]
    removed = iptables_unblock_ip(ip_text)
    with closing(db_conn()) as conn:
        exists = conn.execute(
            "SELECT ip_address FROM whitelist_ips WHERE ip_address = ? LIMIT 1",
            (ip_text,),
        ).fetchone()
        if exists is None:
            conn.execute(
                """
                INSERT INTO whitelist_ips(ip_address, note, created_by, created_at, updated_at, active)
                VALUES(?,?,?,?,?,1)
                """,
                (ip_text, note_text, user or "", now, now),
            )
        else:
            conn.execute(
                """
                UPDATE whitelist_ips
                SET note = ?, created_by = ?, updated_at = ?, active = 1
                WHERE ip_address = ?
                """,
                (note_text, user or "", now, ip_text),
            )
        conn.execute(
            "UPDATE blocked_ips SET active = 0, unblocked_at = ? WHERE ip_address = ?",
            (now, ip_text),
        )
        conn.commit()
    log_system_security_event(
        "ip_whitelisted_by_admin",
        severity="info",
        ip_address=ip_text,
        details=f"Whitelisted by {user}; iptables_removed={removed}; note={note_text or '-'}",
    )
    return RedirectResponse(url=security_redirect_url(return_to, f"Whitelisted {ip_text}"), status_code=303)


@app.post("/security/whitelist/remove", response_class=HTMLResponse)
def security_whitelist_remove(
    request: Request,
    ip_address: str = Form(...),
    return_to: str = Form("security"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied
    ip_text = normalize_ipv4(ip_address)
    if not ip_text:
        return RedirectResponse(url=security_redirect_url(return_to, "Invalid IP address"), status_code=303)
    now = datetime.now(UTC).isoformat()
    with closing(db_conn()) as conn:
        conn.execute(
            "UPDATE whitelist_ips SET active = 0, updated_at = ? WHERE ip_address = ?",
            (now, ip_text),
        )
        conn.commit()
    log_system_security_event(
        "ip_whitelist_removed_by_admin",
        severity="info",
        ip_address=ip_text,
        details=f"Whitelist removed by {user}",
    )
    return RedirectResponse(url=security_redirect_url(return_to, f"Removed whitelist {ip_text}"), status_code=303)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = require_user(request)
    if not user:
        return redirect_login()
    with closing(db_conn()) as conn:
        if is_admin_user(user):
            users = conn.execute("SELECT username, created_at, updated_at FROM users ORDER BY username").fetchall()
        else:
            users = conn.execute(
                "SELECT username, created_at, updated_at FROM users WHERE username = ?",
                (user,),
            ).fetchall()
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "message": None,
            "error": None,
            "users": users,
            "can_manage_users": is_admin_user(user),
        },
    )


@app.post("/settings/password", response_class=HTMLResponse)
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    user = require_user(request)
    if not user:
        return redirect_login()
    with closing(db_conn()) as conn:
        if is_admin_user(user):
            users = conn.execute("SELECT username, created_at, updated_at FROM users ORDER BY username").fetchall()
        else:
            users = conn.execute(
                "SELECT username, created_at, updated_at FROM users WHERE username = ?",
                (user,),
            ).fetchall()

    if new_password != confirm_password:
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "message": None,
                "error": "New password mismatch",
                "users": users,
                "can_manage_users": is_admin_user(user),
            },
        )

    with closing(db_conn()) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
        if row is None:
            return templates.TemplateResponse(
                "settings.html",
                {
                    "request": request,
                    "user": user,
                    "message": None,
                    "error": "User not found",
                    "users": users,
                    "can_manage_users": is_admin_user(user),
                },
            )
        current_hash = hash_password(current_password, row["salt"])
        if not secrets.compare_digest(current_hash, row["password_hash"]):
            return templates.TemplateResponse(
                "settings.html",
                {
                    "request": request,
                    "user": user,
                    "message": None,
                    "error": "Current password invalid",
                    "users": users,
                    "can_manage_users": is_admin_user(user),
                },
            )
        new_salt = secrets.token_hex(16)
        new_hash = hash_password(new_password, new_salt)
        conn.execute(
            "UPDATE users SET salt = ?, password_hash = ?, updated_at = ? WHERE username = ?",
            (new_salt, new_hash, datetime.now(UTC).isoformat(), user),
        )
        conn.commit()

    with closing(db_conn()) as conn:
        if is_admin_user(user):
            users = conn.execute("SELECT username, created_at, updated_at FROM users ORDER BY username").fetchall()
        else:
            users = conn.execute(
                "SELECT username, created_at, updated_at FROM users WHERE username = ?",
                (user,),
            ).fetchall()
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "message": "Password updated successfully.",
            "error": None,
            "users": users,
            "can_manage_users": is_admin_user(user),
        },
    )


@app.post("/settings/users", response_class=HTMLResponse)
def create_user_account(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    user = require_user(request)
    if not user:
        return redirect_login()

    with closing(db_conn()) as conn:
        if is_admin_user(user):
            users = conn.execute("SELECT username, created_at, updated_at FROM users ORDER BY username").fetchall()
        else:
            users = conn.execute(
                "SELECT username, created_at, updated_at FROM users WHERE username = ?",
                (user,),
            ).fetchall()

    if not is_admin_user(user):
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "message": None,
                "error": "Only the admin account can create new users.",
                "users": users,
                "can_manage_users": False,
            },
        )

    username_norm = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username_norm):
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "message": None,
                "error": "Username must be 3-64 chars: letters, numbers, dot, underscore, hyphen.",
                "users": users,
                "can_manage_users": is_admin_user(user),
            },
        )
    if password != confirm_password:
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "message": None,
                "error": "New user password mismatch.",
                "users": users,
                "can_manage_users": is_admin_user(user),
            },
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "message": None,
                "error": "New user password must be at least 8 characters.",
                "users": users,
                "can_manage_users": is_admin_user(user),
            },
        )

    with closing(db_conn()) as conn:
        existing = conn.execute("SELECT username FROM users WHERE username = ?", (username_norm,)).fetchone()
        if existing is not None:
            users = conn.execute("SELECT username, created_at, updated_at FROM users ORDER BY username").fetchall()
            return templates.TemplateResponse(
                "settings.html",
                {
                    "request": request,
                    "user": user,
                    "message": None,
                    "error": f"Username {username_norm} already exists.",
                    "users": users,
                    "can_manage_users": is_admin_user(user),
                },
            )
        salt = secrets.token_hex(16)
        pw_hash = hash_password(password, salt)
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO users(username, salt, password_hash, created_at, updated_at) VALUES(?,?,?,?,?)",
            (username_norm, salt, pw_hash, now, now),
        )
        conn.commit()
        users = conn.execute("SELECT username, created_at, updated_at FROM users ORDER BY username").fetchall()

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "message": f"User {username_norm} created. They can now log in.",
            "error": None,
            "users": users,
            "can_manage_users": is_admin_user(user),
        },
    )


@app.post("/simulate-call")
def simulate_call(
    request: Request,
    queue_number: str = Form(...),
    caller_id: str = Form("4163501959"),
    destination_number: str = Form("4163501959"),
    source_ip: str = Form("69.90.209.70"),
):
    user, denied = require_admin_or_redirect(request)
    if denied:
        return denied

    load_platform()
    if queue_number not in platform.engine.queues:
        return RedirectResponse(url="/dashboard", status_code=303)

    call = platform.ingest_incoming_call(
        queue_number=queue_number,
        caller_id=caller_id,
        destination_number=destination_number,
        source_ip=source_ip,
    )
    platform.execute_cycle()
    if call.offered_agent_ids:
        platform.engine.answer_call(call.offered_agent_ids[0], call.call_id)
        platform.engine.complete_call(call.call_id, "simulated")
    platform.execute_cycle()
    return RedirectResponse(url="/dashboard", status_code=303)






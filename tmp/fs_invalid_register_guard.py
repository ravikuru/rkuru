#!/usr/bin/env python3
"""
Auto-block SIP scanners that attempt invalid (non-10-digit) usernames.

This script tails FreeSWITCH logs, tracks repeated invalid REGISTER attempts,
and inserts iptables DROP rules for offending source IPs.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import time
from collections import deque
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Auto-block invalid SIP REGISTER scans")
    p.add_argument(
        "--log-file",
        default="/usr/local/freeswitch/log/freeswitch.log",
        help="FreeSWITCH log file path",
    )
    p.add_argument(
        "--state-file",
        default="/var/lib/fs-guard/invalid-register-state.json",
        help="State file path",
    )
    p.add_argument(
        "--realm",
        default="204.29.213.58",
        help="Realm/IP to match inside Can't find user log entries",
    )
    p.add_argument(
        "--window-seconds",
        type=int,
        default=900,
        help="Sliding time window for invalid attempts",
    )
    p.add_argument(
        "--threshold",
        type=int,
        default=4,
        help="Block IP after this many invalid attempts in window",
    )
    p.add_argument(
        "--tail-lines-first-run",
        type=int,
        default=200000,
        help="How many lines to inspect on first run",
    )
    p.add_argument(
        "--max-new-blocks",
        type=int,
        default=100,
        help="Safety cap for new blocks per run",
    )
    p.add_argument(
        "--whitelist",
        default="127.0.0.1,204.29.213.58,142.198.198.72",
        help="Comma-separated IP whitelist",
    )
    return p.parse_args()


def run_iptables(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["iptables", *args],
        text=True,
        capture_output=True,
        check=False,
    )


def iptables_drop_exists(ip: str) -> bool:
    return run_iptables("-C", "INPUT", "-s", ip, "-j", "DROP").returncode == 0


def add_iptables_drop(ip: str) -> bool:
    if iptables_drop_exists(ip):
        return False
    # Insert at top of INPUT chain so block happens early.
    res = run_iptables("-I", "INPUT", "1", "-s", ip, "-j", "DROP")
    return res.returncode == 0


def is_ip_allowed(ip: str, whitelist: set[str]) -> bool:
    if ip in whitelist:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    )


def load_state(path: Path) -> dict:
    if not path.exists():
        return {
            "inode": None,
            "offset": 0,
            "bootstrapped": False,
            "ip_hits": {},
            "blocked_ips": [],
        }
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            raise ValueError("invalid state format")
        return data
    except Exception:
        return {
            "inode": None,
            "offset": 0,
            "bootstrapped": False,
            "ip_hits": {},
            "blocked_ips": [],
        }


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True))


def read_new_lines(
    log_path: Path, state: dict, tail_lines_first_run: int
) -> tuple[list[str], int, int]:
    st = log_path.stat()
    inode = int(st.st_ino)
    size = int(st.st_size)
    offset = int(state.get("offset", 0) or 0)
    bootstrapped = bool(state.get("bootstrapped", False))
    same_file = int(state.get("inode") or 0) == inode

    lines: list[str]
    if not same_file or offset > size:
        offset = 0

    with log_path.open("r", errors="ignore") as f:
        if offset == 0 and not bootstrapped:
            # First run: inspect only recent tail to avoid expensive full parse.
            lines = list(deque(f, maxlen=tail_lines_first_run))
        else:
            f.seek(offset)
            lines = f.readlines()
        new_offset = f.tell()

    return lines, int(new_offset), inode


def prune_hits(ip_hits: dict[str, list[float]], now: float, window: int) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    cutoff = now - window
    for ip, timestamps in ip_hits.items():
        keep = [float(t) for t in timestamps if float(t) >= cutoff]
        if keep:
            out[ip] = keep
    return out


def main() -> int:
    args = parse_args()
    log_path = Path(args.log_file)
    state_path = Path(args.state_file)
    whitelist = {ip.strip() for ip in args.whitelist.split(",") if ip.strip()}

    if not log_path.exists():
        print(f"log file not found: {log_path}")
        return 1

    state = load_state(state_path)
    now = time.time()

    lines, new_offset, inode = read_new_lines(
        log_path=log_path,
        state=state,
        tail_lines_first_run=args.tail_lines_first_run,
    )

    # Example line:
    # ... sofia_reg.c:3210 Can't find user [101@204.29.213.58] from 5.39.101.60
    regex = re.compile(
        rf"Can't find user \[([^@\]]+)@{re.escape(args.realm)}\] from "
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
    )

    ip_hits = prune_hits(
        {
            str(k): [float(v) for v in vals]
            for k, vals in (state.get("ip_hits") or {}).items()
        },
        now,
        args.window_seconds,
    )
    blocked_ips = set(str(ip) for ip in (state.get("blocked_ips") or []))

    invalid_seen = 0
    for line in lines:
        m = regex.search(line)
        if not m:
            continue
        user = m.group(1).strip()
        ip = m.group(2).strip()

        # Ignore valid 10-digit attempts.
        if user.isdigit() and len(user) == 10:
            continue
        # Ignore local/private/whitelisted sources.
        if is_ip_allowed(ip, whitelist):
            continue

        ip_hits.setdefault(ip, []).append(now)
        invalid_seen += 1

    ip_hits = prune_hits(ip_hits, now, args.window_seconds)

    new_blocks = 0
    for ip, hits in sorted(ip_hits.items(), key=lambda item: len(item[1]), reverse=True):
        if len(hits) < args.threshold:
            continue
        if ip in blocked_ips:
            # Ensure rule still exists after reboot/manual flush.
            if not iptables_drop_exists(ip):
                add_iptables_drop(ip)
            continue
        if new_blocks >= args.max_new_blocks:
            break
        if add_iptables_drop(ip):
            blocked_ips.add(ip)
            new_blocks += 1
            print(f"blocked {ip} invalid_attempts={len(hits)}")

    state["inode"] = inode
    state["offset"] = new_offset
    state["bootstrapped"] = True
    state["ip_hits"] = ip_hits
    state["blocked_ips"] = sorted(blocked_ips)
    save_state(state_path, state)

    print(
        f"processed_lines={len(lines)} invalid_seen={invalid_seen} "
        f"tracked_ips={len(ip_hits)} blocked_total={len(blocked_ips)} "
        f"new_blocks={new_blocks}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


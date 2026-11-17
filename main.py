from __future__ import annotations

import os
import ipaddress
import json
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


CONFIG_PATH = Path(os.getenv("SSH_CONFIG", Path(__file__).with_name("config.json")))
with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
    CONFIG = json.load(config_file)
HOOKS = CONFIG["webhooks"]
AUTH_LOG = Path(CONFIG.get("auth_log", "/var/log/auth.log"))
AUTH_LOG_CANDIDATES = [AUTH_LOG, Path("/var/log/secure")]
UPLOAD_DIRS = [Path(p).expanduser() for p in CONFIG.get("upload_dirs", [])]
POLL_SECONDS = max(1, int(CONFIG.get("poll_seconds", 2)))
running = True
BLOCKED_HOOKS: set[str] = set()
PROXY_LOOKUP_ENABLED = CONFIG.get("proxy_lookup_enabled", True)
PROXY_LOOKUP_TIMEOUT = max(1, float(CONFIG.get("proxy_lookup_timeout", 3)))
PROXY_RESULTS: dict[str, str] = {}

IP = r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,}"
ACCEPTED = re.compile(rf"Accepted \S+ for (\S+) from ({IP}) port (\d+)")
FAILED = re.compile(rf"Failed \S+ for (?:invalid user )?(\S+) from ({IP}) port (\d+)")
INVALID = re.compile(rf"Invalid user (\S+) from ({IP})")
DISCONNECTED = re.compile(rf"Disconnected from (?:authenticating )?user (\S+)(?:\s+({IP})\s+port\s+(\d+))?")
SESSION_CLOSE = re.compile(r"pam_unix\(sshd:session\): session closed for user (\S+)")


def check_proxy_vpn(ip: str) -> str:
    if ip in PROXY_RESULTS:
        return PROXY_RESULTS[ip]
    if not PROXY_LOOKUP_ENABLED:
        return "Lookup disabled"
    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            result = "No (non-public IP)"
        else:
            url = f"http://ip-api.com/json/{address}?fields=status,message,proxy"
            req = urllib.request.Request(url, headers={"User-Agent": "ssh-log-notifier/1.0"})
            with urllib.request.urlopen(req, timeout=PROXY_LOOKUP_TIMEOUT) as response:
                data = json.loads(response.read().decode("utf-8"))
            if data.get("status") != "success":
                raise ValueError(data.get("message", "lookup failed"))
            result = "Yes (proxy/VPN/Tor)" if data.get("proxy") else "No"
    except (ValueError, OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        result = f"Lookup unavailable ({str(exc)[:100]})"
    if not result.startswith("Lookup unavailable"):
        PROXY_RESULTS[ip] = result
    return result


def post(kind: str, fields: dict[str, str]) -> None:
    if kind in BLOCKED_HOOKS:
        return
    url = HOOKS.get(kind, "")
    if not url:
        print(f"No webhook configured for {kind}; event skipped", file=sys.stderr)
        return
    names = {"connect": "SSH connection", "disconnect": "SSH disconnection",
             "upload": "New file", "failure": "SSH login failed"}
    embed = {"title": names[kind], "fields": [
        {"name": key, "value": str(value)[:900], "inline": True}
        for key, value in fields.items() if value
    ]}
    payload = json.dumps({"embeds": [embed]}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "User-Agent": "ssh-log-notifier/1.0",
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"Sent {kind} notification to Discord (HTTP {response.status})", flush=True)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        print(f"Discord rejected {kind} notification with HTTP {exc.code}: {detail}", file=sys.stderr)
        if exc.code == 403:
            BLOCKED_HOOKS.add(kind)
            print(f"Disabled {kind} webhook for this run after HTTP 403 to prevent repeated rejected requests", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Could not send {kind} notification: {exc}", file=sys.stderr)


def log_reader():
    for path in dict.fromkeys(AUTH_LOG_CANDIDATES):
        try:
            if not path.is_file():
                continue
            f = path.open("r", encoding="utf-8", errors="replace")
            f.seek(0, os.SEEK_END)
            print(f"Following SSH authentication log: {path}", file=sys.stderr)
            break
        except OSError as exc:
            print(f"Cannot read {path}: {exc}", file=sys.stderr)
    else:
        f = None
    if f is not None:
        with f:
            while running:
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(POLL_SECONDS)
                    try:
                        if f.tell() > path.stat().st_size:
                            f.seek(0)
                    except OSError:
                        pass
        return
    cmd = ["journalctl", "--follow", "--lines=0", "--output=cat", "--identifier=sshd"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        print(f"Cannot start journalctl: {exc}", file=sys.stderr)
        return
    try:
        assert proc.stdout is not None
        print("Following SSH authentication messages with journalctl", file=sys.stderr)
        while running:
            line = proc.stdout.readline()
            if line:
                yield line
            else:
                if proc.poll() is not None:
                    error = proc.stderr.read() if proc.stderr else ""
                    print(f"journalctl stopped: {error.strip() or proc.returncode}", file=sys.stderr)
                    return
                time.sleep(0.2)
    finally:
        proc.terminate()


def watch_auth():
    sessions: dict[str, set[str]] = {}
    for line in log_reader():
        m = ACCEPTED.search(line)
        if m:
            user, ip, port = m.groups()
            print(f"Detected SSH connection for {user} from {ip}", flush=True)
            sessions.setdefault(user, set()).add(ip)
            post("connect", {"User": user, "Client IP": ip, "Source port": port})
            continue
        m = FAILED.search(line) or INVALID.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            print(f"Detected SSH login failure for {user} from {ip}", flush=True)
            proxy_status = check_proxy_vpn(ip)
            post("failure", {"User": user, "Client IP": ip, "Proxy/VPN/Tor": proxy_status})
            continue
        m = DISCONNECTED.search(line)
        if m:
            user, logged_ip, _port = m.groups()
            ips = sessions.get(user, set())
            ip = logged_ip or (next(iter(ips)) if len(ips) == 1 else "")
            print(f"Detected SSH disconnection for {user}" + (f" from {ip}" if ip else "; client IP unavailable"), flush=True)
            post("disconnect", {"User": user, "Client IP": ip})
            if ip:
                ips.discard(ip)
                if not ips:
                    sessions.pop(user, None)
            continue
        m = SESSION_CLOSE.search(line)
        if m:
            user = m.group(1)
            ips = sessions.get(user, set())
            ip = next(iter(ips)) if len(ips) == 1 else ""
            print(f"Detected SSH session close for {user}" + (f" from {ip}" if ip else "; client IP unavailable"), flush=True)
            post("disconnect", {"User": user, "Client IP": ip})
            if ip:
                ips.discard(ip)
                if not ips:
                    sessions.pop(user, None)


def scan_upload_dirs():
    if not UPLOAD_DIRS:
        return
    known: dict[Path, set[str]] = {}
    for root in UPLOAD_DIRS:
        try:
            known[root] = {str(p) for p in root.rglob("*") if p.is_file()}
        except OSError as exc:
            print(f"Cannot scan upload directory {root}: {exc}", file=sys.stderr)
            known[root] = set()
    while running:
        for root in UPLOAD_DIRS:
            try:
                now = {str(p) for p in root.rglob("*") if p.is_file()}
                for filename in sorted(now - known.setdefault(root, set())):
                    post("upload", {"File": Path(filename).name})
                known[root] = now
            except OSError as exc:
                print(f"Cannot scan upload directory {root}: {exc}", file=sys.stderr)
        time.sleep(POLL_SECONDS)


def stop(_signum, _frame):
    global running
    running = False


def main() -> None:
    if sys.platform != "linux":
        raise SystemExit("Run this service on the Linux VPS that runs OpenSSH.")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    import threading
    threading.Thread(target=watch_auth, daemon=True).start()
    if UPLOAD_DIRS:
        threading.Thread(target=scan_upload_dirs, daemon=True).start()
    while running:
        time.sleep(1)


if __name__ == "__main__":
    main()

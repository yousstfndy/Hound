from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

DEFAULT_UA = "Mozilla/5.0 (compatible; HoundRecon/0.1; +https://github.com/)"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_token(value: str) -> str:
    value = value.strip().lower().rstrip("/")
    if value.startswith("*."):
        value = value[2:]
    return value


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_lines(path: Path, values: list[str] | set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for value in sorted(set(values)):
            handle.write(f"{value}\n")


def append_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{now_iso()} | {message}\n")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def command_exists(command: str) -> bool:
    from shutil import which

    return which(command) is not None


def coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run_command(command: list[str], timeout: int, dry_run: bool = False) -> tuple[int, str, str]:
    if dry_run:
        return 0, "DRY-RUN: " + " ".join(command), ""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, coerce_text(result.stdout), coerce_text(result.stderr)
    except subprocess.TimeoutExpired as exc:
        return 124, coerce_text(exc.stdout), coerce_text(exc.stderr) or f"timeout after {timeout}s"
    except OSError as exc:
        return 127, "", str(exc)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "https://" + url
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not is_tracking_param(k)]
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path.rstrip("/") or "/",
            urlencode(query, doseq=True),
            "",
        )
    )


def is_tracking_param(name: str) -> bool:
    return name.lower().startswith("utm_") or name.lower() in {"fbclid", "gclid", "mc_cid", "mc_eid"}


class HostRateLimiter:
    def __init__(self, rate_per_second: float = 10.0) -> None:
        self.min_interval = 1.0 / max(rate_per_second, 0.1)
        self.last_seen: dict[str, float] = defaultdict(float)

    def wait(self, host: str) -> None:
        now = time.monotonic()
        elapsed = now - self.last_seen[host]
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_seen[host] = time.monotonic()


def safe_request(
    method: str,
    url: str,
    scope_engine: Any,
    *,
    timeout: int = 10,
    headers: dict[str, str] | None = None,
    ua: str = DEFAULT_UA,
    rate_limiter: HostRateLimiter | None = None,
    allow_redirects: bool = True,
) -> Any | None:
    import requests

    ok, reason = scope_engine.is_in_scope(url)
    if not ok:
        return None
    request_headers = {"User-Agent": ua}
    request_headers.update(headers or {})
    current = normalize_url(url)
    for _ in range(10):
        host = urlsplit(current).hostname or current
        if rate_limiter:
            rate_limiter.wait(host)
        response = requests.request(
            method,
            current,
            headers=request_headers,
            timeout=timeout,
            allow_redirects=False,
        )
        if not allow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        if not location:
            return response
        destination = urljoin(current, location)
        ok, redirect_reason = scope_engine.is_in_scope(destination)
        if not ok:
            scope_engine.audit(destination, "redirect_blocked", f"{current} -> {redirect_reason}")
            return None
        current = destination
    scope_engine.audit(current, "redirect_blocked", "redirect chain exceeded 10 hops")
    return None

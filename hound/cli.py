from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .install_deps import DependencyManager
from .modules import headers, idor_gen, input_map, js_mine, report, run_scope_check, subdomains
from .rich_compat import Console
from .scope import ScopeEngine
from .utils import append_log, ensure_dir

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="hound - modular bug bounty reconnaissance CLI")
    parser.add_argument("--scope", help="scope.txt file in Hound INI-like format")
    parser.add_argument("--module", default="scope_check", choices=["scope_check", "subdomains", "headers", "js_mine", "input_map", "idor_gen", "report"], help="module to run")
    parser.add_argument("--threads", type=int, default=20, help="HTTP worker threads")
    parser.add_argument("--rate", type=float, default=10.0, help="max requests per second per host")
    parser.add_argument("--timeout", type=int, default=300, help="subprocess timeout in seconds")
    parser.add_argument("--ua", default="Mozilla/5.0 (compatible; HoundRecon/0.1)", help="User-Agent for HTTP requests")
    parser.add_argument("--dry-run", action="store_true", help="print subprocess actions without executing them")
    parser.add_argument("--check-deps", action="store_true", help="force fresh dependency check")
    parser.add_argument("--confirm", action="store_true", help="skip interactive proceed prompt and allow conflict errors")
    parser.add_argument("--report", action="store_true", dest="write_report", help="write an extra markdown summary when supported")
    parser.add_argument("--input-file", help="input file for input_map or idor_gen")
    parser.add_argument("--target", help="override target output folder for modules that do not require scope")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_root = Path("hound_output")
    ensure_dir(output_root)
    deps = DependencyManager(output_root=output_root, force=args.check_deps, dry_run=args.dry_run)
    deps.run()

    scope_required = args.module in {"scope_check", "subdomains", "headers", "js_mine"}
    scope: ScopeEngine | None = None
    target = args.target or "manual"
    if scope_required:
        if not args.scope:
            console.print("[red]--scope is required for this module[/red]")
            return 2
        try:
            scope = ScopeEngine(args.scope, output_root=output_root)
        except Exception as exc:
            console.print(f"[red]Scope parsing failed:[/red] {exc}")
            return 2
        target = scope.primary_target()
        target_root = ensure_dir(output_root / target)
        append_log(target_root / "hound.log", f"launch module={args.module}")
        if not run_scope_check(scope, target_root, confirm=args.confirm):
            console.print("[yellow]Aborted before module execution.[/yellow]")
            return 1

    if args.module == "scope_check":
        return 0
    if args.module == "subdomains" and scope:
        subdomains(scope, output_root, args.threads, args.timeout, args.dry_run, args.ua)
    elif args.module == "headers" and scope:
        headers(scope, output_root, args.threads, args.timeout, args.ua, args.rate)
    elif args.module == "js_mine" and scope:
        js_mine(scope, output_root, args.threads, args.timeout, args.dry_run, args.ua, args.rate)
    elif args.module == "input_map":
        fields = load_fields(args.input_file)
        input_map(output_root, target, fields)
    elif args.module == "idor_gen":
        if not args.input_file:
            console.print("[red]--input-file is required for idor_gen[/red]")
            return 2
        idor_gen(output_root, target, Path(args.input_file))
    elif args.module == "report":
        report(output_root, target)
    return 0


def load_fields(input_file: str | None) -> list[str]:
    if input_file:
        values = Path(input_file).read_text(encoding="utf-8").splitlines()
    elif not sys.stdin.isatty():
        values = sys.stdin.read().splitlines()
    else:
        values = input("Field names, comma-separated: ").split(",")
    return [item.strip() for item in values if item.strip()]

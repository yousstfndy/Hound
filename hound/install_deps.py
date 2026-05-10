from __future__ import annotations

import importlib.util
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .rich_compat import Console, Table
from .utils import append_log, ensure_dir, read_json, write_json


GO_TOOLS = {
    "subfinder": ("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "-version", "subdomains"),
    "amass": ("github.com/owasp-amass/amass/v4/...@master", "-version", "subdomains"),
    "assetfinder": ("github.com/tomnomnom/assetfinder@latest", None, "subdomains"),
    "httpx": ("github.com/projectdiscovery/httpx/cmd/httpx@latest", "-version", "subdomains"),
    "gospider": ("github.com/jaeles-project/gospider@latest", "version", "js_mine"),
    "hakrawler": ("github.com/hakluke/hakrawler@latest", None, "js_mine"),
    "gau": ("github.com/lc/gau/v2/cmd/gau@latest", "--version", "js_mine"),
    "waybackurls": ("github.com/tomnomnom/waybackurls@latest", None, "js_mine"),
    "meg": ("github.com/tomnomnom/meg@latest", None, "headers"),
}

PIP_PACKAGES = {"requests": "requests", "rich": "rich", "pyyaml": "yaml"}


class DependencyManager:
    def __init__(self, output_root: str | Path = "hound_output", force: bool = False, dry_run: bool = False) -> None:
        self.output_root = Path(output_root)
        ensure_dir(self.output_root)
        self.cache_path = self.output_root / ".deps_cache.json"
        self.log_path = self.output_root / "hound.log"
        self.force = force
        self.dry_run = dry_run
        self.console = Console()
        self.os_name = self._detect_os()
        self.gopath_bin: str | None = None
        self.results: dict[str, dict[str, str]] = {}

    def run(self) -> dict[str, dict[str, str]]:
        cached = self._fresh_cache()
        if cached and not self.force:
            self.results = cached.get("tools", {})
            self.gopath_bin = cached.get("gopath_bin")
            if self.gopath_bin:
                os.environ["PATH"] += os.pathsep + self.gopath_bin
            self.print_table(cached=True)
            return self.results
        self._check_python()
        self._check_pip()
        self._check_go()
        self._check_go_tools()
        self._check_findomain()
        if not self.dry_run:
            self._write_cache()
        self.print_table()
        return self.results

    def _detect_os(self) -> str:
        if sys.platform.startswith("linux"):
            return "linux"
        if sys.platform == "darwin":
            return "darwin"
        if sys.platform.startswith("win"):
            return "win32"
        return sys.platform

    def _fresh_cache(self) -> dict | None:
        cache = read_json(self.cache_path)
        if not cache:
            return None
        try:
            checked = datetime.fromisoformat(cache["last_checked"])
        except (KeyError, ValueError):
            return None
        if datetime.now(timezone.utc) - checked < timedelta(hours=24):
            return cache
        return None

    def _check_python(self) -> None:
        version = platform.python_version()
        if sys.version_info < (3, 10):
            self.results["python"] = {"status": "FAIL", "version": version, "path": sys.executable, "used_by": "all modules"}
            self.print_table()
            raise SystemExit("Install Python 3.10+ from python.org or via your package manager")
        self.results["python"] = {"status": "ready", "version": version, "path": sys.executable, "used_by": "all modules"}

    def _check_pip(self) -> None:
        for package, import_name in PIP_PACKAGES.items():
            if importlib.util.find_spec(import_name):
                self.results[package] = {"status": "ready", "version": self._package_version(package), "path": "pip", "used_by": "all modules"}
                continue
            append_log(self.log_path, f"[INSTALLING] pip package {package}")
            if self.dry_run:
                self.results[package] = {"status": "skip", "version": "-", "path": "dry-run", "used_by": "all modules"}
                continue
            result = subprocess.run([sys.executable, "-m", "pip", "install", package], capture_output=True, text=True, check=False)
            append_log(self.log_path, f"pip install {package}: rc={result.returncode}")
            if result.returncode == 0 and importlib.util.find_spec(import_name):
                self.results[package] = {"status": "ready_new", "version": self._package_version(package), "path": "pip", "used_by": "all modules"}
            else:
                self.results[package] = {"status": "FAIL", "version": "-", "path": f"{sys.executable} -m pip install {package}", "used_by": "all modules"}
                raise SystemExit(f"Could not install {package}. Run: {sys.executable} -m pip install {package}")

    def _check_go(self) -> None:
        go = shutil.which("go")
        if not go and self.os_name == "win32":
            self.results["go"] = {"status": "skip", "version": "-", "path": "https://go.dev/dl/ or winget install GoLang.Go", "used_by": "tool installer"}
            self._print_windows_manuals()
            return
        if not go and self.os_name == "darwin" and not shutil.which("brew"):
            self.results["go"] = {"status": "FAIL", "version": "-", "path": "install Homebrew first", "used_by": "tool installer"}
            raise SystemExit("Install Homebrew from https://brew.sh/ to enable Mac auto-install.")
        if not go and self.os_name == "linux":
            installer = self._linux_go_install_command()
            if installer and not self.dry_run:
                append_log(self.log_path, "[INSTALLING] go")
                subprocess.run(installer, check=False)
            go = shutil.which("go")
        elif not go and self.os_name == "darwin":
            subprocess.run(["brew", "install", "go"], check=False)
            go = shutil.which("go")
        if not go:
            self.results["go"] = {"status": "skip", "version": "-", "path": "manual install required", "used_by": "tool installer"}
            return
        version = subprocess.run(["go", "version"], capture_output=True, text=True, check=False).stdout.strip()
        gopath = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True, check=False).stdout.strip()
        self.gopath_bin = str(Path(gopath) / "bin") if gopath else None
        if self.gopath_bin:
            os.environ["PATH"] += os.pathsep + self.gopath_bin
        parsed_version = re.search(r"go(\d+\.\d+)", version)
        status = "ready"
        if parsed_version and tuple(map(int, parsed_version.group(1).split("."))) < (1, 19):
            status = "skip"
        self.results["go"] = {"status": status, "version": version or "-", "path": go, "used_by": "tool installer"}

    def _linux_go_install_command(self) -> list[str] | None:
        if shutil.which("apt"):
            return ["sudo", "apt", "install", "-y", "golang-go"]
        if shutil.which("dnf"):
            return ["sudo", "dnf", "install", "-y", "golang"]
        if shutil.which("yum"):
            return ["sudo", "yum", "install", "-y", "golang"]
        return None

    def _check_go_tools(self) -> None:
        if self.results.get("go", {}).get("status") not in {"ready", "ready_new"}:
            for tool, (_, _, used_by) in GO_TOOLS.items():
                self.results[tool] = {"status": "skip", "version": "-", "path": "go unavailable", "used_by": used_by}
            return
        for tool, (package, version_flag, used_by) in GO_TOOLS.items():
            location = shutil.which(tool) or self._gopath_tool(tool)
            if not location and not self.dry_run:
                append_log(self.log_path, f"[INSTALLING] {tool} via go install {package}")
                result = subprocess.run(["go", "install", package], capture_output=True, text=True, timeout=120, check=False)
                append_log(self.log_path, f"go install {tool}: rc={result.returncode}")
                location = shutil.which(tool) or self._gopath_tool(tool)
                status = "ready_new" if location else "skip"
            else:
                status = "ready" if location else "skip"
            version = self._tool_version(tool, version_flag) if location and version_flag else "-"
            self.results[tool] = {"status": status, "version": version, "path": location or "missing", "used_by": used_by}

    def _check_findomain(self) -> None:
        location = shutil.which("findomain")
        if location:
            self.results["findomain"] = {"status": "ready", "version": self._tool_version("findomain", "--version"), "path": location, "used_by": "subdomains"}
            return
        if shutil.which("cargo") and not self.dry_run:
            result = subprocess.run(["cargo", "install", "findomain"], capture_output=True, text=True, timeout=300, check=False)
            append_log(self.log_path, f"cargo install findomain: rc={result.returncode}")
            location = shutil.which("findomain")
        if location:
            self.results["findomain"] = {"status": "ready_new", "version": self._tool_version("findomain", "--version"), "path": location, "used_by": "subdomains"}
        else:
            self.results["findomain"] = {"status": "skip", "version": "-", "path": "requires cargo or binary install", "used_by": "subdomains"}

    def _gopath_tool(self, tool: str) -> str | None:
        if not self.gopath_bin:
            return None
        suffix = ".exe" if self.os_name == "win32" else ""
        path = Path(self.gopath_bin) / f"{tool}{suffix}"
        return str(path) if path.exists() else None

    def _tool_version(self, tool: str, flag: str | None) -> str:
        if not flag:
            return "-"
        try:
            result = subprocess.run([tool, flag], capture_output=True, text=True, timeout=10, check=False)
            return (result.stdout or result.stderr).strip().splitlines()[0][:80] or "-"
        except Exception:
            return "-"

    def _package_version(self, package: str) -> str:
        try:
            from importlib.metadata import version

            return version(package)
        except Exception:
            return "-"

    def _write_cache(self) -> None:
        write_json(
            self.cache_path,
            {
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "os": self.os_name,
                "go_version": self.results.get("go", {}).get("version"),
                "gopath_bin": self.gopath_bin,
                "tools": self.results,
            },
        )

    def _print_windows_manuals(self) -> None:
        table = Table(title="Windows manual tool installation")
        table.add_column("Tool")
        table.add_column("Install hint")
        table.add_row("Go", "winget install GoLang.Go")
        table.add_row("Rust/findomain", "winget install Rustlang.Rustup, then cargo install findomain")
        table.add_row("Go recon tools", "Install Go first; Hound will print go install package names")
        self.console.print(table)

    def print_table(self, cached: bool = False) -> None:
        table = Table(title="Hound dependencies" + (" (cached)" if cached else ""))
        for column in ["Tool", "Status", "Version", "Location", "Used By"]:
            table.add_column(column)
        ready = skipped = failed = 0
        for tool, data in self.results.items():
            status = data.get("status", "-")
            if status in {"ready", "ready_new"}:
                ready += 1
                style = "green" if status == "ready" else "blue"
                label = "✓ ready"
            elif status == "FAIL":
                failed += 1
                style = "red"
                label = "✗ FAIL"
            else:
                skipped += 1
                style = "yellow"
                label = "✗ skip"
            table.add_row(tool, f"[{style}]{label}[/{style}]", data.get("version", "-"), data.get("path", "-"), data.get("used_by", "-"))
        self.console.print(table)
        self.console.print(f"{ready}/{len(self.results)} dependencies ready. {skipped} skipped. {failed} failed.")

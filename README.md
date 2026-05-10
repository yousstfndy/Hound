# Hound

`hound` is a modular Python CLI for bug bounty reconnaissance with scope enforcement at the center of every module.

```bash
python hound.py --scope scope.txt
python hound.py --scope scope.txt --module subdomains
python hound.py --scope scope.txt --module js_mine --threads 30
```

All output is written under:

```text
hound_output/{target}/{module}/
```

The scope engine logs every decision to `hound_output/scope_audit.log` and refuses to run target-fetching modules without a valid scope file.

## Modules

- `scope_check`: parse, validate, report, and write `scope_parsed.json`
- `subdomains`: run passive collectors, deduplicate, scope-filter, and resolve live hosts
- `headers`: fetch common paths across live hosts and flag rare or sensitive headers
- `js_mine`: collect, download, and analyze JavaScript URLs
- `input_map`: generate a manual testing checklist for input fields
- `idor_gen`: convert OpenAPI path parameters into curl targets and Burp payloads
- `report`: interactive markdown bug report wizard

## Dependency Behavior

`install_deps.py` runs on every launch. It caches checks for 24 hours in `hound_output/.deps_cache.json`; use `--check-deps` to force a fresh check. Missing external recon tools are skipped with warnings, so Python-native modules can still run.

Windows does not auto-install Go tools. Install Go manually, then rerun Hound.

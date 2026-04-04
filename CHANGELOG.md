# Changelog

## v0.3.0 (unreleased)

Complete architectural overhaul from single-file CLI to clean multi-package Go project.

### Highlights

- **8-package clean architecture** — `main.go` reduced from 2,989 lines to 7
- **7 output formats** — text, json, jsonl, summary, sections, coverage, table
- **Terminal color support** — ANSI colors with auto-detection (`--color auto|always|never`)
- **148 tests** across 5 packages with 166 real Android 16 VDEX integration tests
- **GitHub Actions CI** — lint, test, build (5 platforms), auto-release on tag

### New Features

- `--format table` — aligned columns with color-coded verifier status, coverage percentage, and warnings
- `--format summary` — one-line `key=value` output for CI gates (`status=ok coverage=100.0%`)
- `--format sections` — TSV for `awk`/`grep` pipelines
- `--format coverage` — byte coverage report only
- `--format jsonl` — compact single-line JSON for log collection
- `--color auto|always|never` — ANSI color with terminal auto-detection via `golang.org/x/term`
- Structured error diagnostics — 33 codes with severity, category, and human-readable messages
- DEX extractor interfaces — `FileWriter`, `NameRenderer`, `DexExtractor` for testability
- `Makefile` — `make all/build/test/lint/clean`, cross-compile, release strip, debug build

### Architecture Changes

```
Before:  main.go (2,989 lines, 53 functions, 0 packages)
After:   8 packages, 28 source files, 3,904 lines total

cmd/           791 lines  Cobra commands (6 files)
internal/
  binutil/      86 lines  Binary I/O primitives
  model/       490 lines  Shared types, constants, diagnostics (5 files)
  dex/         253 lines  DEX format parsing (4 files, VDEX-independent)
  parser/      815 lines  VDEX container parsing (7 files)
  modifier/    721 lines  Verifier section build/patch/compare
  extractor/   224 lines  DEX extraction (interface-driven)
  presenter/   517 lines  Output formatting + ANSI color (3 files)
```

No circular dependencies. Dependency flow: `cmd → parser/modifier/extractor/presenter → dex → binutil/model`.

### Bug Fixes

- **Verifier deps offset encoding** — offsets now section-absolute, matching ART runtime (`EncodeSetVector`/`DecodeSetVector`)
- **Section header parsing** — fixed off-by-12 bug that skipped TypeLookupTable section
- **Error context** — all dex/modifier/parser errors now include file offset, range, and package prefix
- **Flag scoping** — extract flags (`--extract-dex` etc.) no longer appear on `dump`/`version`/`modify` help
- **`SilenceErrors`** — stderr now shows error message before `os.Exit(1)`
- **`showVersion` duplication** — removed manual `--version` check, uses cobra built-in
- **dry-run message** — no longer prints "dry-run" when status is "failed"
- **duplicate error check** — replaced 16-line for-loops with `lo.Contains`
- **table SIZE column** — now hex (matching OFFSET column) instead of mixed decimal
- **Windows release** — `.exe` rename step added to packaging workflow

### Testing

```
148 tests, 0 failures

binutil     18 tests   100.0% coverage
parser      51 tests    88.9% coverage
modifier    30 tests    38.5% coverage
extractor    9 tests    81.3% coverage
cmd         35 tests    (e2e subprocess + 166 real VDEX integration)
```

### Documentation

- `README.md` — Quick Start, 8 real CLI output examples, 7 format examples, error examples
- `docs/architecture.md` — Mermaid dependency graph, sequence diagrams, package details
- `docs/vdex-format.md` — section-absolute offset fix, `--format` docs, diagnostic codes
- `ROADMAP.md` — 4-phase expansion plan (v0.3 stability → v1.0 ecosystem)

### CI/CD

- `ci.yml` — 5-job pipeline: lint, vet, fmt-check, test, build (5 platforms)
- `release.yml` — tag push → test → build → package → GitHub Release (auto release notes)
- `test-integration.yml` — 166 real VDEX files + per-package coverage report

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `spf13/cobra` | v1.8.1 | CLI framework |
| `samber/lo` | v1.53.0 | Functional collection utilities |
| `stretchr/testify` | v1.11.1 | Test assertions (test-only) |
| `golang.org/x/term` | v0.41.0 | Terminal detection for color |

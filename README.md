# vdexcli

[![CI](https://github.com/0xc0de1ab/vdexcli/actions/workflows/ci.yml/badge.svg)](https://github.com/0xc0de1ab/vdexcli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0xc0de1ab/vdexcli)](https://github.com/0xc0de1ab/vdexcli/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/0xc0de1ab/vdexcli)](https://goreportcard.com/report/github.com/0xc0de1ab/vdexcli)
[![Go Reference](https://pkg.go.dev/badge/github.com/0xc0de1ab/vdexcli/pkg/vdex.svg)](https://pkg.go.dev/github.com/0xc0de1ab/vdexcli/pkg/vdex)

**See every byte of an Android VDEX file.**
Parse, explain, extract, diff, and patch — from the CLI, as a Go library, or in the browser via WebAssembly.

한국어 문서: [README.ko.md](README.ko.md)

```
$ vdexcli explain app.vdex

offset     size  type        path                                value
---------- ----- ----------- ----------------------------------- ---------------------------
0x00000000     4  magic       vdex.header.magic                  "vdex"
0x00000004     4  bytes       vdex.header.version                "027\0"
0x00000008     4  uint32_le   vdex.header.num_sections           4
0x0000000c    12  bytes       vdex.section[0].header             kind=0 off=0x3c size=4
0x00000018    12  bytes       vdex.section[1].header             kind=1 off=0x40 size=112
...
0x000000cc     0  padding     <gap>                              —
coverage: 204/204 bytes (100.0%) — all bytes explained
```

---

## Contents

- [What is VDEX?](#what-is-vdex)
- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
  - [parse](#parse)
  - [explain](#explain)
  - [extract-dex](#extract-dex)
  - [modify](#modify)
  - [diff](#diff)
  - [dump](#dump)
- [Go Library API](#go-library-api)
- [WebAssembly Engine](#webassembly-engine)
- [Browser Demo](#browser-demo)
- [Install](#install)
- [Project Structure](#project-structure)
- [CI / Workflows](#ci--workflows)
- [Testing](#testing)
- [VDEX v027 Format Reference](#vdex-v027-format-reference)
- [Contributing](#contributing)

---

## What is VDEX?

VDEX (**V**erified **DEX**) is a binary container produced by the Android ART runtime during `dexpreopt`. It wraps one or more DEX files together with:

- **Verifier dependency data** — which classes ART verified and against what type hierarchy
- **Checksum table** — CRC32 fingerprint for each embedded DEX
- **Type lookup table** — hash table for fast class descriptor lookups

VDEX files live at `/data/dalvik-cache/` or inside `.dm` (`.vdex`-carrying DM format) on-device files. Understanding their structure is essential for:

- Auditing `dexpreopt` output in AOSP builds
- Researching ART verification behavior
- Building custom class-loader tooling

---

## Features

| Category | Capability |
|----------|-----------|
| **CLI** | `parse`, `explain`, `extract-dex`, `modify`, `diff`, `dump` |
| **Output formats** | `text`, `json`, `jsonl`, `summary`, `sections`, `coverage`, `table` |
| **Byte-level explain** | Every byte mapped to a named, typed, annotated field |
| **DEX decomposition** | `string_ids`, `type_ids`, `proto_ids`, `field_ids`, `method_ids`, `class_defs` individually resolved |
| **Go library** | `pkg/vdex` — importable public API (`ExplainBytes`, `ParseBytes`, ...) |
| **WebAssembly** | `wasm/` — runs in any browser, zero server-side dependencies |
| **Browser demo** | Drag-and-drop VDEX analyzer at `demo/index.html` |
| **AOSP-compatible** | Section-absolute offsets matching ART runtime encoding |
| **Diagnostics** | 34 error/warning codes with actionable hints |
| **Strict mode** | Pattern-filtered warnings treated as fatal for CI gating |
| **Verifier patching** | Replace or merge verifier-deps via JSON |
| **DEX extraction** | Pull embedded DEX files with customizable filename templates |
| **Diff** | Structural comparison; exit 0 = identical, 1 = different |

---

## Quick Start

```bash
# Install
go install github.com/0xc0de1ab/vdexcli@latest

# Parse — full structural dump
vdexcli parse app.vdex

# Explain — byte-level annotated field map
vdexcli explain app.vdex

# Query a specific byte offset
vdexcli explain --offset 0x3c app.vdex

# Extract embedded DEX files
vdexcli extract-dex app.vdex ./dex-out/

# Compare two builds
vdexcli diff before.vdex after.vdex

# Patch verifier dependencies
vdexcli modify --verifier-json patch.json in.vdex out.vdex
```

---

## CLI Usage

### parse

Parse the complete VDEX structure and display it in the chosen format.

```bash
vdexcli parse app.vdex                            # human-readable text (default)
vdexcli parse --json app.vdex                     # pretty-printed JSON
vdexcli parse --format jsonl app.vdex             # compact single-line JSON
vdexcli parse --format summary app.vdex           # one-line key=value for CI
vdexcli parse --format sections app.vdex          # TSV section table
vdexcli parse --format coverage app.vdex          # byte coverage only
vdexcli parse --format table --color never app.vdex  # aligned table
vdexcli parse --strict --strict-warn "re:(checksum|version)" app.vdex
```

**Sample output (text):**

```
file: app.vdex
size: 204 bytes
vdex magic="vdex" version="027" sections=4
sections:
  kind=kChecksumSection      (0) off=0x3c  size=0x4
  kind=kDexFileSection       (1) off=0x40  size=0x70
  kind=kVerifierDepsSection  (2) off=0xb0  size=0x1c
  kind=kTypeLookupTableSection (3) off=0xcc size=0x0
checksums: 1
  [0]=0xcafebabe
dex files: 1
  [0] off=0x40 size=0x70 magic="dex\n" ver="035" endian=little-endian file_size=112
       sha1=0000000000000000000000000000000000000000
       strings=0 types=0 protos=0 fields=0 methods=0 class_defs=3
verifier_deps: off=0xb0 size=0x1c
  [dex 0] verified=2 unverified=1 pairs=1 extra_strings=0
byte_coverage: 204/204 bytes (100.0%)
```

**Batch pipeline:**

```bash
for f in *.vdex; do vdexcli parse --format summary "$f"; done
# status=ok file=base.vdex size=524288 version=027 coverage=100.0% gaps=0
```

---

### explain

Map every byte of the VDEX file to a named, typed, annotated primitive field.
All bytes are accounted for — including padding and gaps.

```bash
vdexcli explain app.vdex                    # hex-dump table (text)
vdexcli explain --format json app.vdex      # full PrimitiveMap as JSON
vdexcli explain --offset 0x3c app.vdex      # field at specific byte offset
vdexcli explain --offset 60 app.vdex        # decimal offset also supported
vdexcli explain --offset 0x3c --json app.vdex  # single field as JSON
```

**DEX table decomposition** — each DEX embedded in the VDEX is decomposed into its constituent tables:

```
vdex.dex[0].string_ids[0].offset     → uint32_le  0x00000070
vdex.dex[0].type_ids[0]              → uint32_le  0x00000005
vdex.dex[0].proto_ids[0].shorty_idx  → uint32_le  0x00000001
vdex.dex[0].field_ids[0].class_idx   → uint16_le  0x0000
...
```

---

### extract-dex

Extract all embedded DEX files from a VDEX container.

```bash
vdexcli extract-dex app.vdex ./dex-out/
vdexcli extract-dex --json app.vdex ./out/
vdexcli extract-dex --extract-name-template "{base}_{index}_{checksum_hex}.dex" app.vdex ./out/
vdexcli extract-dex --extract-continue-on-error app.vdex ./out/
```

Template tokens: `{base}`, `{index}`, `{checksum}`, `{checksum_hex}`, `{offset}`, `{size}`

---

### modify

Patch the verifier-deps section via a JSON descriptor.

```bash
# Replace mode (default) — rebuild entire verifier section
vdexcli modify --verifier-json patch.json in.vdex out.vdex

# Merge mode — overlay on top of existing data
vdexcli modify --mode merge --verifier-json patch.json in.vdex out.vdex

# Dry run — validate patch without writing output
vdexcli modify --dry-run --json --verifier-json patch.json in.vdex out.vdex

# Read patch from stdin
cat patch.json | vdexcli modify --verifier-json - in.vdex out.vdex
```

**Patch JSON schema:**

```json
{
  "mode": "replace",
  "dexes": [{
    "dex_index": 0,
    "extra_strings": ["Ljava/lang/Object;"],
    "classes": [
      {"class_index": 0, "verified": true,  "pairs": [{"dest": 5, "src": 10}]},
      {"class_index": 1, "verified": false}
    ]
  }]
}
```

See [`samples/`](samples/) for example patch files.

---

### diff

Structurally compare two VDEX files. Exit code: `0` = identical, `1` = different.

```bash
vdexcli diff before.vdex after.vdex           # text with color
vdexcli diff --json before.vdex after.vdex    # JSON diff
vdexcli diff --format summary a.vdex b.vdex   # CI-friendly one-liner
```

**Example:**

```
VDEX diff
  A: before.vdex (204 bytes)
  B: after.vdex  (204 bytes)

verifier_deps: (2 classes changed)
  [dex 0] verified 2→0 (-2)  pairs 1→0 (-1)  extras 0→0

summary: sections=0 checksums=0 dexes=0 verifier=2 typelookup=0
```

---

### dump

Print the field-meaning dictionary embedded in the binary.

```bash
vdexcli dump                      # YAML meanings
vdexcli dump --format jsonl       # JSON for piping
```

---

## Global Flags

| Flag | Description |
|------|-------------|
| `-i, --in <path>` | Input VDEX path (alternative to positional argument) |
| `--format <mode>` | `text` \| `json` \| `jsonl` \| `summary` \| `sections` \| `coverage` \| `table` |
| `--json` | Shorthand for `--format json` |
| `--color <mode>` | `auto` (default) \| `always` \| `never` |
| `--strict` | Treat matched warnings as fatal (non-zero exit) |
| `--strict-warn <patterns>` | Comma-separated filters; prefix `re:` for regex |
| `--show-meaning` | Include field descriptions (default: `true`) |
| `--extract-dex <dir>` | Extract DEX files during parse |
| `--extract-name-template` | Filename template (default: `{base}_{index}_{checksum}.dex`) |
| `--extract-continue-on-error` | Skip failures and continue extracting |
| `-v, --version` | Print version and exit |

---

## Go Library API

`vdexcli` exposes a stable public API in [`pkg/vdex`](pkg/vdex/) that other Go projects can import directly.

```go
import "github.com/0xc0de1ab/vdexcli/pkg/vdex"
```

### Core functions

```go
// Byte-level annotated field map — every byte is accounted for.
// WASM-compatible (no filesystem access).
fm, err := vdex.ExplainBytes(data []byte) (*vdex.FieldMap, error)

// High-level structural report.
// WASM-compatible.
report, err := vdex.ParseBytes(data []byte, opts ...vdex.Option) (*vdex.Report, error)

// Convenience wrappers for non-WASM (desktop/server) builds.
fm, err     := vdex.ExplainFile(path string) (*vdex.FieldMap, error)
report, err := vdex.ParseFile(path string, opts ...vdex.Option) (*vdex.Report, error)
```

### Options

```go
vdex.WithMeanings()   // include human-readable field descriptions
vdex.WithDexPreview() // include DEX class preview in report
```

### Types

```go
// Field — a single annotated byte range.
type Field struct {
    Offset      uint32
    Size        uint32
    Type        FieldType     // "uint32_le", "magic", "bytes", "padding", ...
    RawBytes    []byte
    ParsedValue interface{}
    LogicalPath string        // e.g. "vdex.dex[0].string_ids[3].offset"
    Summary     string
    Description string
}

// FieldMap — complete annotated view of the VDEX file.
type FieldMap struct {
    Fields       []*Field
    TotalBytes   uint32
    UnmappedGaps []ByteRange
}

// Report — high-level parsed result.
type Report struct {
    File         string
    Header       *VdexHeader
    Sections     []SectionHeader
    Checksums    []uint32
    DexFiles     []DexInfo
    VerifierDeps *VerifierDepsInfo
    TypeLookup   *TypeLookupInfo
    Coverage     *CoverageReport
    Diagnostics  []Diagnostic
}
```

### Example

```go
package main

import (
    "fmt"
    "os"

    "github.com/0xc0de1ab/vdexcli/pkg/vdex"
)

func main() {
    data, _ := os.ReadFile("app.vdex")

    // Byte-level explain
    fm, err := vdex.ExplainBytes(data)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Total bytes: %d, Fields: %d\n", fm.TotalBytes, len(fm.Fields))
    for _, f := range fm.Fields[:5] {
        fmt.Printf("0x%08x  %-12s  %s\n", f.Offset, f.Type, f.LogicalPath)
    }

    // High-level parse
    report, _ := vdex.ParseBytes(data, vdex.WithMeanings())
    fmt.Printf("VDEX version: %d, DEX count: %d\n",
        report.Header.Version, report.Header.DexCount)
}
```

---

## WebAssembly Engine

The `wasm/` package compiles the full engine to WebAssembly using the standard Go toolchain (`GOOS=js GOARCH=wasm`). No TinyGo or code-gen hacks required.

### Build

```bash
GOOS=js GOARCH=wasm go build \
  -trimpath -ldflags="-s -w" \
  -o vdex.wasm ./wasm/

# Or via Makefile:
make demo
```

Output: `vdex.wasm` (~3.3 MB stripped)

### JavaScript API

```js
// Load runtime + WASM
const go = new Go();  // from wasm_exec.js
const result = await WebAssembly.instantiateStreaming(fetch("vdex.wasm"), go.importObject);
go.run(result.instance);

// Analyze a VDEX file (FileReader → Uint8Array → WASM)
const bytes = new Uint8Array(await file.arrayBuffer());

// Byte-level field map → { fields: [...], total_bytes: N, unmapped_gaps: [...] }
const fieldMap = window.vdex.explain(bytes);

// High-level structural report → { header: {...}, dex_files: [...], ... }
const report = window.vdex.parse(bytes);

// Engine version string
console.log(window.vdex.version);  // "v0.1.0"
```

### WASM bridge functions

| Function | Input | Output |
|----------|-------|--------|
| `window.vdex.explain(Uint8Array)` | Raw VDEX bytes | `{ fields, total_bytes, unmapped_gaps }` or `{ error }` |
| `window.vdex.parse(Uint8Array)` | Raw VDEX bytes | `VdexReport` object or `{ error }` |
| `window.vdex.version` | — | Version string |

Both functions are **synchronous** — no `async/await` needed on the JS side.

---

## Browser Demo

A fully client-side VDEX analyzer is included in `demo/`. No server required — the engine runs entirely inside the browser via WebAssembly.

### Run locally

```bash
# 1. Build the WASM binary and copy wasm_exec.js
make demo
# or: bash demo/build_demo.sh

# 2. Serve (any static file server works)
make demo-serve
# → http://localhost:8080

# Manual alternative:
cd demo && python3 -m http.server 8080
```

### Features

- **Drag-and-drop** or **file picker** to load any `.vdex` file
- **Explain tab** — complete byte-level field table with:
  - Offset, size, type badge, logical path, decoded value, hex preview
  - Filterable by path prefix and field type
  - Padding toggle, JSON copy button
  - Click any row for a full detail modal with complete hex dump
- **Parse tab** — high-level structural summary cards (header, sections, DEX files, verifier deps, coverage)
- **Coverage bar** — animated byte coverage indicator
- **100% client-side** — no file uploads, no analytics, no dependencies

> **Note:** Browsers require a proper HTTP server for WASM (`fetch` + `Content-Type: application/wasm`). Opening `index.html` directly via `file://` will not work.

---

## Diagnostics

Every warning and error carries a structured diagnostic with `severity`, `code`, `message`, and `hint`.

**Text output:**

```
section warnings (1):
  ! section kDexFileSection has zero size
    ~ this section is empty; normal for DM-format VDEX (no embedded DEX)
verifier warnings (1):
  ! dex 0: inferred class_def_count=246 from verifier section (DM format)
    ~ no embedded DEX; class count inferred from offset table heuristic
```

**JSON output:**

```json
{
  "severity": "warning",
  "category": "section",
  "code": "WARN_SECTION_ZERO_SIZE",
  "message": "section kDexFileSection has zero size",
  "hint": "this section is empty; normal for DM-format VDEX (no embedded DEX)"
}
```

**34 diagnostic codes** covering: truncated files, invalid magic, corrupted sections, broken LEB128, legacy version guards, type-lookup failures, and more.

**CI integration:**

```bash
# Fail only on checksum/verifier issues; ignore structural warnings
vdexcli parse --strict --strict-warn "re:(checksum|verifier)" app.vdex

# Extract all errors from JSON output
vdexcli parse --json app.vdex | jq '[.diagnostics[] | select(.severity == 0)]'

# Batch scan
for f in *.vdex; do
  errs=$(vdexcli parse --json "$f" | jq '[.diagnostics[] | select(.severity==0)] | length')
  [ "$errs" -gt 0 ] && echo "FAIL $f ($errs errors)"
done
```

---

## Install

### Via `go install` (recommended)

```bash
go install github.com/0xc0de1ab/vdexcli@latest
```

### Build from source

```bash
git clone https://github.com/0xc0de1ab/vdexcli.git
cd vdexcli
make build          # → build/<os>-<arch>/release/vdexcli
```

Available Make targets:

| Target | Description |
|--------|-------------|
| `make all` | fmt + vet + lint + test + build |
| `make build` | Release binary for current OS/arch |
| `make test` | Run full test suite |
| `make lint` | golangci-lint |
| `make fmt` | gofmt in-place |
| `make vet` | go vet + mod tidy check |
| `make demo` | Build WASM demo artifacts |
| `make demo-serve` | Build demo and serve at `localhost:8080` |
| `make clean` | Remove build artifacts |

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/0xc0de1ab/vdexcli/releases/latest):

```bash
# Verify checksum
sha256sum -c vdexcli-checksums.txt
```

Available platforms: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`

### Debug build

```bash
make build VARIANT=debug
```

---

## Project Structure

```
vdexcli/
├── main.go                          # Entry point (7 lines)
├── Makefile                         # Build, test, demo targets
├── cmd/                             # Cobra CLI commands
│   ├── root.go                      # Root command + global flags
│   ├── parse.go                     # parse subcommand
│   ├── explain.go                   # explain subcommand
│   ├── extract.go                   # extract-dex subcommand
│   ├── modify.go                    # modify subcommand
│   ├── diff.go                      # diff subcommand
│   ├── dump.go                      # dump subcommand
│   └── version.go                   # version subcommand
├── pkg/
│   └── vdex/                        # ★ Public Go library API
│       ├── api.go                   # ExplainBytes, ParseBytes
│       ├── api_fs.go                # ExplainFile, ParseFile (non-WASM)
│       ├── types.go                 # Field, FieldMap, Report, ...
│       ├── options.go               # WithMeanings, WithDexPreview
│       └── doc.go                   # Package documentation
├── wasm/
│   └── main.go                      # ★ WebAssembly entry point (syscall/js)
├── demo/                            # ★ Browser-based VDEX analyzer
│   ├── index.html                   # Single-page app
│   ├── style.css                    # Dark glassmorphism UI
│   ├── script.js                    # FileReader → WASM bridge + renderer
│   └── build_demo.sh                # Build WASM + copy wasm_exec.js
├── internal/
│   ├── binutil/                     # Low-level binary I/O (ReadU32, LEB128, ...)
│   ├── model/                       # Shared types, constants, diagnostics
│   ├── dex/                         # DEX format parsing (VDEX-independent)
│   ├── parser/                      # VDEX container parsing
│   │   ├── explain.go               # ExplainVdexBytes — byte-level field map
│   │   ├── explain_dex.go           # DEX table decomposition
│   │   ├── parser.go                # ParseVdexBytes — structural report
│   │   ├── verifier.go              # VerifierDeps parsing
│   │   ├── typelookup.go            # TypeLookup table parsing
│   │   └── legacy.go                # Legacy VDEX v021-v026 support
│   ├── modifier/                    # Verifier section build/patch/compare
│   ├── extractor/                   # DEX file extraction
│   └── presenter/                   # Output formatting + ANSI color
│       ├── color_terminal.go        # Terminal color support (!js build)
│       └── color_wasm.go            # No-op overrides for WASM build
├── .github/
│   └── workflows/
│       ├── ci.yml                   # [01] CI Build (7 jobs)
│       ├── release.yml              # Release pipeline
│       └── test-integration.yml     # 166-file VDEX integration test
├── docs/
│   ├── architecture.md              # Package diagram + design decisions
│   └── vdex-format.md              # VDEX v027 binary format reference
├── samples/                         # Example verifier patch JSON files
├── testdata/                        # Real VDEX files for integration tests
└── ROADMAP.md                       # Phased expansion plan
```

---

## CI / Workflows

### `[01] CI Build` — `ci.yml`

Triggers: **push to `main`** and **manual dispatch** (`workflow_dispatch`).

| Job | What it checks |
|-----|---------------|
| `fmt` | `gofmt` formatting |
| `vet` | `go mod tidy` drift · `go mod verify` · `go vet ./...` · `GOOS=js GOARCH=wasm go vet ./wasm/` |
| `lint` | `golangci-lint` (staticcheck, errcheck, ...) |
| `vulncheck` | `govulncheck` — CVE scan |
| `test` | `go test -v -count=1 ./...` · coverage ≥ 85% across all packages including `pkg/vdex/` |
| `build` | 5-platform matrix (linux/darwin/windows × amd64/arm64) + linux/amd64 smoke test |
| `build-wasm` | `GOOS=js GOARCH=wasm` build · uploads `vdex.wasm` artifact |

**Manual trigger:** GitHub → Actions → `[01] CI Build` → **Run workflow**

### `Release` — `release.yml`

Triggers: version tag `v*.*.*` or `workflow_dispatch`.
Produces: per-platform archives + SHA256 checksums + GitHub Release.

### `test-integration.yml`

Triggers: weekly (Monday 00:00 UTC), push to main, `workflow_dispatch`.
Runs: **166 real Android 16 VDEX files** through the full parser pipeline.

---

## Testing

```bash
go test -v ./...
# or
make test
```

| Package | Tests | Notes |
|---------|-------|-------|
| `cmd` | 35 | E2E subprocess tests for all commands and formats |
| `internal/binutil` | 18 | LEB128, alignment, encoding round-trips (100% coverage) |
| `internal/parser` | 51+ | Header, sections, verifier, typelookup, byte-level explain |
| `internal/modifier` | 30 | Patch parse/validate/build, atomic write |
| `internal/extractor` | 9 | Mock filesystem, interface verification |
| `pkg/vdex` | 14 | Public API stability, option validation, type aliases |
| **Integration** | 166 | Real Android 16 VDEX files (`android-16.0.0_r4`) |

**Coverage gate:** ≥ 85% across testable packages (enforced in CI).

---

## VDEX v027 Format Reference

Based on AOSP ART [`runtime/vdex_file.h`](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/vdex_file.h):

```
Offset   Size   Field
------   ----   -----
0x00       4    magic        "vdex"
0x04       4    version      "027\0"
0x08       4    num_sections (= 4)
0x0c    N×12    VdexSectionHeader[N]
                  ├ kind    uint32  (0=Checksum, 1=Dex, 2=VerifierDeps, 3=TypeLookup)
                  ├ offset  uint32  section start (absolute)
                  └ size    uint32  section length in bytes

Section 0  kChecksumSection         uint32[D] — CRC32 per embedded DEX
Section 1  kDexFileSection          Concatenated DEX payloads (empty in DM format)
Section 2  kVerifierDepsSection     Per-DEX verification dependency data
Section 3  kTypeLookupTableSection  Per-DEX class descriptor hash tables
```

Full field-level reference: [`docs/vdex-format.md`](docs/vdex-format.md)

---

## Performance

Measured on a single core (arm64), single VDEX file:

| File size | Parse time | Throughput |
|-----------|-----------|------------|
| 204 B | ~4 ms | instant |
| 5.6 KB | ~4 ms | instant |
| 178 KB (28 DEX) | ~13 ms | ~14 MB/s |

Batch: **166 files in 1.4 seconds** (including DM format class inference).

---

## Contributing

- [Bug reports](https://github.com/0xc0de1ab/vdexcli/issues/new?template=bug_report.md)
- [Feature requests](https://github.com/0xc0de1ab/vdexcli/issues/new?template=feature_request.md)
- [Discussions](https://github.com/0xc0de1ab/vdexcli/discussions)

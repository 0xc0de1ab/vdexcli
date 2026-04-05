# vdexcli

[![CI](https://github.com/0xc0de1ab/vdexcli/actions/workflows/ci.yml/badge.svg)](https://github.com/0xc0de1ab/vdexcli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0xc0de1ab/vdexcli)](https://github.com/0xc0de1ab/vdexcli/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/0xc0de1ab/vdexcli)](https://goreportcard.com/report/github.com/0xc0de1ab/vdexcli)

See every byte of an Android VDEX file. Parse, extract, diff, and patch — from the command line.

```bash
$ vdexcli parse app.vdex
vdex magic="vdex" version="027" sections=4
  kChecksumSection      off=0x3c   size=4
  kDexFileSection       off=0x40   size=112
  kVerifierDepsSection  off=0xb0   size=28
verifier_deps:
  [dex 0] verified=246 unverified=87 pairs=565 extras=7
byte_coverage: 2256/2256 bytes (100.0%)
```

## Quick Start

```bash
go install github.com/0xc0de1ab/vdexcli@latest

vdexcli parse app.vdex                    # full structural dump
vdexcli parse --json app.vdex             # machine-readable JSON
vdexcli extract-dex app.vdex ./out/       # pull embedded DEX files
vdexcli diff before.vdex after.vdex       # compare two builds
vdexcli modify --verifier-json patch.json in.vdex out.vdex  # patch verifier deps
```

## Features

- **Parse** — Headers, sections, checksums, DEX files, verifier deps, type lookup tables — with byte-level coverage
- **Extract** — Pull embedded DEX files for disassembly with jadx/baksmali
- **Modify** — Patch verifier-deps section via JSON (replace or merge mode)
- **Diff** — Structural comparison of two VDEX files (exit 0=identical, 1=different)
- **Diagnostics** — 34 error/warning codes with [actionable hints](#diagnostics-with-actionable-hints)
- **7 output formats** — text, json, jsonl, summary, sections, coverage, table
- **ART-compatible** — Section-absolute offsets matching AOSP ART runtime encoding

More: [output examples](#example-output), [CI integration](#diagnostics-with-actionable-hints), [error handling](#error-handling).

### Use Cases

- **AOSP build verification** — scan all VDEX files after `dexpreopt` to confirm 100% byte coverage and no parse errors
- **Verifier patching** — selectively mark classes as verified/unverified for testing ART behavior
- **DEX extraction** — pull embedded DEX files from VDEX containers for disassembly with `jadx`/`baksmali`
- **CI/CD integration** — `--format summary` provides a single parseable line for automated checks
- **Pre/post comparison** — `vdexcli diff` detects structural changes between VDEX builds

### Performance

Measured on a single core (arm64), single VDEX file:

| File size | Parse time | Throughput |
|-----------|-----------|------------|
| 204 B | ~4 ms | instant |
| 5.6 KB | ~4 ms | instant |
| 178 KB (28 dex) | ~13 ms | ~14 MB/s |

Batch scan: **166 files in 1.4 seconds** (including DM format class inference).

## Example Output

### Parsing a VDEX with embedded DEX

```
$ vdexcli parse --show-meaning=false app.vdex

file: app.vdex
size: 204 bytes
vdex magic="vdex" version="027" sections=4
sections:
  kind=kChecksumSection (0) off=0x3c size=0x4
    DEX file location checksum list (one uint32 per input dex)
  kind=kDexFileSection (1) off=0x40 size=0x70
    Concatenated DEX file payload
  kind=kVerifierDepsSection (2) off=0xb0 size=0x1c
    Verifier dependency section
  kind=kTypeLookupTableSection (3) off=0xcc size=0x0
    Class descriptor lookup table section
checksums: 1
  [0]=0xcafebabe
dex files: 1
  [0] off=0x40 size=0x70 magic="dex\n" ver="035" endian=little-endian file_size=112 header=112
     sha1=0000000000000000000000000000000000000000 checksum=0xcafebabe
     strings=0(@0x0) types=0(@0x0) protos=0(@0x0) fields=0(@0x0) methods=0(@0x0) class_defs=3(@0x0)
verifier_deps: off=0xb0 size=0x1c
  [dex 0] verified=2 unverified=1 pairs=1 extra_strings=0
    class 0: string_5(5) -> string_10(10)
type_lookup: off=0xcc size=0x0
byte_coverage: 204/204 bytes (100.0%)
  0x00000000..0x0000000c      12 bytes  vdex_header
  0x0000000c..0x0000003c      48 bytes  section_headers
  0x0000003c..0x00000040       4 bytes  kChecksumSection
  0x00000040..0x000000b0     112 bytes  kDexFileSection
  0x000000b0..0x000000cc      28 bytes  kVerifierDepsSection
```

### Pipeline: batch scan with summary

```
$ for f in *.vdex; do vdexcli parse --format summary "$f"; done

status=ok  file=base.vdex  size=524288 version=027 sections=4 checksums=3 dexes=3 warnings=0 errors=0 coverage=100.0% gaps=0
status=warn file=app.vdex   size=204    version=027 sections=4 checksums=1 dexes=1 warnings=2 errors=0 coverage=100.0% gaps=0
```

### Pipeline: find non-empty sections with awk

```
$ vdexcli parse --format sections app.vdex | awk -F'\t' 'NR>1 && $4>0 {printf "%-30s %s bytes\n", $2, $4}'

kChecksumSection               4 bytes
kDexFileSection                112 bytes
kVerifierDepsSection           28 bytes
```

### Pipeline: coverage check

```
$ vdexcli parse --format coverage app.vdex

file=app.vdex size=204 parsed=204 unparsed=0 coverage=100.00%
  0x00000000      12  vdex_header
  0x0000000c      48  section_headers
  0x0000003c       4  kChecksumSection
  0x00000040     112  kDexFileSection
  0x000000b0      28  kVerifierDepsSection
```

### Extracting DEX files

```
$ vdexcli extract-dex app.vdex ./dex-out/
extracted 1 dex files to ./dex-out/

$ ls ./dex-out/
app.vdex_0_3405691582.dex
```

### Modifying verifier deps (dry run)

```
$ cat patch.json
{"dexes":[{"dex_index":0,"classes":[
  {"class_index":0,"verified":false},
  {"class_index":1,"verified":false},
  {"class_index":2,"verified":false}]}]}

$ vdexcli modify --dry-run --verifier-json patch.json app.vdex out.vdex
modify summary: mode=replace patch_dexes=1 patch_classes=3 patch_extra_strings=0
modify diff: classes=3 modified=2 unchanged=1 change=66.67%
modify changed dexes: [0]
modify changed class samples: dex=0 classes=[0 2]
modify status: ok
verifier section size: old=28 new=24 delta=-4
modify output: dry-run (no file written)

$ vdexcli modify --dry-run --format json --verifier-json patch.json app.vdex out.vdex \
    | jq '{status, modified_classes, class_change_percent}'
{
  "status": "ok",
  "modified_classes": 2,
  "class_change_percent": 66.66666666666666
}
```

### Table format with color

```
$ vdexcli parse --format table --color never app.vdex

VDEX vdex  v027  204 bytes

  KIND  NAME                              OFFSET        SIZE
  ----  ----------------------------  ----------  ----------
     0  kChecksumSection                    0x3c           4
     1  kDexFileSection                     0x40         112
     2  kVerifierDepsSection                0xb0          28
     3  kTypeLookupTableSection             0xcc           0

checksums: 1
  [0] 0xcafebabe

dex files: 1
  [0] dex\n035 off=0x40 size=112 endian=little-endian sha1=00000000000000000000...
       strings=0 types=0 protos=0 fields=0 methods=0 class_defs=3

verifier_deps: off=0xb0 size=28
  [dex 0] verified=2 unverified=1 pairs=1 extras=0

coverage: 204/204 bytes (100.0%)

warnings: 2
  ! section kind 3 has zero size
  ! type-lookup section truncated before dex 0
```

When output is a terminal, fields are color-coded: green for verified, yellow for warnings, red for errors. Use `--color always` to force colors in pipes.

### Comparing two VDEX files

```
$ vdexcli diff original.vdex modified.vdex

VDEX diff
  A: original.vdex (204 bytes)
  B: modified.vdex (204 bytes)

verifier_deps: (2 classes changed)
  [dex 0] verified 2→0 (-2)  pairs 1→0 (-1)  extras 0→0

summary: sections=0 checksums=0 dexes=0 verifier=2 typelookup=0

$ vdexcli diff --format json original.vdex modified.vdex | jq '.summary'
{
  "identical": false,
  "sections_changed": 0,
  "checksums_changed": 0,
  "dex_files_changed": 0,
  "verifier_classes_changed": 2,
  "type_lookup_entries_changed": 0
}
```

### Strict mode

```
# Passes: no warnings match the pattern
$ vdexcli parse --strict --strict-warn "checksum" --format summary app.vdex
status=warn file=app.vdex size=204 version=027 ... coverage=100.0% gaps=0
$ echo $?
0

# Fails: all warnings matched (no --strict-warn filter = match all)
$ vdexcli parse --strict --format summary app.vdex
strict mode: 2 matching warning(s): [section kind 3 has zero size type-lookup section truncated before dex 0]
$ echo $?
1
```

### Diagnostics with actionable hints

Every warning and error includes a diagnostic code and a hint explaining what went wrong and what to do next. Warnings use `!` (yellow), hints use `~` (dim).

**Text output:**

```
$ vdexcli parse old-android10.vdex

section warnings (1):
  ! section kDexFileSection has zero size
    ~ this section is empty; normal for DM-format VDEX (no embedded DEX)
verifier warnings (1):
  ! dex 0: inferred class_def_count=246 from verifier section (DM format)
    ~ no embedded DEX; class count inferred from offset table heuristic — verify against source APK
```

**JSON output** — each diagnostic has `severity`, `code`, `message`, `hint`:

```
$ vdexcli parse --json old-android10.vdex | jq '.diagnostics[0]'
{
  "severity": 1,
  "category": "section",
  "code": "WARN_SECTION_ZERO_SIZE",
  "message": "section kDexFileSection has zero size",
  "hint": "this section is empty; normal for DM-format VDEX (no embedded DEX)"
}
```

Severity values: `0` = error (fatal), `1` = warning (parsing continues). Codes prefixed `ERR_` are errors, `WARN_` are warnings.

34 diagnostic codes cover every parser failure mode — truncated files, invalid magic, corrupted sections, broken LEB128, and more. Each code maps to an actionable hint so you know whether to re-extract, check your input, or safely ignore. See [`internal/model/errors.go`](internal/model/errors.go) for the full code list.

**CI integration** — filter diagnostics by code in pipelines:

```bash
# Fail CI only on checksum/verifier warnings, ignore section zero-size
vdexcli parse --strict --strict-warn "re:(checksum|verifier)" app.vdex

# Extract specific diagnostic codes from JSON
vdexcli parse --json app.vdex | jq '[.diagnostics[] | select(.code | startswith("ERR_"))]'

# Batch scan: flag files with errors
for f in *.vdex; do
  errs=$(vdexcli parse --json "$f" | jq '[.diagnostics[] | select(.severity==0)] | length')
  [ "$errs" -gt 0 ] && echo "FAIL $f ($errs errors)"
done
```

### Error handling

```
$ vdexcli parse broken.vdex
errors (1):
  ! file too small for VDEX header: 11 bytes (need >= 12)
    ~ verify the file is a complete VDEX and not truncated during copy

$ vdexcli parse nonexistent.vdex
open nonexistent.vdex: no such file or directory

$ vdexcli parse
input vdex path is required (pass as argument or use --in)

$ vdexcli modify in.vdex out.vdex
--verifier-json is required

$ vdexcli modify --mode bogus --verifier-json p.json in.vdex out.vdex
unsupported --mode "bogus"; supported: replace, merge
```

## Install

```bash
go install github.com/0xc0de1ab/vdexcli@latest
```

Or build from source:

```bash
git clone https://github.com/0xc0de1ab/vdexcli.git
cd vdexcli
make build          # release binary in build/<os>-<arch>/release/
```

Available Make targets: `make all`, `make build`, `make test`, `make lint`, `make fmt`, `make vet`, `make clean`

Debug build: `make build VARIANT=debug`

## Commands

### parse

```bash
vdexcli parse app.vdex                    # text output (default)
vdexcli parse --json app.vdex             # JSON output
vdexcli parse --format jsonl app.vdex     # single-line JSON for log pipelines
vdexcli parse --format summary app.vdex   # one-line key=value for CI
vdexcli parse --format sections app.vdex  # TSV section table for awk/grep
vdexcli parse --format coverage app.vdex  # byte coverage only
vdexcli parse --format table app.vdex     # aligned table with color
vdexcli parse --extract-dex ./out app.vdex # extract DEX during parse
vdexcli parse --strict --strict-warn "re:(checksum|version)" app.vdex
```

**Output includes:**
- VDEX header (magic, version, section count)
- Section table with offsets/sizes for all 4 section types
- Per-DEX header fields (magic, version, SHA-1, all size/offset fields, class preview)
- Verifier dependencies (verified/unverified counts, assignability pairs, extra strings)
- Type lookup table statistics (bucket count, entries, chain lengths)
- Byte coverage report with gap detection

### extract-dex

```bash
vdexcli extract-dex app.vdex ./dex-output/
vdexcli extract-dex --json app.vdex ./out/
vdexcli extract-dex --extract-name-template "{base}_{index}_{checksum_hex}.dex" app.vdex ./out/
vdexcli extract-dex --extract-continue-on-error app.vdex ./out/
```

Tokens: `{base}`, `{index}`, `{checksum}`, `{checksum_hex}`, `{offset}`, `{size}`

### modify

```bash
# Replace mode (default) — rebuild entire verifier section
vdexcli modify --verifier-json patch.json input.vdex output.vdex

# Merge mode — overlay onto existing data
vdexcli modify --mode merge --verifier-json patch.json in.vdex out.vdex

# Dry run — validate without writing
vdexcli modify --dry-run --json --verifier-json patch.json in.vdex out.vdex

# Stdin + logging
cat patch.json | vdexcli modify --verifier-json - --log-file modify.log in.vdex out.vdex
```

**Patch JSON format:**

```json
{
  "mode": "replace",
  "dexes": [{
    "dex_index": 0,
    "extra_strings": ["Ljava/lang/Object;"],
    "classes": [
      {"class_index": 0, "verified": true, "pairs": [{"dest": 5, "src": 10}]},
      {"class_index": 1, "verified": false}
    ]
  }]
}
```

Sample patches: [`samples/`](samples/)

### dump

```bash
$ vdexcli dump | head -8
meanings:
  vdex_file:
    magic: Vdex header magic (must be 'vdex')
    version: Vdex format version, currently '027' expected
    sections: Section table entries for checksum, dex, verifier_deps, type_lookup
    checksums: Concatenated checksum array, one entry per embedded dex
    dex_files: Parsed DEX payload metadata and preview classes
    verifier_deps: Verifier dependency section summary per dex
```

### diff

```bash
vdexcli diff before.vdex after.vdex              # text with color
vdexcli diff --json before.vdex after.vdex        # full JSON diff
vdexcli diff --format summary before.vdex after.vdex  # one-line for CI
vdexcli diff --format jsonl before.vdex after.vdex    # single-line JSON for logs
```

Exit code: 0 if identical, 1 if different.

**Compares:** header, section sizes, checksums, DEX files, verifier classes/pairs, type-lookup entries.

**Example — files differ:**

```
$ vdexcli diff original.vdex modified.vdex

VDEX diff
  A: original.vdex (204 bytes)
  B: modified.vdex (204 bytes)

verifier_deps: (2 classes changed)
  [dex 0] verified 2→0 (-2)  pairs 1→0 (-1)  extras 0→0

summary: sections=0 checksums=0 dexes=0 verifier=2 typelookup=0
```

**Example — CI gate with summary:**

```
$ vdexcli diff --format summary original.vdex modified.vdex
status=different size_a=204 size_b=204 sections=0 checksums=0 dexes=0 verifier=2 typelookup=0
$ echo $?
1

$ vdexcli diff --format summary same.vdex same.vdex
status=identical size_a=204 size_b=204 sections=0 checksums=0 dexes=0 verifier=0 typelookup=0
$ echo $?
0
```

## Global Flags

| Flag | Description |
|------|-------------|
| `-i, --in <path>` | Input vdex path (alternative to positional argument) |
| `--format <mode>` | Output format: `text`, `json`, `jsonl`, `summary`, `sections`, `coverage`, `table` |
| `--json` | Shorthand for `--format json` |
| `--color <mode>` | Color output: `auto` (default), `always`, `never` |
| `--strict` | Treat matched warnings as fatal errors (non-zero exit) |
| `--strict-warn <patterns>` | Comma-separated warning filters; prefix `re:` for regex |
| `--show-meaning` | Include field descriptions in output (default: `true`) |
| `--extract-dex <dir>` | Extract DEX files during parse |
| `--extract-name-template` | Filename template (default: `{base}_{index}_{checksum}.dex`) |
| `--extract-continue-on-error` | Skip failures and continue extracting |
| `-v, --version` | Print version and exit |

**Output formats:**
- **text** — Human-readable full dump (default)
- **json** — Pretty-printed JSON, suitable for `jq`
- **jsonl** — Compact single-line JSON for log pipelines
- **summary** — One-line `key=value` for CI gates and monitoring
- **sections** — TSV table of section headers for `grep`/`awk`
- **coverage** — Byte coverage report only
- **table** — Aligned columns with ANSI colors (auto-detected terminal)

## Modify Flags

| Flag | Description |
|------|-------------|
| `--verifier-json <path>` | Path to verifier patch JSON (`-` for stdin) |
| `--mode <replace\|merge>` | Patch mode (default: `replace`) |
| `--dry-run` | Validate without writing output |
| `--verify` | Alias for `--dry-run` |
| `--quiet` | Suppress text-mode summary |
| `--force` | Allow output path equal to input |
| `--log-file <path>` | Append result as NDJSON |

## VDEX v027 Format

Based on the AOSP ART runtime ([`runtime/vdex_file.h`](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/vdex_file.h)):

```
Offset  Size    Description
------  ------  ----------------------------------------
0x00    12      VdexFileHeader: magic("vdex") + version("027\0") + num_sections(u32)
0x0C    N*12    VdexSectionHeader[N]: kind + offset + size (N = 4)

Section 0: kChecksumSection        uint32[D] per-DEX checksums
Section 1: kDexFileSection         Concatenated DEX files (empty in DM format)
Section 2: kVerifierDepsSection    Per-DEX verification dependency data
Section 3: kTypeLookupTableSection Per-DEX class descriptor hash tables
```

See [`docs/vdex-format.md`](docs/vdex-format.md) for detailed field descriptions.

## Project Structure

```
vdexcli/
├── main.go                          # Entry point (7 lines)
├── Makefile                         # Build targets (all/build/test/lint/clean)
├── cmd/                             # Cobra command layer
│   ├── root.go                      # Root command + global flags + --color
│   ├── parse.go                     # parse subcommand + extract flags
│   ├── extract.go                   # extract-dex subcommand
│   ├── modify.go                    # modify subcommand (11-step pipeline)
│   ├── dump.go                      # dump subcommand
│   └── version.go                   # version subcommand
├── internal/
│   ├── binutil/                     # Low-level binary I/O (ReadU32, LEB128, ...)
│   ├── model/                       # Shared types, constants, diagnostics (5 files)
│   ├── dex/                         # DEX format parsing (4 files, VDEX-independent)
│   ├── parser/                      # VDEX container parsing (7 files)
│   ├── modifier/                    # Verifier section build/patch/compare
│   ├── extractor/                   # DEX file extraction (interface-driven)
│   └── presenter/                   # Output formatting + ANSI color (3 files)
├── .github/workflows/               # CI, release, integration test workflows
├── samples/                         # Example verifier patch JSON files
├── scripts/                         # Log analysis utilities
├── testdata/                        # Real VDEX files for integration tests
├── docs/
│   ├── architecture.md              # Package diagram, data flow, design decisions
│   └── vdex-format.md              # VDEX v027 binary format reference
└── ROADMAP.md                       # Phased expansion plan
```

## Testing

```bash
go test -v ./...
# or
make test
```

The test suite includes 148 tests across 5 packages:
- **cmd**: 32 e2e subprocess tests (all commands, 7 formats, error cases) + 3 integration tests (166 real VDEX files)
- **internal/binutil**: 18 unit tests (100% coverage — LEB128, alignment, encoding round-trips)
- **internal/parser**: 51 unit tests (header, sections, verifier, typelookup, coverage, meanings, diagnostics)
- **internal/modifier**: 30 unit tests (patch parsing, validation, builder, failure classification, atomic write)
- **internal/extractor**: 9 unit tests (mock filesystem, interface verification)
- Real VDEX integration tests against Android 16 (AOSP `android-16.0.0_r4`)

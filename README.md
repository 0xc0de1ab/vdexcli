# vdexcli

A CLI tool for parsing, extracting, and modifying Android ART VDEX (`.vdex`) files.

Parses every byte of a VDEX v027 file — header, section table, checksums, embedded DEX files, verifier dependencies, and type lookup tables — and reports structural details in human-readable text or machine-readable JSON.

## Features

- **Parse** — Full structural dump of VDEX files with byte-level coverage tracking
- **Extract-dex** — Pull embedded DEX files out of a VDEX container
- **Modify** — Patch the verifier-deps section via JSON (replace or merge mode)
- **Dump** — Print human-readable descriptions of every parsed field
- **Byte coverage** — Quantitative report showing which byte ranges are parsed vs. gaps
- **ART-compatible encoding** — Verifier-deps offsets use section-absolute addressing, matching the AOSP ART runtime

## Quick Start

```bash
go install github.com/0xc0de1ab/vdexcli@latest

# Parse a VDEX file
vdexcli parse app.vdex

# JSON output for scripting
vdexcli parse --json app.vdex | jq '.byte_coverage.coverage_percent'

# Extract embedded DEX files
vdexcli extract-dex app.vdex ./dex-output/

# Patch verifier deps
vdexcli modify --verifier-json patch.json input.vdex output.vdex
```

## Example Output

### Text mode

```
$ vdexcli parse --show-meaning=false javalib.vdex

file: javalib.vdex
size: 5608 bytes
vdex magic="vdex" version="027" sections=4
sections:
  kind=kChecksumSection (0) off=0x3c size=0x4
    DEX file location checksum list (one uint32 per input dex)
  kind=kDexFileSection (1) off=0x0 size=0x0
    Concatenated DEX file payload
  kind=kVerifierDepsSection (2) off=0x40 size=0xda3
    Verifier dependency section
  kind=kTypeLookupTableSection (3) off=0xde4 size=0x804
    Class descriptor lookup table section
checksums: 1
  [0]=0xb767a504
dex files: 0
verifier_deps: off=0x40 size=0xda3
  [dex 0] verified=0 unverified=0 pairs=0 extra_strings=0
type_lookup: off=0xde4 size=0x804
  [dex 0] raw=2048 buckets=256 entries=246 non_empty=246 max_chain=1 avg_chain=1.00
byte_coverage: 5607/5608 bytes (100.0%)
  0x00000000..0x0000000c      12 bytes  vdex_header
  0x0000000c..0x0000003c      48 bytes  section_headers
  0x0000003c..0x00000040       4 bytes  kChecksumSection
  0x00000040..0x00000de3    3491 bytes  kVerifierDepsSection
  0x00000de4..0x000015e8    2052 bytes  kTypeLookupTableSection
  gaps:
    0x00000de3..0x00000de4       1 bytes  gap/padding
```

### JSON mode (byte coverage)

```
$ vdexcli parse --json --show-meaning=false javalib.vdex | jq '.byte_coverage'
```

```json
{
  "file_size": 5608,
  "parsed_bytes": 5607,
  "unparsed_bytes": 1,
  "coverage_percent": 99.98,
  "ranges": [
    {"offset": 0, "size": 12, "label": "vdex_header"},
    {"offset": 12, "size": 48, "label": "section_headers"},
    {"offset": 60, "size": 4, "label": "kChecksumSection"},
    {"offset": 64, "size": 3491, "label": "kVerifierDepsSection"},
    {"offset": 3556, "size": 2052, "label": "kTypeLookupTableSection"}
  ],
  "gaps": [
    {"offset": 3555, "size": 1, "label": "gap/padding"}
  ]
}
```

### Error handling

Corrupted or unsupported files produce clear, structured error messages:

```
$ vdexcli parse broken.vdex
parse error: file too small for VDEX header: 11 bytes (need >= 12)

$ vdexcli parse nonexistent.vdex
open nonexistent.vdex: no such file or directory

$ vdexcli parse
input vdex path is required (pass as argument or use --in)

$ vdexcli modify in.vdex out.vdex
--verifier-json is required
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

## Global Flags

| Flag | Description |
|------|-------------|
| `-i, --in <path>` | Input vdex path (alternative to positional argument) |
| `--format <mode>` | Output format: `text`, `json`, `jsonl`, `summary`, `sections`, `coverage` |
| `--json` | Shorthand for `--format json` |
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
├── cmd/                             # Cobra command layer
│   ├── root.go                      # Root command + global flags
│   ├── parse.go                     # parse subcommand
│   ├── extract.go                   # extract-dex subcommand
│   ├── modify.go                    # modify subcommand
│   ├── dump.go                      # dump subcommand
│   └── version.go                   # version subcommand
├── internal/
│   ├── binutil/                     # Low-level binary I/O (ReadU32, LEB128, ...)
│   ├── model/                       # Shared types, constants, diagnostics
│   ├── dex/                         # DEX format parsing (independent of VDEX)
│   ├── parser/                      # VDEX container parsing
│   ├── modifier/                    # Verifier section build/patch/compare
│   ├── extractor/                   # DEX file extraction
│   └── presenter/                   # Text/JSON output, warning categorization
├── samples/                         # Example verifier patch JSON files
├── scripts/                         # Log analysis utilities
├── testdata/                        # Real VDEX files for integration tests
└── docs/                            # Format documentation
```

## Testing

```bash
go test -v ./...
# or
make test
```

The test suite includes 36 test cases across 3 packages:
- VDEX header/section parsing edge cases and diagnostic codes (23 cases)
- DEX extractor with mock filesystem (9 cases)
- Verifier-deps encoding/decoding round-trip with section-absolute offsets
- Integration tests against 166 real VDEX files from Android 16 (AOSP `android-16.0.0_r4`)

# vdexcli

A CLI tool for parsing, extracting, and modifying Android ART VDEX (`.vdex`) files.

Parses every byte of a VDEX v027 file — header, section table, checksums, embedded DEX files, verifier dependencies, and type lookup tables — and reports structural details in human-readable text or machine-readable JSON.

## Features

- **Parse** — Full structural dump of VDEX files with byte-level coverage tracking
- **Extract** — Pull embedded DEX files out of a VDEX container
- **Modify** — Patch the verifier-deps section via JSON (replace or merge mode)
- **Byte coverage** — Quantitative report of parsed vs. unparsed bytes per file
- **ART-compatible encoding** — Verifier-deps offsets use section-absolute addressing, matching the AOSP ART runtime

## Requirements

- Go 1.22+

## Install

```bash
go install github.com/0xc0de1ab/vdexcli@latest
```

Or build from source:

```bash
git clone https://github.com/0xc0de1ab/vdexcli.git
cd vdexcli
go build -o vdexcli .
```

## Usage

```
vdexcli parse [flags] <file.vdex>
vdexcli extract <file.vdex> <out-dir>
vdexcli modify [flags] <input.vdex> <output.vdex>
vdexcli meanings
vdexcli version
```

Running `vdexcli <file.vdex>` without a subcommand is equivalent to `vdexcli parse`.

### Parse

```bash
# Text output
vdexcli parse app.vdex

# JSON output
vdexcli parse --json app.vdex

# Extract DEX files during parse
vdexcli parse --extract-dex ./out app.vdex

# Strict mode — treat matched warnings as errors
vdexcli parse --strict --strict-warn "checksum,version" app.vdex
```

**Output includes:**
- VDEX header (magic, version, section count)
- Section table (checksum, dex, verifier-deps, type-lookup)
- Per-DEX header fields (magic, version, SHA-1 signature, all size/offset fields)
- Verifier dependencies (verified/unverified class counts, assignability pairs, extra strings)
- Type lookup table statistics (bucket count, entries, chain lengths)
- Byte coverage report (parsed bytes, gaps, alignment padding)

### Extract

```bash
vdexcli extract app.vdex ./dex-output/
vdexcli extract --json app.vdex ./dex-output/
```

Customize output filenames with `--extract-name-template`:

```bash
vdexcli extract --extract-name-template "{base}_{index}_{checksum_hex}.dex" app.vdex ./out/
```

Available tokens: `{base}`, `{index}`, `{checksum}`, `{checksum_hex}`, `{offset}`, `{size}`

### Modify

Patch the verifier-deps section using a JSON specification:

```bash
# Replace mode (default) — rebuild verifier section from patch
vdexcli modify --verifier-json patch.json input.vdex output.vdex

# Merge mode — overlay patch onto existing verifier data
vdexcli modify --mode merge --verifier-json patch.json input.vdex output.vdex

# Dry run — validate without writing
vdexcli modify --dry-run --json --verifier-json patch.json input.vdex output.vdex

# Read patch from stdin
cat patch.json | vdexcli modify --verifier-json - input.vdex output.vdex
```

**Patch JSON format:**

```json
{
  "mode": "replace",
  "dexes": [
    {
      "dex_index": 0,
      "extra_strings": ["Ljava/lang/Object;"],
      "classes": [
        {
          "class_index": 0,
          "verified": true,
          "pairs": [{"dest": 5, "src": 10}]
        },
        {
          "class_index": 1,
          "verified": false
        }
      ]
    }
  ]
}
```

Sample patches are in the [`samples/`](samples/) directory.

### Meanings

```bash
# Print field descriptions
vdexcli meanings

# JSON output
vdexcli --json meanings
```

## Global Options

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |
| `--strict` | Treat warnings as fatal errors (non-zero exit) |
| `--strict-warn <patterns>` | Comma-separated warning filter patterns; prefix `re:` for regex |
| `--show-meaning` | Include field descriptions in output (default: true) |

## Modify Options

| Flag | Description |
|------|-------------|
| `--verifier-json <path>` | Path to verifier patch JSON (`-` for stdin) |
| `--mode <replace\|merge>` | Patch application mode |
| `--dry-run` | Validate only, don't write output |
| `--verify` | Alias for `--dry-run` |
| `--quiet` | Suppress text-mode summary lines |
| `--force` | Allow output path to equal input path |
| `--log-file <path>` | Append modify result as NDJSON to file |

## VDEX v027 Format

Based on the AOSP ART runtime ([`runtime/vdex_file.h`](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/vdex_file.h)):

```
Offset  Size    Description
──────  ──────  ────────────────────────────────────────
0x00    12      VdexFileHeader: magic("vdex") + version("027\0") + num_sections(uint32)
0x0C    N*12    VdexSectionHeader[N]: kind + offset + size (N = num_sections = 4)

Section 0: kChecksumSection     — uint32[D] checksums, one per DEX file
Section 1: kDexFileSection      — Concatenated DEX files (optional, empty in DM format)
Section 2: kVerifierDepsSection — Per-DEX verification dependency data
Section 3: kTypeLookupTableSection — Per-DEX class descriptor hash tables
```

See [`docs/vdex-format.md`](docs/vdex-format.md) for detailed field descriptions.

## Byte Coverage

The `byte_coverage` field in JSON output tracks exactly which byte ranges are parsed:

```json
{
  "byte_coverage": {
    "file_size": 5608,
    "parsed_bytes": 5607,
    "unparsed_bytes": 1,
    "coverage_percent": 100.0,
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
}
```

## Testing

```bash
go test -v ./...
```

The test suite includes:
- Unit tests for verifier-deps encoding/decoding with section-absolute offsets
- Integration tests against 166 real VDEX files from Android 16 (AOSP `android-16.0.0_r4`)

## License

See [LICENSE](LICENSE) for details.

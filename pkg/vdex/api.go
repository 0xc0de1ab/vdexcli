package vdex

import (
	"github.com/0xc0de1ab/vdexcli/internal/parser"
)

// ExplainBytes parses raw VDEX bytes and returns a byte-level annotated FieldMap.
//
// Every byte in data is accounted for in the returned FieldMap — fields are
// ordered by offset, gaps/padding are explicitly represented, and bounded DEX
// identity/package previews are provided separately from physical byte fields.
// This function is WASM-compatible (no filesystem access).
//
// Returns an error if data is too small, has an invalid magic, or uses an
// unsupported format (e.g. legacy VDEX v021-026 requires different handling).
func ExplainBytes(data []byte) (*FieldMap, error) {
	return parser.ExplainVdexBytes(data)
}

// ParseBytes parses VDEX structure from raw bytes and returns a high-level Report.
//
// The report contains the VDEX header, section table, checksums, DEX metadata,
// verifier dependency statistics, and byte-level coverage.
// This function is WASM-compatible (no filesystem access).
//
// Options (e.g. WithMeanings) can be supplied to configure the parser.
func ParseBytes(data []byte, opts ...Option) (*Report, error) {
	cfg := applyOptions(opts)
	r, _, err := parser.ParseVdexBytes(data, cfg.includeMeanings)
	if r != nil && cfg.maxDexPreview >= 0 && len(r.Dexes) > cfg.maxDexPreview {
		r.Dexes = r.Dexes[:cfg.maxDexPreview]
	}
	return r, err
}

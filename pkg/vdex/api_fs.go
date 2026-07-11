//go:build !js

package vdex

import (
	"os"
	"path/filepath"

	"github.com/0xc0de1ab/vdexcli/internal/parser"
)

// ExplainFile reads a VDEX file from the given path and returns an annotated FieldMap.
//
// This is a convenience wrapper around ExplainBytes for non-WASM builds.
// For WASM or in-memory usage, use ExplainBytes directly.
func ExplainFile(path string) (*FieldMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parser.ExplainVdexBytes(data)
}

// ParseFile reads a VDEX file from the given path and returns a high-level Report.
//
// This is a convenience wrapper around ParseBytes for non-WASM builds.
// The Report.File field is set to the cleaned absolute path.
func ParseFile(path string, opts ...Option) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := ParseBytes(data, opts...)
	if r != nil {
		r.File = filepath.Clean(path)
	}
	return r, err
}

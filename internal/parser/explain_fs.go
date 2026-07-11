//go:build !js

package parser

import (
	"os"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ExplainVdex reads a VDEX file from path and returns a byte-level annotated field map.
// This is a convenience wrapper around ExplainVdexBytes for non-WASM builds.
// For WASM or in-memory usage, call ExplainVdexBytes directly.
func ExplainVdex(path string) (*model.PrimitiveMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ExplainVdexBytes(data)
}

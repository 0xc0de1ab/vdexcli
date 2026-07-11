//go:build !js

package parser

import (
	"os"
	"path/filepath"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseVdex reads a VDEX file from path and returns a structured report.
// When includeMeanings is true the report includes human-readable field descriptions.
// This is a convenience wrapper around ParseVdexBytes for non-WASM builds.
func ParseVdex(path string, includeMeanings bool) (*model.VdexReport, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	r, raw, parseErr := ParseVdexBytes(data, includeMeanings)
	if r != nil {
		r.File = filepath.Clean(path)
	}
	return r, raw, parseErr
}

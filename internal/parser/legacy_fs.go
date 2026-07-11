//go:build !js

package parser

import (
	"os"
	"path/filepath"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseVdexLegacy reads a VDEX v021-v026 file from path.
// This is a convenience wrapper around ParseVdexLegacyBytes for non-WASM builds.
func ParseVdexLegacy(path string, includeMeanings bool) (*model.VdexReport, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	r, raw, parseErr := ParseVdexLegacyBytes(data, includeMeanings)
	if r != nil {
		r.File = filepath.Clean(path)
	}
	return r, raw, parseErr
}

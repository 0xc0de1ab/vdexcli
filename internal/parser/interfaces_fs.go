//go:build !js

package parser

import "github.com/0xc0de1ab/vdexcli/internal/model"

// DefaultParser is the standard VdexParser implementation using filesystem access.
// Not available in WASM builds; use ParseVdexBytes directly instead.
type DefaultParser struct{}

func (DefaultParser) Parse(path string, includeMeanings bool) (*model.VdexReport, []byte, error) {
	return ParseVdex(path, includeMeanings)
}

// Compile-time interface compliance check for DefaultParser.
var _ VdexParser = DefaultParser{}

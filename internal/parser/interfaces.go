package parser

import "github.com/0xc0de1ab/vdexcli/internal/model"

// VdexParser parses a VDEX file and returns a structured report.
// This interface enables version-specific parser implementations
// (e.g., v021-v026 vs v027) and test mock injection.
type VdexParser interface {
	Parse(path string, includeMeanings bool) (*model.VdexReport, []byte, error)
}

// DiffCalculator compares two parsed VDEX reports.
type DiffCalculator interface {
	Diff(a, b *model.VdexReport) model.VdexDiff
}

// --- Default implementations wrapping package-level functions ---

// DefaultParser is the standard v027 VdexParser implementation.
type DefaultParser struct{}

func (DefaultParser) Parse(path string, includeMeanings bool) (*model.VdexReport, []byte, error) {
	return ParseVdex(path, includeMeanings)
}

// DefaultDiffCalculator is the standard DiffCalculator implementation.
type DefaultDiffCalculator struct{}

func (DefaultDiffCalculator) Diff(a, b *model.VdexReport) model.VdexDiff {
	return Diff(a, b)
}

// Compile-time interface compliance checks.
var (
	_ VdexParser     = DefaultParser{}
	_ DiffCalculator = DefaultDiffCalculator{}
)

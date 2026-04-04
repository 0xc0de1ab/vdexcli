package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func TestComputeByteCoverage_FullCoverage(t *testing.T) {
	header := model.VdexHeader{NumSections: 2}
	sections := []model.VdexSection{
		{Kind: 0, Offset: 36, Size: 8},  // right after header(12) + 2 sections(24) = 36
		{Kind: 1, Offset: 44, Size: 16}, // contiguous
	}
	cov := ComputeByteCoverage(60, header, sections, nil)

	assert.Equal(t, 60, cov.FileSize)
	assert.Equal(t, 60, cov.ParsedBytes)
	assert.Equal(t, 0, cov.UnparsedBytes)
	assert.InDelta(t, 100.0, cov.CoveragePercent, 0.01)
	assert.Empty(t, cov.Gaps)
}

func TestComputeByteCoverage_WithGap(t *testing.T) {
	header := model.VdexHeader{NumSections: 1}
	sections := []model.VdexSection{
		{Kind: 0, Offset: 28, Size: 4}, // gap of 4 bytes between header(12+12=24) and offset 28
	}
	cov := ComputeByteCoverage(32, header, sections, nil)

	assert.Equal(t, 32, cov.FileSize)
	assert.Equal(t, 28, cov.ParsedBytes) // 12 + 12 + 4 = 28
	assert.Equal(t, 4, cov.UnparsedBytes)
	require.Len(t, cov.Gaps, 1)
	assert.Equal(t, 24, cov.Gaps[0].Offset)
	assert.Equal(t, 4, cov.Gaps[0].Size)
	assert.Equal(t, "gap/padding", cov.Gaps[0].Label)
}

func TestComputeByteCoverage_TrailingBytes(t *testing.T) {
	header := model.VdexHeader{NumSections: 1}
	sections := []model.VdexSection{
		{Kind: 0, Offset: 24, Size: 4},
	}
	cov := ComputeByteCoverage(100, header, sections, nil)

	// header(12) + section_headers(12) + checksum(4) = 28 bytes parsed, 72 trailing
	assert.Equal(t, 100, cov.FileSize)
	assert.Equal(t, 28, cov.ParsedBytes)

	hasTrailing := false
	for _, g := range cov.Gaps {
		if g.Label == "trailing_bytes" {
			hasTrailing = true
			assert.Equal(t, 28, g.Offset)
			assert.Equal(t, 72, g.Size)
		}
	}
	assert.True(t, hasTrailing, "should detect trailing bytes")
}

func TestComputeByteCoverage_ZeroSizeSection(t *testing.T) {
	header := model.VdexHeader{NumSections: 1}
	sections := []model.VdexSection{
		{Kind: 0, Offset: 24, Size: 0}, // zero-size, should be excluded from ranges
	}
	cov := ComputeByteCoverage(24, header, sections, nil)

	assert.Equal(t, 24, cov.ParsedBytes) // only header + section_headers
	for _, r := range cov.Ranges {
		assert.NotEqual(t, "kChecksumSection", r.Label, "zero-size section should not appear in ranges")
	}
}

func TestComputeByteCoverage_OverlappingSections(t *testing.T) {
	header := model.VdexHeader{NumSections: 2}
	sections := []model.VdexSection{
		{Kind: 0, Offset: 36, Size: 20},
		{Kind: 1, Offset: 40, Size: 20}, // overlaps with kind 0
	}
	cov := ComputeByteCoverage(60, header, sections, nil)

	// Should not double-count overlapping bytes
	assert.LessOrEqual(t, cov.ParsedBytes, 60)
	assert.GreaterOrEqual(t, cov.ParsedBytes, 0)
}

func TestComputeByteCoverage_EmptyFile(t *testing.T) {
	header := model.VdexHeader{NumSections: 0}
	cov := ComputeByteCoverage(12, header, nil, nil)

	assert.Equal(t, 12, cov.FileSize)
	assert.Equal(t, 12, cov.ParsedBytes) // header only
	assert.Empty(t, cov.Gaps)
}

func TestComputeByteCoverage_RangesAreSorted(t *testing.T) {
	header := model.VdexHeader{NumSections: 3}
	sections := []model.VdexSection{
		{Kind: 2, Offset: 100, Size: 10},
		{Kind: 0, Offset: 48, Size: 4},
		{Kind: 1, Offset: 52, Size: 40},
	}
	cov := ComputeByteCoverage(110, header, sections, nil)

	for i := 1; i < len(cov.Ranges); i++ {
		assert.GreaterOrEqual(t, cov.Ranges[i].Offset, cov.Ranges[i-1].Offset,
			"ranges must be sorted by offset")
	}
}

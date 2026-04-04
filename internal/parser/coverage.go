package parser

import (
	"fmt"
	"sort"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ComputeByteCoverage builds a report of which byte ranges in the file
// are accounted for by parsed structures, and identifies gaps/padding.
func ComputeByteCoverage(fileSize int, header model.VdexHeader, sections []model.VdexSection, dexes []model.DexReport) *model.ByteCoverageReport {
	type rangeEntry struct {
		offset int
		size   int
		label  string
	}
	var ranges []rangeEntry

	headerSize := 12
	ranges = append(ranges, rangeEntry{0, headerSize, "vdex_header"})

	sectionTableSize := int(header.NumSections) * 12
	ranges = append(ranges, rangeEntry{headerSize, sectionTableSize, "section_headers"})

	for _, s := range sections {
		if s.Size == 0 {
			continue
		}
		name := s.Name
		if name == "" {
			name = fmt.Sprintf("section_%d", s.Kind)
		}
		ranges = append(ranges, rangeEntry{int(s.Offset), int(s.Size), name})
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].offset < ranges[j].offset
	})

	merged := make([]rangeEntry, 0, len(ranges))
	for _, r := range ranges {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			lastEnd := last.offset + last.size
			if r.offset < lastEnd {
				overlap := lastEnd - r.offset
				if overlap >= r.size {
					continue
				}
				r.offset = lastEnd
				r.size -= overlap
			}
		}
		merged = append(merged, r)
	}

	parsedBytes := 0
	outRanges := make([]model.ByteCoverageRange, 0, len(merged))
	for _, r := range merged {
		parsedBytes += r.size
		outRanges = append(outRanges, model.ByteCoverageRange{
			Offset: r.offset,
			Size:   r.size,
			Label:  r.label,
		})
	}

	var gaps []model.ByteCoverageRange
	cursor := 0
	for _, r := range merged {
		if r.offset > cursor {
			gaps = append(gaps, model.ByteCoverageRange{
				Offset: cursor,
				Size:   r.offset - cursor,
				Label:  "gap/padding",
			})
		}
		if end := r.offset + r.size; end > cursor {
			cursor = end
		}
	}
	if cursor < fileSize {
		gaps = append(gaps, model.ByteCoverageRange{
			Offset: cursor,
			Size:   fileSize - cursor,
			Label:  "trailing_bytes",
		})
	}

	unparsed := fileSize - parsedBytes
	pct := 0.0
	if fileSize > 0 {
		pct = float64(parsedBytes) / float64(fileSize) * 100.0
	}

	return &model.ByteCoverageReport{
		FileSize:        fileSize,
		ParsedBytes:     parsedBytes,
		UnparsedBytes:   unparsed,
		CoveragePercent: pct,
		Ranges:          outRanges,
		Gaps:            gaps,
	}
}

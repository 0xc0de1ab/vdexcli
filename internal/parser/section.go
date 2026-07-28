package parser

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

const maxSectionDiagnostics = 64

func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validByteRange(dataLen int, offset, size uint32) bool {
	return uint64(offset)+uint64(size) <= uint64(dataLen)
}

func sectionBounds(dataLen int, s model.VdexSection) (int, int, bool) {
	if !validByteRange(dataLen, s.Offset, s.Size) {
		return 0, 0, false
	}
	return int(s.Offset), int(uint64(s.Offset) + uint64(s.Size)), true
}

// ParseSections reads the section header table from raw bytes starting at
// offset 12 (right after the VdexFileHeader). Each entry is 12 bytes:
// kind(u32) + offset(u32) + size(u32).
func ParseSections(buf []byte, count uint32) ([]model.VdexSection, map[uint32]int, []model.ParseDiagnostic) {
	sections := make([]model.VdexSection, 0, count)
	index := map[uint32]int{}
	var diags []model.ParseDiagnostic
	for i := uint32(0); i < count; i++ {
		base := int(i) * 12
		kind := binary.LittleEndian.Uint32(buf[base : base+4])
		offset := binary.LittleEndian.Uint32(buf[base+4 : base+8])
		size := binary.LittleEndian.Uint32(buf[base+8 : base+12])
		item := model.VdexSection{
			Kind:    kind,
			Offset:  offset,
			Size:    size,
			Name:    model.SectionName[kind],
			Meaning: model.SectionMeaning[kind],
		}
		if item.Name == "" {
			item.Name = model.UnknownSectionName(kind)
			item.Meaning = "unknown section kind"
		}
		if _, exists := index[kind]; exists && len(diags) == 0 {
			diags = append(diags, model.DiagSectionDuplicate(kind))
		}
		if _, exists := index[kind]; !exists {
			index[kind] = int(i)
		}
		sections = append(sections, item)
	}
	return sections, index, diags
}

// ValidateSections checks every section's offset/size against the file size,
// the optional header/table end, and other sections.
func ValidateSections(fileSize int, sections []model.VdexSection, headerEnds ...uint64) []model.ParseDiagnostic {
	type sectionRange struct {
		section model.VdexSection
		index   int
		start   uint64
		end     uint64
	}

	diags := make([]model.ParseDiagnostic, 0, min(len(sections), maxSectionDiagnostics))
	diagnosticsOmitted := 0
	appendDiag := func(d model.ParseDiagnostic) {
		if len(diags) < maxSectionDiagnostics-1 {
			diags = append(diags, d)
			return
		}
		diagnosticsOmitted++
	}

	ranges := make([]sectionRange, 0, len(sections))
	fileEnd := uint64(max(fileSize, 0))
	headerEnd := uint64(0)
	if len(headerEnds) > 0 {
		headerEnd = headerEnds[0]
	}
	for i, s := range sections {
		start := uint64(s.Offset)
		end := start + uint64(s.Size)
		if start > fileEnd {
			appendDiag(model.DiagSectionBeyondFile(s.Kind, s.Offset))
			continue
		}
		if end > fileEnd {
			appendDiag(model.DiagSectionExceedsFile(s.Kind, s.Offset, s.Size))
			continue
		}
		if s.Size == 0 {
			appendDiag(model.DiagSectionZeroSize(s.Kind))
			continue
		}
		if start < headerEnd {
			appendDiag(model.DiagSectionHeaderOverlap(s.Kind, s.Offset, headerEnd))
			continue
		}
		ranges = append(ranges, sectionRange{section: s, index: i, start: start, end: end})
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		if ranges[i].end != ranges[j].end {
			return ranges[i].end > ranges[j].end
		}
		return ranges[i].index < ranges[j].index
	})

	if len(ranges) > 0 {
		furthest := ranges[0]
		for _, current := range ranges[1:] {
			if current.start < furthest.end {
				appendDiag(model.DiagSectionOverlap(current.section.Kind, furthest.section.Kind))
			}
			if current.end > furthest.end {
				furthest = current
			}
		}
	}

	if diagnosticsOmitted > 0 {
		diags = append(diags, model.ParseDiagnostic{
			Severity: model.SeverityWarning,
			Category: model.CatSection,
			Code:     model.DiagCode("WARN_SECTION_DIAGNOSTICS_TRUNCATED"),
			Message:  fmt.Sprintf("%d additional section diagnostic(s) omitted", diagnosticsOmitted),
			Hint:     "fix the first reported section errors before inspecting additional overlap diagnostics",
		})
	}
	return diags
}

package parser

import (
	"encoding/binary"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

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

// ValidateSections checks every section's offset/size against the file size
// and detects overlaps between sections.
func ValidateSections(fileSize int, sections []model.VdexSection) []model.ParseDiagnostic {
	var diags []model.ParseDiagnostic
	for i, s := range sections {
		start := int(s.Offset)
		end := int(uint64(s.Offset) + uint64(s.Size))
		if start < 0 || start > fileSize {
			diags = append(diags, model.DiagSectionBeyondFile(s.Kind, s.Offset))
			continue
		}
		if end > fileSize {
			diags = append(diags, model.DiagSectionExceedsFile(s.Kind, s.Offset, s.Size))
			continue
		}
		if s.Size == 0 {
			diags = append(diags, model.DiagSectionZeroSize(s.Kind))
		}
		for j := 0; j < i; j++ {
			other := sections[j]
			otherStart := int(other.Offset)
			otherEnd := int(uint64(other.Offset) + uint64(other.Size))
			if other.Size == 0 || s.Size == 0 {
				continue
			}
			if start < otherEnd && otherStart < end {
				diags = append(diags, model.DiagSectionOverlap(s.Kind, other.Kind))
			}
		}
	}
	return diags
}

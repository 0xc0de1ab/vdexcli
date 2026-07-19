package modifier

import (
	"encoding/binary"
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// RelayoutVdex replaces one section and shifts the following file bytes while
// preserving every byte outside the replaced section. Section header offsets
// are adjusted by the resulting shift.
func RelayoutVdex(raw []byte, sections []model.VdexSection, targetKind uint32, newPayload []byte) ([]byte, error) {
	if uint64(len(newPayload)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("replacement payload exceeds VDEX uint32 size limit")
	}
	headerSize := 12 + len(sections)*12
	if headerSize > len(raw) {
		return nil, fmt.Errorf("section header table exceeds file size")
	}

	targetIndex := -1
	for i, section := range sections {
		end := uint64(section.Offset) + uint64(section.Size)
		if end > uint64(len(raw)) {
			return nil, fmt.Errorf("section kind %d range exceeds file size", section.Kind)
		}
		if section.Size > 0 && int(section.Offset) < headerSize {
			return nil, fmt.Errorf("section kind %d overlaps the VDEX header", section.Kind)
		}
		if targetIndex < 0 && section.Kind == targetKind {
			targetIndex = i
		}
	}
	if targetIndex < 0 {
		return nil, fmt.Errorf("target section kind %d not found", targetKind)
	}

	target := sections[targetIndex]
	if len(newPayload) > 0 && int(target.Offset) < headerSize {
		return nil, fmt.Errorf("target section has no valid payload location")
	}
	targetStart := int(target.Offset)
	targetEnd := int(uint64(target.Offset) + uint64(target.Size))
	for i, section := range sections {
		if i == targetIndex || section.Size == 0 {
			continue
		}
		start := int(section.Offset)
		end := int(uint64(section.Offset) + uint64(section.Size))
		if start < targetEnd && targetStart < end {
			return nil, fmt.Errorf("target section overlaps section kind %d", section.Kind)
		}
	}

	baseShift := len(newPayload) - int(target.Size)
	padding := 0
	nextOffset := -1
	for i, section := range sections {
		if i == targetIndex || section.Offset == 0 || int(section.Offset) < targetEnd {
			continue
		}
		if nextOffset < 0 || int(section.Offset) < nextOffset {
			nextOffset = int(section.Offset)
		}
	}
	if nextOffset >= 0 {
		shiftedNext := nextOffset + baseShift
		padding = binutil.Align4(shiftedNext) - shiftedNext
	}
	shift := baseShift + padding
	newSize := len(raw) + shift
	if newSize < headerSize || uint64(newSize) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("replacement produces invalid file size %d", newSize)
	}

	out := make([]byte, newSize)
	copy(out, raw[:targetStart])
	copy(out[targetStart:], newPayload)
	tailStart := targetStart + len(newPayload) + padding
	copy(out[tailStart:], raw[targetEnd:])

	for i, section := range sections {
		newOffset := section.Offset
		newSectionSize := section.Size
		switch {
		case i == targetIndex:
			newSectionSize = uint32(len(newPayload))
		case section.Offset != 0 && int(section.Offset) >= targetEnd:
			shifted := int64(section.Offset) + int64(shift)
			if shifted < 0 || shifted > int64(^uint32(0)) {
				return nil, fmt.Errorf("section kind %d offset overflows after relayout", section.Kind)
			}
			newOffset = uint32(shifted)
		}

		base := 12 + i*12
		binary.LittleEndian.PutUint32(out[base:], section.Kind)
		binary.LittleEndian.PutUint32(out[base+4:], newOffset)
		binary.LittleEndian.PutUint32(out[base+8:], newSectionSize)
	}

	return out, nil
}

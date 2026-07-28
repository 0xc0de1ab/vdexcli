package dex

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseClassDefs reads class_def entries and resolves each class_idx
// through type_ids → string_ids to produce a descriptor preview list
// (capped at model.MaxClassPreview).
func ParseClassDefs(
	raw []byte,
	strs []string,
	typeIds uint32,
	typeIdsOff uint32,
	classDefsOff uint32,
	classDefsSize uint32,
) ([]string, error) {
	if classDefsSize == 0 {
		return nil, nil
	}
	typeIDsEnd := uint64(typeIdsOff) + uint64(typeIds)*4
	if typeIDsEnd > uint64(len(raw)) {
		return nil, fmt.Errorf("dex: type_ids table out of range (off=%#x count=%d, dex size=%d)", typeIdsOff, typeIds, len(raw))
	}
	classDefsEnd := uint64(classDefsOff) + uint64(classDefsSize)*32
	if classDefsEnd > uint64(len(raw)) {
		return nil, fmt.Errorf("dex: class_defs table out of range (off=%#x count=%d, dex size=%d)", classDefsOff, classDefsSize, len(raw))
	}

	typeCount := int(typeIds)
	typeOffset := int(typeIdsOff)
	classOffset := int(classDefsOff)
	classCount := int(classDefsSize)
	out := make([]string, 0, binutil.MinInt(classCount, model.MaxClassPreview))
	for i := 0; i < classCount; i++ {
		base := classOffset + i*32
		classTypeIdx := int(binutil.ReadU32(raw, base))
		desc := fmt.Sprintf("<invalid class_idx=%d>", classTypeIdx)
		if classTypeIdx >= 0 && classTypeIdx < typeCount {
			typeIdxOff := typeOffset + classTypeIdx*4
			stringIdx := int(binutil.ReadU32(raw, typeIdxOff))
			if stringIdx >= 0 && stringIdx < len(strs) {
				desc = strs[stringIdx]
			}
		}
		if i < model.MaxClassPreview {
			out = append(out, desc)
		}
	}
	return out, nil
}

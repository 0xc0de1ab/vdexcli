package dex

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseClassDefs reads class_def entries and resolves each class_idx
// through type_ids → string_ids to produce a descriptor preview list
// (capped at model.MaxClassPreview).
func ParseClassDefs(raw []byte, strs []string, typeIds int, typeIdsOff int, classDefsOff int, classDefsSize int) ([]string, error) {
	if classDefsSize == 0 {
		return nil, nil
	}
	if typeIdsOff < 0 || typeIdsOff+typeIds*4 > len(raw) {
		return nil, fmt.Errorf("dex: type_ids table out of range (off=%#x count=%d, dex size=%d)", typeIdsOff, typeIds, len(raw))
	}
	if classDefsOff < 0 || classDefsOff+classDefsSize*32 > len(raw) {
		return nil, fmt.Errorf("dex: class_defs table out of range (off=%#x count=%d, dex size=%d)", classDefsOff, classDefsSize, len(raw))
	}

	out := make([]string, 0, binutil.MinInt(classDefsSize, model.MaxClassPreview))
	for i := 0; i < classDefsSize; i++ {
		base := classDefsOff + i*32
		classTypeIdx := int(binutil.ReadU32(raw, base))
		desc := fmt.Sprintf("<invalid class_idx=%d>", classTypeIdx)
		if classTypeIdx >= 0 && classTypeIdx < typeIds {
			typeIdxOff := typeIdsOff + classTypeIdx*4
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

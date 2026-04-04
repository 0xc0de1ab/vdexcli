package dex

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseSection iterates over a kDexFileSection byte range, parsing each
// concatenated DEX file. DEX files are 4-byte aligned within the section.
func ParseSection(raw []byte, s model.VdexSection, expected int) ([]*model.DexContext, []string) {
	var out []*model.DexContext
	var warnings []string
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end > len(raw) || start >= end {
		warnings = append(warnings, "dex section out of file range")
		return out, warnings
	}

	cursor := start
	for (expected == 0 && cursor < end) || (expected > 0 && len(out) < expected) {
		if cursor+0x70 > end {
			warnings = append(warnings, "truncated dex header in dex section")
			break
		}
		nextIdx := len(out)
		ctx, used, err := Parse(raw[cursor:end], cursor)
		if ctx != nil {
			ctx.Rep.Index = nextIdx
			if int(ctx.Rep.Offset)+int(ctx.Rep.Size) > end {
				ctx.Rep.Size = uint32(end - int(ctx.Rep.Offset))
				used = end - int(ctx.Rep.Offset)
				warnings = append(warnings, fmt.Sprintf("dex[%d]: file_size exceeds dex section, truncated to %#x", nextIdx, ctx.Rep.Size))
			}
			out = append(out, ctx)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("dex[%d]: %v", nextIdx, err))
		}
		if used <= 0 {
			break
		}
		cursor += used
		cursor = binutil.Align4(cursor)
		if cursor > end {
			break
		}
	}
	return out, warnings
}

package dex

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseSection iterates over a kDexFileSection byte range, parsing each
// concatenated DEX file. DEX files are 4-byte aligned within the section.
func ParseSection(raw []byte, s model.VdexSection, expected int) ([]*model.DexContext, []model.ParseDiagnostic) {
	var out []*model.DexContext
	var diags []model.ParseDiagnostic
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end > len(raw) || start >= end {
		diags = append(diags, model.DiagDexSectionRange())
		return out, diags
	}

	cursor := start
	for (expected == 0 && cursor < end) || (expected > 0 && len(out) < expected) {
		if cursor+0x70 > end {
			diags = append(diags, model.DiagDexTruncated(len(out)))
			break
		}
		nextIdx := len(out)
		ctx, used, err := Parse(raw[cursor:end], cursor)
		if ctx != nil {
			ctx.Rep.Index = nextIdx
			if int(ctx.Rep.Offset)+int(ctx.Rep.Size) > end {
				ctx.Rep.Size = uint32(end - int(ctx.Rep.Offset))
				used = end - int(ctx.Rep.Offset)
				diags = append(diags, model.DiagDexFileSizeClamped(nextIdx, ctx.Rep.FileSize, ctx.Rep.Size))
			}
			out = append(out, ctx)
		}
		if err != nil {
			diags = append(diags, model.ParseDiagnostic{
				Severity: model.SeverityWarning,
				Category: model.CatDex,
				Code:     model.WarnDexTruncated,
				Message:  fmt.Sprintf("dex[%d]: %v", nextIdx, err),
				Hint:     "DEX parsing error; this dex may be partially parsed",
			})
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
	return out, diags
}

package parser

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseVerifierSection parses the kVerifierDepsSection. The section
// starts with a uint32[D] offset table (section-absolute), followed
// by per-dex verifier dependency blocks.
func ParseVerifierSection(raw []byte, s model.VdexSection, dexes []*model.DexContext, expected int) (*model.VerifierReport, []string) {
	out := &model.VerifierReport{
		Offset: s.Offset,
		Size:   s.Size,
	}
	var warnings []string
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end > len(raw) {
		warnings = append(warnings, "verifier-deps section out of file range")
		return out, warnings
	}
	if expected == 0 {
		expected = len(dexes)
	}

	for i := 0; i < expected; i++ {
		indexOff := start + i*4
		if indexOff+4 > end {
			warnings = append(warnings, fmt.Sprintf("verifier section index table truncated at dex %d", i))
			break
		}
		relative := int(binutil.ReadU32(raw, indexOff))
		blockOff := start + relative
		if blockOff < start || blockOff >= end {
			warnings = append(warnings, fmt.Sprintf("verifier block %d offset %#x outside section", i, relative))
			continue
		}
		rep, ws := parseVerifierDex(raw, start, blockOff, end, i, dexes)
		out.Dexes = append(out.Dexes, rep)
		warnings = append(warnings, ws...)
	}
	return out, warnings
}

func parseVerifierDex(raw []byte, sectionStart int, blockStart int, sectionEnd int, dexIdx int, dexes []*model.DexContext) (model.VerifierDexReport, []string) {
	out := model.VerifierDexReport{DexIndex: dexIdx}
	var warnings []string

	numClass := 0
	var baseStrings []string
	if dexIdx < len(dexes) {
		numClass = int(dexes[dexIdx].Rep.ClassDefs)
		baseStrings = dexes[dexIdx].Strings
	}

	// When DEX section is absent (DM format), class_def_count is unknown.
	// Infer it from the verifier block's class offset table structure.
	if numClass == 0 && blockStart < sectionEnd {
		inferred := inferClassCount(raw, sectionStart, blockStart, sectionEnd)
		if inferred > 0 {
			numClass = inferred
			warnings = append(warnings, fmt.Sprintf("dex %d: inferred class_def_count=%d from verifier section (DM format)", dexIdx, numClass))
		}
	}

	if blockStart+4*(numClass+1) > sectionEnd {
		warnings = append(warnings, fmt.Sprintf("dex %d verifier block truncated", dexIdx))
		return out, warnings
	}

	offsets := make([]uint32, numClass+1)
	for i := 0; i <= numClass; i++ {
		offsets[i] = binutil.ReadU32(raw, blockStart+i*4)
	}

	type rawPair struct {
		class, dest, src uint32
	}
	var pairs []rawPair

	// Offsets in the class-def table are section-absolute, matching ART's
	// EncodeSetVector / DecodeSetVector encoding.
	maxSetEnd := blockStart + 4*(numClass+1)
	nextValid := 1

	for classIdx := 0; classIdx < numClass; classIdx++ {
		o := offsets[classIdx]
		if o == model.NotVerifiedMarker {
			out.UnverifiedClasses++
			continue
		}
		out.VerifiedClasses++

		for nextValid <= classIdx || (nextValid <= numClass && offsets[nextValid] == model.NotVerifiedMarker) {
			nextValid++
			if nextValid > numClass {
				warnings = append(warnings, fmt.Sprintf("dex %d class %d malformed class offset chain", dexIdx, classIdx))
				return out, warnings
			}
		}
		setStart := sectionStart + int(o)
		setEnd := sectionStart + int(offsets[nextValid])
		if setStart < blockStart || setEnd > sectionEnd || setEnd < setStart {
			warnings = append(warnings, fmt.Sprintf("dex %d class %d malformed set bounds", dexIdx, classIdx))
			continue
		}
		cursor := setStart
		if cursor > maxSetEnd {
			maxSetEnd = cursor
		}
		for cursor < setEnd {
			dest, n, err := binutil.ReadULEB128(raw, cursor)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("dex %d class %d invalid destination leb128", dexIdx, classIdx))
				break
			}
			cursor += n
			src, n, err := binutil.ReadULEB128(raw, cursor)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("dex %d class %d invalid source leb128", dexIdx, classIdx))
				break
			}
			cursor += n
			pairs = append(pairs, rawPair{class: uint32(classIdx), dest: dest, src: src})
			out.AssignabilityPairs++
		}
		if setEnd > maxSetEnd {
			maxSetEnd = setEnd
		}
	}

	cursor := binutil.Align4(maxSetEnd)
	if cursor+4 > sectionEnd {
		out.ExtraStringCount = 0
		return out, warnings
	}
	numStrings := int(binutil.ReadU32(raw, cursor))
	cursor += 4
	if cursor+numStrings*4 > sectionEnd {
		warnings = append(warnings, fmt.Sprintf("dex %d verifier extra strings table truncated", dexIdx))
		out.ExtraStringCount = 0
		return out, warnings
	}

	extras := make([]string, numStrings)
	for i := 0; i < numStrings; i++ {
		// Extra string offsets are section-absolute.
		rel := int(binutil.ReadU32(raw, cursor+i*4))
		abs := sectionStart + rel
		if abs < blockStart || abs >= sectionEnd {
			extras[i] = fmt.Sprintf("invalid_%d", i)
			warnings = append(warnings, fmt.Sprintf("dex %d extra string %d offset %#x invalid", dexIdx, i, rel))
			continue
		}
		extras[i] = binutil.ReadCString(raw[abs:sectionEnd])
	}
	out.ExtraStringCount = len(extras)

	extraBase := uint32(len(baseStrings))
	for i := 0; i < len(pairs) && i < model.MaxVerifierPairs; i++ {
		p := pairs[i]
		out.FirstPairs = append(out.FirstPairs, model.VerifierPair{
			ClassDefIndex: p.class,
			DestID:        p.dest,
			Dest:          resolveVerifierString(baseStrings, extras, extraBase, p.dest),
			SrcID:         p.src,
			Src:           resolveVerifierString(baseStrings, extras, extraBase, p.src),
		})
	}

	return out, warnings
}

// inferClassCount determines class_def_count from the verifier block's
// class offset table when the DEX section is absent (DM format).
//
// The offset table has class_count+1 entries (last is sentinel). Each entry
// is either NotVerifiedMarker (0xFFFFFFFF) or a section-absolute offset
// pointing into the assignability data area. Valid offsets are:
//   - monotonically non-decreasing among verified classes
//   - within [blockRelOffset, sectionSize)
//
// We scan uint32 values from blockStart until a value falls outside
// the valid range, then class_count = entries_read - 1.
func inferClassCount(raw []byte, sectionStart int, blockStart int, sectionEnd int) int {
	sectionSize := sectionEnd - sectionStart
	blockRel := blockStart - sectionStart

	maxEntries := (sectionEnd - blockStart) / 4
	if maxEntries <= 1 {
		return 0
	}
	// Cap to avoid scanning huge sections
	if maxEntries > 0x10000 {
		maxEntries = 0x10000
	}

	lastValid := uint32(0)
	count := 0
	for i := 0; i < maxEntries; i++ {
		off := blockStart + i*4
		if off+4 > sectionEnd {
			break
		}
		val := binutil.ReadU32(raw, off)
		if val == model.NotVerifiedMarker {
			count++
			continue
		}
		// Offset must be within section range.
		if val < uint32(blockRel) || val >= uint32(sectionSize) {
			break
		}
		// Offsets among verified classes must be non-decreasing.
		if lastValid > 0 && val < lastValid {
			break
		}
		lastValid = val
		count++
	}

	// Subtract 1 for the sentinel entry.
	if count < 2 {
		return 0
	}
	return count - 1
}

func resolveVerifierString(dexStrings []string, extras []string, extraBase uint32, id uint32) string {
	if int(id) < len(dexStrings) {
		return dexStrings[id]
	}
	rel := int(id - extraBase)
	if id >= extraBase && rel >= 0 && rel < len(extras) {
		return extras[rel]
	}
	return fmt.Sprintf("string_%d", id)
}

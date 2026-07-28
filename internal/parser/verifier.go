package parser

import (
	"bytes"
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

const (
	maxVerifierPairsScanned   = 1_000_000
	maxVerifierExtraStrings   = 250_000
	maxVerifierOffsetWarnings = 64
)

// ParseVerifierSection parses the kVerifierDepsSection. The section
// starts with a uint32[D] offset table (section-absolute), followed
// by per-dex verifier dependency blocks.
func ParseVerifierSection(raw []byte, s model.VdexSection, dexes []*model.DexContext, expected int) (*model.VerifierReport, []model.ParseDiagnostic) {
	out := &model.VerifierReport{
		Offset: s.Offset,
		Size:   s.Size,
	}
	var diags []model.ParseDiagnostic
	start, end, ok := sectionBounds(len(raw), s)
	if !ok {
		diags = append(diags, model.DiagVerifierSectionRange())
		return out, diags
	}
	out.ContentHash = contentHash(raw[start:end])
	if expected == 0 {
		expected = len(dexes)
	}
	if expected < 0 || uint64(expected)*4 > uint64(end-start) {
		diags = append(diags, model.DiagVerifierIndexTruncated(0))
		return out, diags
	}

	indexEnd := start + expected*4
	blockStarts := make([]int, expected)
	for i := range blockStarts {
		blockStarts[i] = -1
	}
	previous := -1
	for i := 0; i < expected; i++ {
		indexOff := start + i*4
		relative := binutil.ReadU32(raw, indexOff)
		blockOff64 := uint64(start) + uint64(relative)
		if relative%4 != 0 || blockOff64 < uint64(indexEnd) || blockOff64 >= uint64(end) {
			diags = append(diags, model.DiagVerifierBlockOutside(i, diagnosticOffset(relative)))
			continue
		}
		blockOff := int(blockOff64)
		if previous >= blockOff {
			diags = append(diags, model.ParseDiagnostic{
				Severity: model.SeverityWarning,
				Category: model.CatVerifier,
				Code:     model.WarnVerifierBlockOutside,
				Message:  fmt.Sprintf("verifier block %d offset %#x is not strictly increasing", i, relative),
				Hint:     "per-dex verifier blocks must be ordered and non-overlapping",
			})
			continue
		}
		blockStarts[i] = blockOff
		previous = blockOff
	}

	for i, blockOff := range blockStarts {
		if blockOff < 0 {
			continue
		}
		blockEnd := end
		for next := i + 1; next < len(blockStarts); next++ {
			if blockStarts[next] > blockOff {
				blockEnd = blockStarts[next]
				break
			}
		}
		rep, ds := parseVerifierDex(raw, start, blockOff, blockEnd, i, dexes)
		out.Dexes = append(out.Dexes, rep)
		diags = append(diags, ds...)
	}
	return out, diags
}

func diagnosticOffset(v uint32) int {
	maxInt := uint64(^uint(0) >> 1)
	if uint64(v) > maxInt {
		return int(maxInt)
	}
	return int(v)
}

func parseVerifierDex(raw []byte, sectionStart int, blockStart int, blockEnd int, dexIdx int, dexes []*model.DexContext) (model.VerifierDexReport, []model.ParseDiagnostic) {
	out := model.VerifierDexReport{DexIndex: dexIdx}
	var diags []model.ParseDiagnostic

	numClass := 0
	var baseStrings []string
	if dexIdx < len(dexes) {
		classDefs := dexes[dexIdx].Rep.ClassDefs
		maxClasses := (blockEnd-blockStart)/4 - 1
		if maxClasses < 0 || uint64(classDefs) > uint64(maxClasses) {
			diags = append(diags, model.DiagVerifierBlockTruncated(dexIdx))
			return out, diags
		}
		numClass = int(classDefs)
		baseStrings = dexes[dexIdx].Strings
	}

	// When DEX section is absent (DM format), class_def_count is unknown.
	// Infer it from the verifier block's class offset table structure.
	if dexIdx >= len(dexes) && blockStart < blockEnd {
		inferred := inferClassCount(raw, sectionStart, blockStart, blockEnd)
		if inferred > 0 {
			numClass = inferred
			diags = append(diags, model.ParseDiagnostic{
				Severity: model.SeverityWarning,
				Category: model.CatVerifier,
				Code:     model.WarnVerifierInferredCount,
				Message:  fmt.Sprintf("dex %d: inferred class_def_count=%d from verifier section (DM format)", dexIdx, numClass),
				Hint:     "no embedded DEX; class count inferred from offset table heuristic — verify against source APK",
			})
		}
	}

	tableEnd64 := uint64(blockStart) + uint64(numClass+1)*4
	if tableEnd64 > uint64(blockEnd) {
		diags = append(diags, model.DiagVerifierBlockTruncated(dexIdx))
		return out, diags
	}

	offsets := make([]uint32, numClass+1)
	for i := 0; i <= numClass; i++ {
		offsets[i] = binutil.ReadU32(raw, blockStart+i*4)
	}

	type rawPair struct {
		class, dest, src uint32
	}
	pairs := make([]rawPair, 0, model.MaxVerifierPairs)

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
				diags = append(diags, model.DiagVerifierMalformedChain(dexIdx, classIdx))
				return out, diags
			}
		}
		setStart64 := uint64(sectionStart) + uint64(o)
		setEnd64 := uint64(sectionStart) + uint64(offsets[nextValid])
		if setStart64 < tableEnd64 ||
			setEnd64 > uint64(blockEnd) ||
			setEnd64 < setStart64 {
			diags = append(diags, model.DiagVerifierMalformedBounds(dexIdx, classIdx))
			continue
		}
		setStart := int(setStart64)
		setEnd := int(setEnd64)
		cursor := setStart
		if cursor > maxSetEnd {
			maxSetEnd = cursor
		}
		for cursor < setEnd {
			if out.AssignabilityPairs >= maxVerifierPairsScanned {
				diags = append(diags, model.DiagVerifierWorkLimit(
					dexIdx,
					fmt.Sprintf("more than %d assignability pairs", maxVerifierPairsScanned),
				))
				return out, diags
			}
			dest, n, err := binutil.ReadULEB128(raw[:setEnd], cursor)
			if err != nil {
				diags = append(diags, model.DiagVerifierInvalidLEB128(dexIdx, classIdx, "destination"))
				break
			}
			cursor += n
			src, n, err := binutil.ReadULEB128(raw[:setEnd], cursor)
			if err != nil {
				diags = append(diags, model.DiagVerifierInvalidLEB128(dexIdx, classIdx, "source"))
				break
			}
			cursor += n
			if len(pairs) < model.MaxVerifierPairs {
				pairs = append(pairs, rawPair{class: uint32(classIdx), dest: dest, src: src})
			}
			out.AssignabilityPairs++
		}
		if setEnd > maxSetEnd {
			maxSetEnd = setEnd
		}
	}

	cursor := binutil.Align4(maxSetEnd)
	if cursor < maxSetEnd || cursor+4 > blockEnd {
		out.ExtraStringCount = 0
		diags = append(diags, model.DiagVerifierExtrasTruncated(dexIdx))
		return out, diags
	}
	numStringsValue := binutil.ReadU32(raw, cursor)
	cursor += 4
	extrasEnd64 := uint64(cursor) + uint64(numStringsValue)*4
	if extrasEnd64 > uint64(blockEnd) {
		diags = append(diags, model.DiagVerifierExtrasTruncated(dexIdx))
		out.ExtraStringCount = 0
		return out, diags
	}
	numStrings := int(numStringsValue)
	if numStrings > maxVerifierExtraStrings {
		diags = append(diags, model.DiagVerifierWorkLimit(
			dexIdx,
			fmt.Sprintf("%d extra strings exceeds limit %d", numStrings, maxVerifierExtraStrings),
		))
		out.ExtraStringCount = numStrings
		return out, diags
	}

	out.ExtraStringCount = numStrings

	extraBase := uint32(len(baseStrings))
	neededExtras := make(map[uint32]struct{})
	for _, pair := range pairs {
		for _, id := range []uint32{pair.dest, pair.src} {
			if id >= extraBase && uint64(id-extraBase) < uint64(numStringsValue) {
				neededExtras[id-extraBase] = struct{}{}
			}
		}
	}
	extras := make(map[uint32]string)
	invalidWarnings := 0
	for index := 0; index < numStrings; index++ {
		relative := binutil.ReadU32(raw, cursor+index*4)
		absolute64 := uint64(sectionStart) + uint64(relative)
		if absolute64 < extrasEnd64 || absolute64 >= uint64(blockEnd) {
			if invalidWarnings < maxVerifierOffsetWarnings {
				diags = append(diags, model.DiagVerifierExtraInvalid(
					dexIdx,
					index,
					diagnosticOffset(relative),
				))
				invalidWarnings++
			}
			if _, needed := neededExtras[uint32(index)]; needed {
				extras[uint32(index)] = fmt.Sprintf("invalid_%d", index)
			}
			continue
		}
		if _, needed := neededExtras[uint32(index)]; !needed {
			continue
		}
		absolute := int(absolute64)
		value, ok := decodeVerifierCString(raw, absolute, blockEnd)
		if !ok {
			if invalidWarnings < maxVerifierOffsetWarnings {
				diags = append(diags, model.DiagVerifierExtraInvalid(
					dexIdx,
					index,
					diagnosticOffset(relative),
				))
				invalidWarnings++
			}
			extras[uint32(index)] = fmt.Sprintf("invalid_%d", index)
			continue
		}
		extras[uint32(index)] = value
	}

	for i := 0; i < len(pairs) && i < model.MaxVerifierPairs; i++ {
		p := pairs[i]
		out.FirstPairs = append(out.FirstPairs, model.VerifierPair{
			ClassDefIndex: p.class,
			DestID:        p.dest,
			Dest:          resolveVerifierStringSparse(baseStrings, extras, extraBase, p.dest),
			SrcID:         p.src,
			Src:           resolveVerifierStringSparse(baseStrings, extras, extraBase, p.src),
		})
	}

	return out, diags
}

func decodeVerifierCString(raw []byte, offset, blockEnd int) (string, bool) {
	const maxVerifierStringBytes = 1 << 20
	if offset < 0 || offset >= blockEnd || blockEnd > len(raw) {
		return "", false
	}
	limit := blockEnd
	if maxEnd := offset + maxVerifierStringBytes; maxEnd > offset && maxEnd < limit {
		limit = maxEnd
	}
	end := bytes.IndexByte(raw[offset:limit], 0)
	if end < 0 {
		return "", false
	}
	return string(raw[offset : offset+end]), true
}

func resolveVerifierStringSparse(dexStrings []string, extras map[uint32]string, extraBase uint32, id uint32) string {
	if uint64(id) < uint64(len(dexStrings)) {
		return dexStrings[int(id)]
	}
	if id >= extraBase {
		if value, ok := extras[id-extraBase]; ok {
			return value
		}
	}
	return fmt.Sprintf("string_%d", id)
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
	if uint64(id) < uint64(len(dexStrings)) {
		return dexStrings[int(id)]
	}
	if id >= extraBase {
		rel := uint64(id - extraBase)
		if rel < uint64(len(extras)) {
			return extras[int(rel)]
		}
	}
	return fmt.Sprintf("string_%d", id)
}

package modifier

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// MakeFailureReason returns a human-readable failure reason from modify results.
func MakeFailureReason(summary model.ModifySummary, parseErr error, compareErr error, writeErr error, strictMatched []string) string {
	if summary.Status == "strict_failed" && len(strictMatched) > 0 {
		return fmt.Sprintf("strict mode: matched %d warning(s): %v", len(strictMatched), strictMatched)
	}
	if writeErr != nil {
		return writeErr.Error()
	}
	if compareErr != nil {
		return compareErr.Error()
	}
	if parseErr != nil {
		return parseErr.Error()
	}
	if summary.Status != "ok" {
		for _, e := range summary.Errors {
			if e != "" {
				return e
			}
		}
		return "modify failed"
	}
	return ""
}

// MakeFailureCategory returns a category tag for the failure type.
func MakeFailureCategory(summary model.ModifySummary, parseErr error, compareErr error, writeErr error, strictMatched []string) string {
	if summary.Status == "strict_failed" && len(strictMatched) > 0 {
		return "strict"
	}
	if writeErr != nil {
		return "write"
	}
	if compareErr != nil {
		return "compare"
	}
	if parseErr != nil {
		return "parse"
	}
	if summary.Status != "ok" {
		return "modify"
	}
	return ""
}

// CompareVerifierSectionDiff compares original and patched verifier sections.
func CompareVerifierSectionDiff(raw []byte, section model.VdexSection, dexes []model.DexReport, checksums []uint32, patchedPayload []byte) (model.VerifierSectionDiff, []model.ModifyDexDiff, []string, error) {
	diff := model.VerifierSectionDiff{}
	warnings := []string{}
	dexDiffs := make([]model.ModifyDexDiff, 0)

	oldData, oldWarn, oldErr := ParseVerifierSectionForMerge(raw, section, dexes, checksums)
	warnings = append(warnings, oldWarn...)

	patchedSection := model.VdexSection{
		Offset: 0,
		Size:   uint32(len(patchedPayload)),
	}
	newData, newWarn, newErr := ParseVerifierSectionForMerge(patchedPayload, patchedSection, dexes, checksums)
	warnings = append(warnings, newWarn...)

	if oldErr != nil || newErr != nil {
		if oldErr != nil {
			warnings = append(warnings, fmt.Sprintf("cannot compare verifier diff against original: %v", oldErr))
		}
		if newErr != nil {
			warnings = append(warnings, fmt.Sprintf("cannot compare verifier diff against patched payload: %v", newErr))
		}
		if oldErr != nil {
			return diff, nil, warnings, oldErr
		}
		return diff, nil, warnings, newErr
	}

	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		oldDex := oldData[dexIdx]
		newDex := newData[dexIdx]
		classCount := oldDex.ClassCount
		if newDex.ClassCount > classCount {
			classCount = newDex.ClassCount
		}
		dexDiff := model.ModifyDexDiff{
			DexIndex: dexIdx,
		}
		if classCount < 0 {
			continue
		}
		for classIdx := 0; classIdx < classCount; classIdx++ {
			var oldClass model.VerifierSectionClass
			var newClass model.VerifierSectionClass
			if classIdx < len(oldDex.Classes) {
				oldClass = oldDex.Classes[classIdx]
			}
			if classIdx < len(newDex.Classes) {
				newClass = newDex.Classes[classIdx]
			}

			diff.TotalClasses++
			dexDiff.TotalClasses++
			if VerifierSectionClassEqual(oldClass, newClass) {
				diff.UnmodifiedClasses++
				dexDiff.UnmodifiedClasses++
			} else {
				diff.ModifiedClasses++
				dexDiff.ModifiedClasses++
				if len(dexDiff.ChangedClassIdxs) < model.MaxModifyClassSamples {
					dexDiff.ChangedClassIdxs = append(dexDiff.ChangedClassIdxs, classIdx)
				}
			}
		}
		dexDiffs = append(dexDiffs, dexDiff)
	}
	return diff, dexDiffs, warnings, nil
}

// VerifierSectionClassEqual compares two class verification entries.
func VerifierSectionClassEqual(a model.VerifierSectionClass, b model.VerifierSectionClass) bool {
	if a.Verified != b.Verified {
		return false
	}
	if len(a.Pairs) != len(b.Pairs) {
		return false
	}
	for i := range a.Pairs {
		if a.Pairs[i].Dest != b.Pairs[i].Dest || a.Pairs[i].Src != b.Pairs[i].Src {
			return false
		}
	}
	return true
}

// ParseVerifierSectionForMerge reads the existing verifier section into a
// per-dex map for merge operations.
func ParseVerifierSectionForMerge(raw []byte, s model.VdexSection, dexes []model.DexReport, checksums []uint32) (map[int]model.VerifierSectionDex, []string, error) {
	warnings := []string{}
	out := map[int]model.VerifierSectionDex{}
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end < start || end > len(raw) {
		return out, warnings, warnErr(&warnings, "modifier: verifier section out of file range")
	}
	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	if dexCount == 0 {
		return out, warnings, fmt.Errorf("cannot infer dex count from input, no dex or checksum section parsed")
	}

	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		indexOff := start + dexIdx*4
		if indexOff+4 > end {
			warnings = append(warnings, fmt.Sprintf("verifier section index table truncated at dex %d", dexIdx))
			out[dexIdx] = model.VerifierSectionDex{
				ClassCount: 0,
			}
			continue
		}
		relative := int(binutil.ReadU32(raw, indexOff))
		blockStart := start + relative
		if blockStart < start || blockStart >= end {
			warnings = append(warnings, fmt.Sprintf("verifier block %d offset %#x outside section", dexIdx, relative))
			out[dexIdx] = model.VerifierSectionDex{
				ClassCount: 0,
			}
			continue
		}
		blockEnd := end
		if dexIdx+1 < dexCount {
			nextIdx := start + (dexIdx+1)*4
			if nextIdx+4 <= end {
				nextRel := int(binutil.ReadU32(raw, nextIdx))
				if nextRel >= 0 && nextRel <= int(s.Size) {
					blockEnd = start + nextRel
				}
			} else {
				warnings = append(warnings, fmt.Sprintf("verifier section index table truncated when determining block end for dex %d", dexIdx))
			}
			if blockEnd < blockStart {
				blockEnd = end
			}
		}
		if blockEnd > end {
			blockEnd = end
		}

		classCount := 0
		if dexIdx < len(dexes) {
			classCount = int(dexes[dexIdx].ClassDefs)
		}
		dexData, parseWarn, parseErr := ParseVerifierDexForMerge(raw, start, blockStart, blockEnd, dexIdx, classCount)
		warnings = append(warnings, parseWarn...)
		if parseErr != nil {
			return out, warnings, parseErr
		}
		out[dexIdx] = dexData
	}

	return out, warnings, nil
}

// ParseVerifierDexForMerge reads a single dex's verifier data for merge.
func ParseVerifierDexForMerge(raw []byte, sectionStart int, blockStart int, sectionEnd int, dexIdx int, classCount int) (model.VerifierSectionDex, []string, error) {
	out := model.VerifierSectionDex{
		ClassCount: classCount,
		Classes:    make([]model.VerifierSectionClass, classCount),
	}
	warnings := []string{}
	if blockStart+4*(classCount+1) > sectionEnd {
		return out, warnings, warnErr(&warnings, fmt.Sprintf("modifier: dex %d verifier block truncated", dexIdx))
	}

	offsets := make([]uint32, classCount+1)
	for i := 0; i <= classCount; i++ {
		offsets[i] = binutil.ReadU32(raw, blockStart+i*4)
	}

	maxSetEnd := blockStart + 4*(classCount+1)
	nextValid := 1
	for classIdx := 0; classIdx < classCount; classIdx++ {
		o := offsets[classIdx]
		if o == model.NotVerifiedMarker {
			out.Classes[classIdx] = model.VerifierSectionClass{Verified: false}
			continue
		}
		out.Classes[classIdx].Verified = true
		for nextValid <= classIdx || (nextValid <= classCount && offsets[nextValid] == model.NotVerifiedMarker) {
			nextValid++
			if nextValid > classCount {
				return out, warnings, warnErr(&warnings, fmt.Sprintf("modifier: dex %d class %d malformed class offset chain", dexIdx, classIdx))
			}
		}
		setStart := sectionStart + int(o)
		setEnd := sectionStart + int(offsets[nextValid])
		if setStart < blockStart || setEnd > sectionEnd || setEnd < setStart {
			return out, warnings, warnErr(&warnings, fmt.Sprintf("modifier: dex %d class %d malformed set bounds", dexIdx, classIdx))
		}
		if setEnd > maxSetEnd {
			maxSetEnd = setEnd
		}
		cursor := setStart
		for cursor < setEnd {
			dest, n, err := binutil.ReadULEB128(raw, cursor)
			if err != nil {
				return out, append(warnings, fmt.Sprintf("dex %d class %d invalid destination leb128", dexIdx, classIdx)), err
			}
			cursor += n
			src, n, err := binutil.ReadULEB128(raw, cursor)
			if err != nil {
				return out, append(warnings, fmt.Sprintf("dex %d class %d invalid source leb128", dexIdx, classIdx)), err
			}
			cursor += n
			out.Classes[classIdx].Pairs = append(out.Classes[classIdx].Pairs, model.VerifierPatchPair{Dest: dest, Src: src})
		}
	}

	cursor := binutil.Align4(maxSetEnd)
	if cursor+4 > sectionEnd {
		return out, warnings, nil
	}
	numStrings := int(binutil.ReadU32(raw, cursor))
	cursor += 4
	if cursor+numStrings*4 > sectionEnd {
		warnings = append(warnings, fmt.Sprintf("dex %d verifier extra strings table truncated", dexIdx))
		return out, warnings, nil
	}
	extras := make([]string, numStrings)
	for i := 0; i < numStrings; i++ {
		rel := int(binutil.ReadU32(raw, cursor+i*4))
		abs := sectionStart + rel
		if abs < blockStart || abs >= sectionEnd {
			extras[i] = fmt.Sprintf("invalid_%d", i)
			warnings = append(warnings, fmt.Sprintf("dex %d extra string %d offset %#x invalid", dexIdx, i, rel))
			continue
		}
		extras[i] = binutil.ReadCString(raw[abs:sectionEnd])
	}
	out.ExtraString = extras
	return out, warnings, nil
}

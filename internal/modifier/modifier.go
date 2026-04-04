// Package modifier builds, patches, and compares VDEX verifier-deps sections.
package modifier

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samber/lo"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// warnErr appends msg to warnings and returns it as an error.
// Avoids duplicating the same string literal in both places.
func warnErr(warnings *[]string, msg string) error {
	*warnings = append(*warnings, msg)
	return fmt.Errorf("%s", msg)
}

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

func ParseVerifierPatch(path string) (model.VerifierPatchSpec, []string, error) {
	out := model.VerifierPatchSpec{}
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return out, nil, fmt.Errorf("read verifier patch: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out, nil, fmt.Errorf("invalid verifier patch json: empty input")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, nil, fmt.Errorf("invalid verifier patch json: %w", err)
	}
	if err := func() error {
		var extra any
		if err := dec.Decode(&extra); err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected extra json content")
	}(); err != nil {
		return out, nil, fmt.Errorf("invalid verifier patch json: %w", err)
	}
	if err := ValidateVerifierPatchIndices(out); err != nil {
		return out, nil, err
	}
	out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	switch out.Mode {
	case "replace", "merge", "":
	default:
		return out, nil, fmt.Errorf("unsupported patch mode %q; supported: replace, merge", out.Mode)
	}
	return out, nil, nil
}

func ValidateVerifierPatchIndices(patch model.VerifierPatchSpec) error {
	dexes := map[int]struct{}{}
	for _, d := range patch.Dexes {
		if d.DexIndex < 0 {
			return fmt.Errorf("invalid dex_index %d", d.DexIndex)
		}
		if _, exists := dexes[d.DexIndex]; exists {
			return fmt.Errorf("duplicate patch dex_index %d", d.DexIndex)
		}
		dexes[d.DexIndex] = struct{}{}

		classes := map[int]struct{}{}
		for _, c := range d.Classes {
			if c.ClassIndex < 0 {
				return fmt.Errorf("invalid class_index %d for dex %d", c.ClassIndex, d.DexIndex)
			}
			if _, exists := classes[c.ClassIndex]; exists {
				return fmt.Errorf("duplicate class_index %d for dex %d", c.ClassIndex, d.DexIndex)
			}
			classes[c.ClassIndex] = struct{}{}
		}
	}
	return nil
}

func BuildVerifierSectionReplacement(dexes []model.DexReport, checksums []uint32, patch model.VerifierPatchSpec) ([]byte, []string, error) {
	warnings := []string{}
	patchByDex := map[int]model.VerifierPatchDex{}
	for _, d := range patch.Dexes {
		if _, exists := patchByDex[d.DexIndex]; exists {
			return nil, warnings, fmt.Errorf("duplicate patch dex_index %d", d.DexIndex)
		}
		if d.DexIndex < 0 {
			return nil, warnings, fmt.Errorf("invalid dex_index %d", d.DexIndex)
		}
		patchByDex[d.DexIndex] = d
	}

	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	if dexCount == 0 {
		return nil, warnings, fmt.Errorf("cannot infer dex count from input, no dex or checksum section parsed")
	}
	for dexIdx := range patchByDex {
		if dexIdx >= dexCount {
			return nil, warnings, fmt.Errorf("patch dex_index %d exceeds dex count %d", dexIdx, dexCount)
		}
		if len(patchByDex[dexIdx].Classes) > 0 && dexIdx >= len(dexes) {
			return nil, warnings, fmt.Errorf("cannot patch dex %d classes: class count is unknown (dex section not parsed)", dexIdx)
		}
		if len(patchByDex[dexIdx].ExtraStrings) > 0 && dexIdx >= len(dexes) {
			warnings = append(warnings, fmt.Sprintf("dex %d extra strings provided but dex section missing, offsets for existing base strings cannot be validated", dexIdx))
		}
	}

	sectionPayload := make([]byte, dexCount*4)
	cursor := dexCount * 4

	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		classCount := uint32(0)
		if dexIdx < len(dexes) {
			classCount = dexes[dexIdx].ClassDefs
		}
		dexPatch, hasPatch := patchByDex[dexIdx]
		if !hasPatch {
			dexPatch = model.VerifierPatchDex{
				DexIndex:     dexIdx,
				Classes:      nil,
				ExtraStrings: nil,
			}
		}
		baseStringCount := 0
		if dexIdx < len(dexes) {
			baseStringCount = int(dexes[dexIdx].StringIds)
		}
		d, buildWarn, err := BuildVerifierDexFromPatch(int(classCount), baseStringCount, dexPatch, uint32(cursor))
		warnings = append(warnings, buildWarn...)
		if err != nil {
			return nil, warnings, err
		}

		binary.LittleEndian.PutUint32(sectionPayload[dexIdx*4:], uint32(cursor))
		sectionPayload = append(sectionPayload, d...)
		cursor += len(d)
	}

	return sectionPayload, warnings, nil
}

func BuildVerifierSectionMerge(dexes []model.DexReport, checksums []uint32, section model.VdexSection, raw []byte, patch model.VerifierPatchSpec) ([]byte, []string, error) {
	warnings := []string{}
	if len(dexes) == 0 {
		warnings = append(warnings, "merge mode running without dex section class-count context; class patches will require explicit dex class info in input")
	}
	existing, parseWarn, err := ParseVerifierSectionForMerge(raw, section, dexes, checksums)
	warnings = append(warnings, parseWarn...)
	if err != nil {
		return nil, warnings, err
	}

	patchByDex := map[int]model.VerifierPatchDex{}
	for _, d := range patch.Dexes {
		if _, exists := patchByDex[d.DexIndex]; exists {
			return nil, warnings, fmt.Errorf("duplicate patch dex_index %d", d.DexIndex)
		}
		if d.DexIndex < 0 {
			return nil, warnings, fmt.Errorf("invalid dex_index %d", d.DexIndex)
		}
		patchByDex[d.DexIndex] = d
	}

	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	if dexCount == 0 {
		return nil, warnings, fmt.Errorf("cannot infer dex count from input, no dex or checksum section parsed")
	}
	for dexIdx := range patchByDex {
		if dexIdx >= dexCount {
			return nil, warnings, fmt.Errorf("patch dex_index %d exceeds dex count %d", dexIdx, dexCount)
		}
		if len(patchByDex[dexIdx].Classes) > 0 && dexIdx >= len(dexes) {
			return nil, warnings, fmt.Errorf("cannot patch dex %d classes in merge mode: class count is unknown (dex section not parsed)", dexIdx)
		}
	}

	sectionPayload := make([]byte, dexCount*4)
	cursor := dexCount * 4

	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		old := existing[dexIdx]
		classCount := old.ClassCount
		if dexIdx < len(dexes) {
			classCount = int(dexes[dexIdx].ClassDefs)
		}
		baseStringCount := 0
		if dexIdx < len(dexes) {
			baseStringCount = int(dexes[dexIdx].StringIds)
		}
		if classCount < 0 {
			return nil, warnings, fmt.Errorf("invalid class count %d for dex %d", classCount, dexIdx)
		}

		classVerified := make([]bool, classCount)
		classPairs := make([][]model.VerifierPatchPair, classCount)
		for i, c := range old.Classes {
			if i >= classCount {
				break
			}
			classVerified[i] = c.Verified
			classPairs[i] = append(classPairs[i], c.Pairs...)
		}

		dexPatch := patchByDex[dexIdx]
		seenClass := map[int]bool{}
		for _, c := range dexPatch.Classes {
			if c.ClassIndex < 0 || c.ClassIndex >= classCount {
				return nil, warnings, fmt.Errorf("invalid class_index %d for class_count %d", c.ClassIndex, classCount)
			}
			if seenClass[c.ClassIndex] {
				return nil, warnings, fmt.Errorf("duplicate class_index %d in patch", c.ClassIndex)
			}
			seenClass[c.ClassIndex] = true
			verified := true
			if c.Verified != nil {
				verified = *c.Verified
			} else if len(c.Pairs) == 0 {
				verified = false
			}
			classVerified[c.ClassIndex] = verified
			if verified {
				classPairs[c.ClassIndex] = append([]model.VerifierPatchPair{}, c.Pairs...)
			} else {
				classPairs[c.ClassIndex] = nil
			}
		}

		extraStrings := append([]string{}, old.ExtraString...)
		extraStrings = append(extraStrings, dexPatch.ExtraStrings...)
		if dexIdx >= len(dexes) && len(extraStrings) > 0 {
			warnings = append(warnings, fmt.Sprintf("merged extra_strings for dex %d without dex section context; base string validation skipped", dexIdx))
		}

		d, buildWarn, err := BuildVerifierDexBlock(classCount, baseStringCount, classVerified, classPairs, extraStrings, uint32(cursor))
		warnings = append(warnings, buildWarn...)
		if err != nil {
			return nil, warnings, err
		}

		binary.LittleEndian.PutUint32(sectionPayload[dexIdx*4:], uint32(cursor))
		sectionPayload = append(sectionPayload, d...)
		cursor += len(d)
	}

	return sectionPayload, warnings, nil
}

func BuildVerifierDexFromPatch(classCount int, baseStringCount int, patch model.VerifierPatchDex, blockOffset uint32) ([]byte, []string, error) {
	warnings := []string{}
	classVerified := make([]bool, classCount)
	classPairs := make([][]model.VerifierPatchPair, classCount)
	seenClass := map[int]bool{}
	for _, c := range patch.Classes {
		if c.ClassIndex < 0 || c.ClassIndex >= classCount {
			return nil, warnings, fmt.Errorf("invalid class_index %d for class_count %d", c.ClassIndex, classCount)
		}
		if seenClass[c.ClassIndex] {
			return nil, warnings, fmt.Errorf("duplicate class_index %d in patch", c.ClassIndex)
		}
		seenClass[c.ClassIndex] = true
		verified := true
		if c.Verified != nil {
			verified = *c.Verified
		} else if len(c.Pairs) == 0 {
			verified = false
		}
		classVerified[c.ClassIndex] = verified
		if verified {
			classPairs[c.ClassIndex] = append([]model.VerifierPatchPair{}, c.Pairs...)
		}
	}
	return BuildVerifierDexBlock(classCount, baseStringCount, classVerified, classPairs, patch.ExtraStrings, blockOffset)
}

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
		// Section-absolute offsets: base is sectionStart, not blockStart.
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
	out.ExtraString = extras
	return out, warnings, nil
}

func BuildVerifierDexBlock(classCount int, baseStringCount int, classVerified []bool, classPairs [][]model.VerifierPatchPair, extraStrings []string, blockOffset uint32) ([]byte, []string, error) {
	warnings := []string{}
	if classCount < 0 {
		return nil, warnings, fmt.Errorf("invalid classCount %d", classCount)
	}
	if len(classVerified) < classCount {
		return nil, warnings, fmt.Errorf("class verified array shorter than class count %d", classCount)
	}
	if len(classPairs) < classCount {
		return nil, warnings, fmt.Errorf("class pairs array shorter than class count %d", classCount)
	}

	// Offsets stored in the class-def table must be section-absolute (relative
	// to the verifier-deps section start), matching the ART runtime encoding.
	// blockOffset is this block's position within the section.
	localOffsetBase := uint32(4 * (classCount + 1))
	offsets := make([]uint32, classCount+1)
	for i := 0; i < classCount; i++ {
		offsets[i] = model.NotVerifiedMarker
	}
	offsets[classCount] = blockOffset + localOffsetBase
	body := make([]byte, 0, 64)
	currentLocalOffset := localOffsetBase
	for i := 0; i < classCount; i++ {
		if !classVerified[i] {
			continue
		}
		offsets[i] = blockOffset + currentLocalOffset
		for _, p := range classPairs[i] {
			if p.Dest >= uint32(baseStringCount)+uint32(len(extraStrings)) {
				warnings = append(warnings, fmt.Sprintf("class %d pair dest id %d exceeds string_ids+extras bound %d (unresolved mapping)", i, p.Dest, uint32(baseStringCount)+uint32(len(extraStrings))))
			}
			if p.Src >= uint32(baseStringCount)+uint32(len(extraStrings)) {
				warnings = append(warnings, fmt.Sprintf("class %d pair src id %d exceeds string_ids+extras bound %d (unresolved mapping)", i, p.Src, uint32(baseStringCount)+uint32(len(extraStrings))))
			}
			body = binutil.EncodeULEB128(body, p.Dest)
			body = binutil.EncodeULEB128(body, p.Src)
		}
		currentLocalOffset = localOffsetBase + uint32(len(body))
	}
	offsets[classCount] = blockOffset + currentLocalOffset

	block := make([]byte, 0, len(body)+256)
	for _, off := range offsets {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], off)
		block = append(block, n[:]...)
	}
	block = append(block, body...)
	if aligned := binutil.Align4(len(block)); aligned > len(block) {
		block = append(block, make([]byte, aligned-len(block))...)
	}

	strCount := len(extraStrings)
	block = binutil.AppendUint32LE(block, uint32(strCount))
	offsetPos := len(block)
	for i := 0; i < strCount; i++ {
		block = binutil.AppendUint32LE(block, 0)
	}
	stringBlob := make([]byte, 0)
	dataStart := len(block)
	for i, s := range extraStrings {
		// Extra string offsets are section-absolute.
		stringBlobOffsets := int(blockOffset) + dataStart + len(stringBlob)
		binary.LittleEndian.PutUint32(block[offsetPos+i*4:], uint32(stringBlobOffsets))
		stringBlob = append(stringBlob, []byte(s)...)
		stringBlob = append(stringBlob, 0)
	}
	block = append(block, stringBlob...)
	return block, warnings, nil
}

func WriteOutputFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()

	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}

	if err = os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func AppendModifyLog(path string, summary model.ModifySummary, cliArgs map[string]string, strictMatched []string, failureReason string, failureCategory string) error {
	changed := lo.Filter(summary.DexDiffs, func(d model.ModifyDexDiff, _ int) bool {
		return d.ModifiedClasses > 0
	})
	modifiedDexes := lo.Map(changed, func(d model.ModifyDexDiff, _ int) int { return d.DexIndex })
	topSamples := lo.Map(changed[:binutil.MinInt(len(changed), 4)], func(d model.ModifyDexDiff, _ int) string {
		return fmt.Sprintf("dex=%d classes=%v", d.DexIndex, d.ChangedClassIdxs)
	})
	entry := model.ModifyLogEntry{
		Timestamp:             time.Now().Format(time.RFC3339Nano),
		Cmd:                   os.Args,
		Summary:               summary,
		Args:                  cliArgs,
		ModifiedDexes:         modifiedDexes,
		TopSamples:            topSamples,
		ModifiedClassCount:    summary.ModifiedClasses,
		StrictMatched:         strictMatched,
		FailureReason:         failureReason,
		FailureCategory:       failureCategory,
		FailureCategoryCounts: summary.FailureCategoryCounts,
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(raw)
	return err
}

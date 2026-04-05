package modifier

import (
	"encoding/binary"
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// warnErr appends msg to warnings and returns it as an error.
func warnErr(warnings *[]string, msg string) error {
	*warnings = append(*warnings, msg)
	return fmt.Errorf("%s", msg)
}

// BuildVerifierSectionReplacement builds a complete verifier-deps section
// from scratch using the patch spec.
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

// BuildVerifierSectionMerge overlays a patch onto an existing verifier section.
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

// BuildVerifierDexFromPatch builds a single per-dex verifier block from a patch.
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

// BuildVerifierDexBlock assembles the raw byte block for a single dex's
// verifier data: class offset table + LEB128 pairs + extra strings.
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
		stringBlobOffsets := int(blockOffset) + dataStart + len(stringBlob)
		binary.LittleEndian.PutUint32(block[offsetPos+i*4:], uint32(stringBlobOffsets))
		stringBlob = append(stringBlob, []byte(s)...)
		stringBlob = append(stringBlob, 0)
	}
	block = append(block, stringBlob...)
	return block, warnings, nil
}

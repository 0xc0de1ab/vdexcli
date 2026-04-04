package modifier

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// buildSimpleVerifierSection builds a verifier section with 1 dex, all classes unverified.
func buildSimpleVerifierSection(classCount int) []byte {
	// Per-dex offset table: 1 dex, block starts at offset 4
	blockOffset := uint32(4)
	offsetTable := make([]byte, 4)
	binary.LittleEndian.PutUint32(offsetTable, blockOffset)

	// Class offset table: all 0xFFFFFFFF + sentinel
	classTable := make([]byte, (classCount+1)*4)
	for i := 0; i <= classCount; i++ {
		binary.LittleEndian.PutUint32(classTable[i*4:], model.NotVerifiedMarker)
	}
	// Sentinel = offset right after class table
	sentinelOff := blockOffset + uint32(len(classTable))
	binary.LittleEndian.PutUint32(classTable[classCount*4:], sentinelOff)

	// Align + extra strings count=0
	block := append(classTable, make([]byte, 0)...)
	for len(block)%4 != 0 {
		block = append(block, 0)
	}
	block = append(block, 0, 0, 0, 0) // extra string count = 0

	return append(offsetTable, block...)
}

// --- ParseVerifierDexForMerge ---

func TestParseVerifierDexForMerge_AllUnverified(t *testing.T) {
	section := buildSimpleVerifierSection(3)
	blockStart := 4 // per-dex offset = 4
	result, warnings, err := ParseVerifierDexForMerge(section, 0, blockStart, len(section), 0, 3)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, 3, result.ClassCount)
	require.Len(t, result.Classes, 3)
	for _, c := range result.Classes {
		assert.False(t, c.Verified)
	}
}

func TestParseVerifierDexForMerge_Truncated(t *testing.T) {
	raw := make([]byte, 8) // too small for 3 classes
	_, warnings, err := ParseVerifierDexForMerge(raw, 0, 0, len(raw), 0, 3)
	require.Error(t, err)
	assert.NotEmpty(t, warnings)
	assert.Contains(t, warnings[0], "truncated")
}

// --- ParseVerifierSectionForMerge ---

func TestParseVerifierSectionForMerge_Valid(t *testing.T) {
	section := buildSimpleVerifierSection(2)
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []model.DexReport{{ClassDefs: 2}}
	checksums := []uint32{0xCAFE}

	result, warnings, err := ParseVerifierSectionForMerge(section, s, dexes, checksums)
	require.NoError(t, err)
	_ = warnings
	require.Contains(t, result, 0)
	assert.Equal(t, 2, result[0].ClassCount)
}

func TestParseVerifierSectionForMerge_OutOfRange(t *testing.T) {
	s := model.VdexSection{Offset: 999, Size: 100}
	_, _, err := ParseVerifierSectionForMerge(make([]byte, 50), s, nil, []uint32{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of file range")
}

func TestParseVerifierSectionForMerge_NoDexCount(t *testing.T) {
	s := model.VdexSection{Offset: 0, Size: 10}
	_, _, err := ParseVerifierSectionForMerge(make([]byte, 10), s, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot infer dex count")
}

// --- BuildVerifierSectionMerge ---

func TestBuildVerifierSectionMerge_NoChange(t *testing.T) {
	classCount := 2
	section := buildSimpleVerifierSection(classCount)
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []model.DexReport{{ClassDefs: uint32(classCount)}}
	checksums := []uint32{0xCAFE}

	// Empty patch — no changes
	patch := model.VerifierPatchSpec{
		Mode:  "merge",
		Dexes: []model.VerifierPatchDex{},
	}

	payload, _, err := BuildVerifierSectionMerge(dexes, checksums, s, section, patch)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
}

func TestBuildVerifierSectionMerge_FlipVerified(t *testing.T) {
	classCount := 2
	section := buildSimpleVerifierSection(classCount)
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []model.DexReport{{ClassDefs: uint32(classCount)}}
	checksums := []uint32{0xCAFE}

	trueVal := true
	patch := model.VerifierPatchSpec{
		Mode: "merge",
		Dexes: []model.VerifierPatchDex{{
			DexIndex: 0,
			Classes: []model.VerifierPatchClass{
				{ClassIndex: 0, Verified: &trueVal},
			},
		}},
	}

	payload, _, err := BuildVerifierSectionMerge(dexes, checksums, s, section, patch)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
}

func TestBuildVerifierSectionMerge_NoDexCount(t *testing.T) {
	s := model.VdexSection{Offset: 0, Size: 10}
	patch := model.VerifierPatchSpec{Mode: "merge"}
	_, _, err := BuildVerifierSectionMerge(nil, nil, s, make([]byte, 10), patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot infer dex count")
}

// --- CompareVerifierSectionDiff ---

func TestCompareVerifierSectionDiff_Identical(t *testing.T) {
	classCount := 2
	section := buildSimpleVerifierSection(classCount)
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []model.DexReport{{ClassDefs: uint32(classCount)}}
	checksums := []uint32{0xCAFE}

	diff, dexDiffs, _, err := CompareVerifierSectionDiff(section, s, dexes, checksums, section)
	require.NoError(t, err)
	assert.Equal(t, classCount, diff.TotalClasses)
	assert.Equal(t, 0, diff.ModifiedClasses)
	assert.Equal(t, classCount, diff.UnmodifiedClasses)
	require.Len(t, dexDiffs, 1)
	assert.Equal(t, 0, dexDiffs[0].ModifiedClasses)
}

func TestCompareVerifierSectionDiff_WithChange(t *testing.T) {
	classCount := 2
	original := buildSimpleVerifierSection(classCount)
	s := model.VdexSection{Offset: 0, Size: uint32(len(original))}
	dexes := []model.DexReport{{ClassDefs: uint32(classCount)}}
	checksums := []uint32{0xCAFE}

	// Build a modified payload using replace
	trueVal := true
	falseVal := false
	patch := model.VerifierPatchSpec{
		Mode: "replace",
		Dexes: []model.VerifierPatchDex{{
			DexIndex: 0,
			Classes: []model.VerifierPatchClass{
				{ClassIndex: 0, Verified: &trueVal},  // changed from unverified
				{ClassIndex: 1, Verified: &falseVal}, // same
			},
		}},
	}
	modified, _, err := BuildVerifierSectionReplacement(dexes, checksums, patch)
	require.NoError(t, err)

	diff, dexDiffs, _, _ := CompareVerifierSectionDiff(original, s, dexes, checksums, modified)
	assert.Equal(t, 2, diff.TotalClasses)
	assert.Equal(t, 1, diff.ModifiedClasses)
	assert.Equal(t, 1, diff.UnmodifiedClasses)
	require.Len(t, dexDiffs, 1)
	assert.Equal(t, 1, dexDiffs[0].ModifiedClasses)
}

// --- BuildVerifierDexBlock with pairs ---

func TestBuildVerifierDexBlock_WithPairs(t *testing.T) {
	pairs := make([][]model.VerifierPatchPair, 2)
	pairs[0] = []model.VerifierPatchPair{{Dest: 5, Src: 10}}
	pairs[1] = nil

	block, warnings, err := BuildVerifierDexBlock(2, 20,
		[]bool{true, false}, pairs, []string{"extra"}, 100)
	require.NoError(t, err)
	assert.NotEmpty(t, block)
	_ = warnings
}

func TestBuildVerifierDexBlock_ShortPairsArray(t *testing.T) {
	_, _, err := BuildVerifierDexBlock(3, 0,
		[]bool{true, true, true}, make([][]model.VerifierPatchPair, 1), nil, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "class pairs array shorter")
}

// --- warnErr ---

func TestWarnErr(t *testing.T) {
	var warnings []string
	err := warnErr(&warnings, "test message")
	require.Error(t, err)
	assert.Equal(t, "test message", err.Error())
	require.Len(t, warnings, 1)
	assert.Equal(t, "test message", warnings[0])
}

// --- Edge cases for merge paths ---

func TestParseVerifierDexForMerge_WithVerifiedClass(t *testing.T) {
	// Build section: 2 classes, class 0 verified with pair (5,10), class 1 unverified
	classCount := 2
	blockOffset := uint32(4)

	// Build via BuildVerifierDexBlock to get correct encoding
	pairs := make([][]model.VerifierPatchPair, classCount)
	pairs[0] = []model.VerifierPatchPair{{Dest: 5, Src: 10}}

	block, _, err := BuildVerifierDexBlock(classCount, 20,
		[]bool{true, false}, pairs, []string{"Lextra;"}, blockOffset)
	require.NoError(t, err)

	// Assemble section: per-dex offset table + block
	section := make([]byte, 4+len(block))
	binary.LittleEndian.PutUint32(section[0:], blockOffset)
	copy(section[4:], block)

	result, _, err := ParseVerifierDexForMerge(section, 0, 4, len(section), 0, classCount)
	require.NoError(t, err)
	assert.Equal(t, classCount, result.ClassCount)
	require.Len(t, result.Classes, classCount)

	assert.True(t, result.Classes[0].Verified)
	require.Len(t, result.Classes[0].Pairs, 1)
	assert.Equal(t, uint32(5), result.Classes[0].Pairs[0].Dest)
	assert.Equal(t, uint32(10), result.Classes[0].Pairs[0].Src)

	assert.False(t, result.Classes[1].Verified)

	require.Len(t, result.ExtraString, 1)
	assert.Equal(t, "Lextra;", result.ExtraString[0])
}

func TestParseVerifierDexForMerge_MalformedBounds(t *testing.T) {
	// Build a section where a class offset points outside section
	section := make([]byte, 100)
	blockStart := 0
	classCount := 1
	// class 0 offset = 9999 (way outside)
	binary.LittleEndian.PutUint32(section[0:], 9999)
	// sentinel
	binary.LittleEndian.PutUint32(section[4:], 9999)

	_, warnings, err := ParseVerifierDexForMerge(section, 0, blockStart, 20, 0, classCount)
	require.Error(t, err)
	assert.NotEmpty(t, warnings)
	assert.Contains(t, warnings[0], "malformed")
}

func TestBuildVerifierSectionMerge_ExtraStringsAppended(t *testing.T) {
	classCount := 1
	section := buildSimpleVerifierSection(classCount)
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []model.DexReport{{ClassDefs: uint32(classCount)}}
	checksums := []uint32{0xCAFE}

	patch := model.VerifierPatchSpec{
		Mode: "merge",
		Dexes: []model.VerifierPatchDex{{
			DexIndex:     0,
			ExtraStrings: []string{"Lmerged/Extra;"},
		}},
	}

	payload, warnings, err := BuildVerifierSectionMerge(dexes, checksums, s, section, patch)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
	_ = warnings
}

func TestBuildVerifierSectionMerge_DuplicateDexIndex(t *testing.T) {
	section := buildSimpleVerifierSection(1)
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []model.DexReport{{ClassDefs: 1}}
	checksums := []uint32{0xCAFE}

	patch := model.VerifierPatchSpec{
		Mode:  "merge",
		Dexes: []model.VerifierPatchDex{{DexIndex: 0}, {DexIndex: 0}},
	}

	_, _, err := BuildVerifierSectionMerge(dexes, checksums, s, section, patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestBuildVerifierSectionMerge_DexIndexExceedsCount(t *testing.T) {
	section := buildSimpleVerifierSection(1)
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []model.DexReport{{ClassDefs: 1}}
	checksums := []uint32{0xCAFE}

	patch := model.VerifierPatchSpec{
		Mode:  "merge",
		Dexes: []model.VerifierPatchDex{{DexIndex: 99}},
	}

	_, _, err := BuildVerifierSectionMerge(dexes, checksums, s, section, patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds dex count")
}

func TestCompareVerifierSectionDiff_NoDexes(t *testing.T) {
	s := model.VdexSection{Offset: 0, Size: 0}
	diff, dexDiffs, _, err := CompareVerifierSectionDiff(nil, s, nil, nil, nil)
	assert.Error(t, err)
	assert.Equal(t, 0, diff.TotalClasses)
	assert.Empty(t, dexDiffs)
}

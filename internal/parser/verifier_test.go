package parser

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// buildVerifierSection constructs a raw verifier-deps section with the given
// per-dex blocks embedded at sectionOffset within the returned byte slice.
// Each dex block contains: class offset table + LEB128 pairs + extra strings.
func buildVerifierSection(sectionOffset int, blocks []verifierDexBlock) []byte {
	dexCount := len(blocks)
	// Phase 1: build per-dex payloads
	payloads := make([][]byte, dexCount)
	for i, b := range blocks {
		payloads[i] = buildVerifierDexPayload(b)
	}

	// Phase 2: compute offsets (section-absolute)
	perDexTable := make([]byte, dexCount*4)
	cursor := dexCount * 4
	for i, p := range payloads {
		// 4-byte align
		for cursor%4 != 0 {
			cursor++
		}
		binary.LittleEndian.PutUint32(perDexTable[i*4:], uint32(cursor))
		cursor += len(p)
	}

	// Phase 3: assemble section
	section := make([]byte, cursor)
	copy(section, perDexTable)
	off := dexCount * 4
	for _, p := range payloads {
		for off%4 != 0 {
			off++
		}
		copy(section[off:], p)
		off += len(p)
	}

	// Embed at sectionOffset within a larger buffer
	raw := make([]byte, sectionOffset+len(section))
	copy(raw[sectionOffset:], section)
	return raw
}

type verifierDexBlock struct {
	classCount int
	// per class: nil=unverified, empty=verified no pairs, non-empty=verified with pairs
	classPairs [][]byte
	extras     []string
}

func buildVerifierDexPayload(b verifierDexBlock) []byte {
	numClasses := b.classCount
	offsetTableSize := (numClasses + 1) * 4
	// We need to know the size of the offset table to compute section-absolute offsets.
	// But we're building a payload relative to dex-block start; the caller adjusts.
	// For now, offsets are relative to the per-dex offset table entry (section-absolute).
	// The caller passes blockOffset, so we build with placeholder offsets then fixup.

	// Simpler approach: build pairs data first, then compute offsets.
	var pairsData []byte
	classOffsets := make([]uint32, numClasses+1)

	for i := 0; i < numClasses; i++ {
		if i >= len(b.classPairs) || b.classPairs[i] == nil {
			classOffsets[i] = model.NotVerifiedMarker
		} else {
			// offset = offsetTableSize + len(pairsData so far)
			// But these will be adjusted to section-absolute by the caller.
			// For unit testing, we set them relative to block start, then
			// ParseVerifierSection will read them as section-absolute.
			// So we need to ADD the block's position within the section.
			// We'll handle this in buildVerifierSection.
			classOffsets[i] = uint32(offsetTableSize + len(pairsData))
			pairsData = append(pairsData, b.classPairs[i]...)
		}
	}
	classOffsets[numClasses] = uint32(offsetTableSize + len(pairsData))

	// Build block
	block := make([]byte, offsetTableSize)
	for i, off := range classOffsets {
		binary.LittleEndian.PutUint32(block[i*4:], off)
	}
	block = append(block, pairsData...)

	// Align to 4
	for len(block)%4 != 0 {
		block = append(block, 0)
	}

	// Extra strings
	strCount := len(b.extras)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(strCount))
	block = append(block, buf...)

	strOffsetBase := len(block) + strCount*4
	for _, s := range b.extras {
		off := make([]byte, 4)
		binary.LittleEndian.PutUint32(off, uint32(strOffsetBase))
		block = append(block, off...)
		strOffsetBase += len(s) + 1
	}
	for _, s := range b.extras {
		block = append(block, []byte(s)...)
		block = append(block, 0)
	}

	return block
}

func TestParseVerifierSection_OutOfRange(t *testing.T) {
	raw := make([]byte, 100)
	s := model.VdexSection{Offset: 200, Size: 50} // beyond raw
	report, diags := ParseVerifierSection(raw, s, nil, 1)
	assert.NotNil(t, report)
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "out of file range")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestParseVerifierSection_EmptySection(t *testing.T) {
	raw := make([]byte, 100)
	s := model.VdexSection{Offset: 0, Size: 0}
	report, diags := ParseVerifierSection(raw, s, nil, 0)
	assert.NotNil(t, report)
	assert.Empty(t, report.Dexes)
	assert.Empty(t, diags)
}

func TestParseVerifierSection_IndexTableTruncated(t *testing.T) {
	raw := make([]byte, 10)
	s := model.VdexSection{Offset: 0, Size: 6} // need 8 bytes for 2 dex offsets, only 6
	report, diags := ParseVerifierSection(raw, s, nil, 2)
	assert.NotNil(t, report)
	require.NotEmpty(t, diags)
	assert.Contains(t, diags[0].Message, "truncated")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestParseVerifierSection_BlockOutsideSection(t *testing.T) {
	raw := make([]byte, 20)
	// per-dex offset table: dex 0 at offset 9999 (outside section)
	binary.LittleEndian.PutUint32(raw[0:], 9999)
	s := model.VdexSection{Offset: 0, Size: 20}
	report, diags := ParseVerifierSection(raw, s, nil, 1)
	assert.NotNil(t, report)
	assert.Empty(t, report.Dexes)
	require.NotEmpty(t, diags)
	assert.Contains(t, diags[0].Message, "outside section")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestParseVerifierSection_SingleDex_AllUnverified(t *testing.T) {
	classCount := 3
	sectionOffset := 0

	// Build: 1 dex, 3 classes all unverified, no extras
	block := buildVerifierDexPayload(verifierDexBlock{
		classCount: classCount,
		classPairs: [][]byte{nil, nil, nil},
		extras:     nil,
	})

	// Section: per-dex offset table (1 entry) + block
	perDexOff := uint32(4) // block starts right after the 4-byte offset table
	section := make([]byte, 4+len(block))
	binary.LittleEndian.PutUint32(section[0:], perDexOff)
	copy(section[4:], block)

	raw := make([]byte, sectionOffset+len(section))
	copy(raw[sectionOffset:], section)

	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(section))}
	dexes := []*model.DexContext{{Rep: model.DexReport{ClassDefs: uint32(classCount)}}}
	report, _ := ParseVerifierSection(raw, s, dexes, 1)

	require.Len(t, report.Dexes, 1)
	assert.Equal(t, 0, report.Dexes[0].VerifiedClasses)
	assert.Equal(t, 3, report.Dexes[0].UnverifiedClasses)
	assert.Equal(t, 0, report.Dexes[0].AssignabilityPairs)
}

func TestParseVerifierSection_SingleDex_WithPairs(t *testing.T) {
	classCount := 2

	// Class 0: verified with 1 pair (dest=5, src=10)
	// Class 1: unverified
	block := buildVerifierDexPayload(verifierDexBlock{
		classCount: classCount,
		classPairs: [][]byte{
			{0x05, 0x0A}, // LEB128: dest=5, src=10
			nil,          // unverified
		},
	})

	perDexOff := uint32(4)
	section := make([]byte, 4+len(block))
	binary.LittleEndian.PutUint32(section[0:], perDexOff)
	copy(section[4:], block)

	// Fix class offsets to be section-absolute
	for ci := 0; ci <= classCount; ci++ {
		off := 4 + ci*4
		val := binary.LittleEndian.Uint32(section[off:])
		if val != model.NotVerifiedMarker {
			binary.LittleEndian.PutUint32(section[off:], val+perDexOff)
		}
	}

	raw := section
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	dexes := []*model.DexContext{{
		Rep:     model.DexReport{ClassDefs: uint32(classCount)},
		Strings: []string{"str0", "str1", "str2", "str3", "str4", "str5", "str6", "str7", "str8", "str9", "str10"},
	}}
	report, _ := ParseVerifierSection(raw, s, dexes, 1)

	require.Len(t, report.Dexes, 1)
	vd := report.Dexes[0]
	assert.Equal(t, 1, vd.VerifiedClasses)
	assert.Equal(t, 1, vd.UnverifiedClasses)
	assert.Equal(t, 1, vd.AssignabilityPairs)
	require.Len(t, vd.FirstPairs, 1)
	assert.Equal(t, uint32(5), vd.FirstPairs[0].DestID)
	assert.Equal(t, uint32(10), vd.FirstPairs[0].SrcID)
	assert.Equal(t, "str5", vd.FirstPairs[0].Dest)
	assert.Equal(t, "str10", vd.FirstPairs[0].Src)
}

func TestResolveVerifierString_DexString(t *testing.T) {
	strs := []string{"a", "b", "c"}
	assert.Equal(t, "b", resolveVerifierString(strs, nil, 3, 1))
}

func TestResolveVerifierString_ExtraString(t *testing.T) {
	strs := []string{"a", "b"}
	extras := []string{"extra0", "extra1"}
	assert.Equal(t, "extra1", resolveVerifierString(strs, extras, 2, 3))
}

func TestResolveVerifierString_OutOfRange(t *testing.T) {
	assert.Equal(t, "string_99", resolveVerifierString(nil, nil, 0, 99))
}

// --- inferClassCount ---

func TestInferClassCount_AllUnverified(t *testing.T) {
	// 3 classes all unverified + sentinel
	section := make([]byte, 100)
	blockStart := 0
	sectionStart := 0
	sentinelOff := uint32(16) // (3+1)*4 = 16
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint32(section[i*4:], model.NotVerifiedMarker)
	}
	binary.LittleEndian.PutUint32(section[3*4:], sentinelOff) // sentinel
	// Next value is data (breaks pattern)
	binary.LittleEndian.PutUint32(section[4*4:], 0xDEADBEEF)

	result := inferClassCount(section, sectionStart, blockStart, len(section))
	assert.Equal(t, 3, result)
}

func TestInferClassCount_MixedVerified(t *testing.T) {
	// 2 classes: class 0 verified at offset 12, class 1 unverified, sentinel at 14
	section := make([]byte, 100)
	binary.LittleEndian.PutUint32(section[0:], 12)                      // class 0 verified, data at 12
	binary.LittleEndian.PutUint32(section[4:], model.NotVerifiedMarker) // class 1
	binary.LittleEndian.PutUint32(section[8:], 14)                      // sentinel
	// Data area
	section[12] = 0x05
	section[13] = 0x0A
	// After sentinel: something that breaks pattern
	binary.LittleEndian.PutUint32(section[14:], 0xFFFFFF00)

	result := inferClassCount(section, 0, 0, len(section))
	assert.Equal(t, 2, result)
}

func TestInferClassCount_TooSmall(t *testing.T) {
	section := make([]byte, 4)
	result := inferClassCount(section, 0, 0, len(section))
	assert.Equal(t, 0, result)
}

func TestInferClassCount_Empty(t *testing.T) {
	result := inferClassCount(nil, 0, 0, 0)
	assert.Equal(t, 0, result)
}

// === Uncovered parseVerifierDex paths ===

func TestParseVerifierDex_MalformedChain(t *testing.T) {
	// All offsets are NotVerifiedMarker except class 0 which is verified,
	// but sentinel is also NotVerifiedMarker → nextValid exceeds numClass
	classCount := 2
	offsetTableSize := (classCount + 1) * 4
	block := make([]byte, offsetTableSize+8) // some padding
	// class 0: verified, pointing to data area
	binary.LittleEndian.PutUint32(block[0:], uint32(offsetTableSize))
	// class 1: unverified
	binary.LittleEndian.PutUint32(block[4:], model.NotVerifiedMarker)
	// sentinel: also unverified → chain malformed
	binary.LittleEndian.PutUint32(block[8:], model.NotVerifiedMarker)

	sectionOffset := 0
	raw := make([]byte, sectionOffset+4+len(block))
	// per-dex offset table: 1 entry pointing to block start
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(raw))}
	_, diags := ParseVerifierSection(raw, s, nil, 1)

	hasMalformed := false
	for _, d := range diags {
		if d.Code == model.WarnVerifierMalformedChain {
			hasMalformed = true
		}
	}
	assert.True(t, hasMalformed, "should detect malformed chain")
}

func TestParseVerifierDex_MalformedBounds(t *testing.T) {
	// class 0 verified but offset points before block start (section-absolute 0,
	// block starts at offset 4 → setStart=0 < blockStart=4 → malformed)
	classCount := 1
	offsetTableSize := (classCount + 1) * 4

	block := make([]byte, offsetTableSize+4)
	binary.LittleEndian.PutUint32(block[0:], 0) // class 0: section-absolute 0
	binary.LittleEndian.PutUint32(block[4:], uint32(offsetTableSize))

	sectionOffset := 0
	raw := make([]byte, sectionOffset+4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4) // block at offset 4
	copy(raw[4:], block)

	// Provide dex context with classCount=1 to skip DM inference
	dexCtx := []*model.DexContext{{Rep: model.DexReport{ClassDefs: 1}}}
	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(raw))}
	_, diags := ParseVerifierSection(raw, s, dexCtx, 1)

	hasBounds := false
	for _, d := range diags {
		if d.Code == model.WarnVerifierMalformedBounds {
			hasBounds = true
		}
	}
	assert.True(t, hasBounds, "should detect malformed bounds")
}

func TestParseVerifierDex_InvalidLEB128(t *testing.T) {
	// Build a block with invalid LEB128 in pairs data
	classCount := 1
	offsetTableSize := (classCount + 1) * 4

	// Invalid LEB128: 5 continuation bytes (0x80) without termination
	badLEB := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80}

	block := make([]byte, offsetTableSize)
	binary.LittleEndian.PutUint32(block[0:], uint32(offsetTableSize))                  // class 0 offset
	binary.LittleEndian.PutUint32(block[4:], uint32(offsetTableSize+len(badLEB)))       // sentinel
	block = append(block, badLEB...)
	// pad + extra strings count = 0
	for len(block)%4 != 0 {
		block = append(block, 0)
	}
	block = append(block, 0, 0, 0, 0) // numStrings=0

	sectionOffset := 0
	raw := make([]byte, sectionOffset+4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(raw))}
	_, diags := ParseVerifierSection(raw, s, nil, 1)

	hasLEB := false
	for _, d := range diags {
		if d.Code == model.WarnVerifierInvalidLEB128 {
			hasLEB = true
		}
	}
	assert.True(t, hasLEB, "should detect invalid LEB128")
}

func TestParseVerifierDex_ExtraStringsTruncated(t *testing.T) {
	// Build block with pairs but extra strings table that exceeds section
	classCount := 1
	offsetTableSize := (classCount + 1) * 4

	block := make([]byte, offsetTableSize)
	// class 0 unverified
	binary.LittleEndian.PutUint32(block[0:], model.NotVerifiedMarker)
	binary.LittleEndian.PutUint32(block[4:], uint32(offsetTableSize)) // sentinel

	// pad to 4-byte align
	for len(block)%4 != 0 {
		block = append(block, 0)
	}
	// numStrings = 999 (way more than available)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 999)
	block = append(block, buf...)

	sectionOffset := 0
	raw := make([]byte, sectionOffset+4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(raw))}
	_, diags := ParseVerifierSection(raw, s, nil, 1)

	hasTrunc := false
	for _, d := range diags {
		if d.Code == model.WarnVerifierExtrasTruncated {
			hasTrunc = true
		}
	}
	assert.True(t, hasTrunc, "should detect truncated extra strings table")
}

func TestParseVerifierDex_ExtraStringInvalidOffset(t *testing.T) {
	// Build block with 1 extra string whose offset points outside section
	classCount := 1
	offsetTableSize := (classCount + 1) * 4

	block := make([]byte, offsetTableSize)
	binary.LittleEndian.PutUint32(block[0:], model.NotVerifiedMarker)
	binary.LittleEndian.PutUint32(block[4:], uint32(offsetTableSize))

	for len(block)%4 != 0 {
		block = append(block, 0)
	}
	// numStrings = 1
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 1)
	block = append(block, buf...)
	// string offset = 0xFFFF (way outside section)
	off := make([]byte, 4)
	binary.LittleEndian.PutUint32(off, 0xFFFF)
	block = append(block, off...)

	sectionOffset := 0
	raw := make([]byte, sectionOffset+4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(raw))}
	report, diags := ParseVerifierSection(raw, s, nil, 1)

	hasInvalid := false
	for _, d := range diags {
		if d.Code == model.WarnVerifierExtraInvalid {
			hasInvalid = true
		}
	}
	assert.True(t, hasInvalid, "should detect invalid extra string offset")
	require.NotEmpty(t, report.Dexes)
	assert.Equal(t, 1, report.Dexes[0].ExtraStringCount)
}

func TestParseVerifierDex_NoExtraStrings_EarlyReturn(t *testing.T) {
	// Block with class data but section ends before extra strings count
	classCount := 1
	offsetTableSize := (classCount + 1) * 4

	block := make([]byte, offsetTableSize)
	binary.LittleEndian.PutUint32(block[0:], model.NotVerifiedMarker)
	binary.LittleEndian.PutUint32(block[4:], uint32(offsetTableSize))
	// No extra strings area — section ends right after offset table

	sectionOffset := 0
	raw := make([]byte, sectionOffset+4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(raw))}
	report, diags := ParseVerifierSection(raw, s, nil, 1)

	// Should return without error, ExtraStringCount = 0
	require.NotEmpty(t, report.Dexes)
	assert.Equal(t, 0, report.Dexes[0].ExtraStringCount)
	// No truncation diag since section cleanly ends
	for _, d := range diags {
		assert.NotEqual(t, model.WarnVerifierExtrasTruncated, d.Code)
	}
}

func TestParseVerifierDex_DMInference(t *testing.T) {
	// No dex context (DM format) — should infer class count and emit diagnostic
	classCount := 2
	offsetTableSize := (classCount + 1) * 4

	block := make([]byte, offsetTableSize+8)
	binary.LittleEndian.PutUint32(block[0:], model.NotVerifiedMarker) // class 0
	binary.LittleEndian.PutUint32(block[4:], model.NotVerifiedMarker) // class 1
	binary.LittleEndian.PutUint32(block[8:], uint32(offsetTableSize)) // sentinel
	// extra strings: count=0
	for len(block)%4 != 0 {
		block = append(block, 0)
	}
	block = append(block, 0, 0, 0, 0)

	sectionOffset := 0
	raw := make([]byte, sectionOffset+4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	s := model.VdexSection{Offset: uint32(sectionOffset), Size: uint32(len(raw))}
	// nil dexes = DM format, expected=1
	report, diags := ParseVerifierSection(raw, s, nil, 1)

	hasInferred := false
	for _, d := range diags {
		if d.Code == model.WarnVerifierInferredCount {
			hasInferred = true
			assert.Contains(t, d.Hint, "heuristic")
		}
	}
	assert.True(t, hasInferred, "should emit DM inference diagnostic")
	require.NotEmpty(t, report.Dexes)
	assert.Equal(t, 2, report.Dexes[0].UnverifiedClasses)
}

func TestParseVerifierDex_SourceLEB128Error(t *testing.T) {
	// dest LEB128 succeeds, but source LEB128 is invalid
	classCount := 1
	offsetTableSize := (classCount + 1) * 4
	// Pair data: valid dest (0x05) + invalid source (5 continuation bytes)
	pairData := []byte{0x05, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}

	block := make([]byte, offsetTableSize)
	binary.LittleEndian.PutUint32(block[0:], uint32(offsetTableSize))
	binary.LittleEndian.PutUint32(block[4:], uint32(offsetTableSize+len(pairData)))
	block = append(block, pairData...)
	for len(block)%4 != 0 {
		block = append(block, 0)
	}
	block = append(block, 0, 0, 0, 0) // numStrings=0

	raw := make([]byte, 4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	dexCtx := []*model.DexContext{{Rep: model.DexReport{ClassDefs: 1}}}
	s := model.VdexSection{Offset: 0, Size: uint32(len(raw))}
	_, diags := ParseVerifierSection(raw, s, dexCtx, 1)

	hasSourceLEB := false
	for _, d := range diags {
		if d.Code == model.WarnVerifierInvalidLEB128 && strings.Contains(d.Message, "source") {
			hasSourceLEB = true
		}
	}
	assert.True(t, hasSourceLEB, "should detect invalid source LEB128")
}

func TestParseVerifierDex_ValidExtraStrings(t *testing.T) {
	// Build block with 1 verified class, 0 pairs, 1 valid extra string
	classCount := 1
	offsetTableSize := (classCount + 1) * 4

	block := make([]byte, offsetTableSize)
	binary.LittleEndian.PutUint32(block[0:], uint32(offsetTableSize)) // class 0 → points to end of offsets (0 pairs)
	binary.LittleEndian.PutUint32(block[4:], uint32(offsetTableSize)) // sentinel = same offset

	for len(block)%4 != 0 {
		block = append(block, 0)
	}
	// Extra strings: count=1
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 1)
	block = append(block, buf...)
	// String offset: section-absolute, points to after the offset table
	strDataOff := 4 + len(block) + 4 // block start(4) + current block + 4 bytes for this offset
	off := make([]byte, 4)
	binary.LittleEndian.PutUint32(off, uint32(strDataOff))
	block = append(block, off...)
	block = append(block, []byte("Lcom/Test;\x00")...)

	raw := make([]byte, 4+len(block))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], block)

	dexCtx := []*model.DexContext{{Rep: model.DexReport{ClassDefs: 1}}}
	s := model.VdexSection{Offset: 0, Size: uint32(len(raw))}
	report, _ := ParseVerifierSection(raw, s, dexCtx, 1)

	require.NotEmpty(t, report.Dexes)
	assert.Equal(t, 1, report.Dexes[0].ExtraStringCount)
}

func TestInferClassCount_DecreasingSentinel(t *testing.T) {
	// Offsets: 20, 24, 16 (decreasing — should break)
	section := make([]byte, 100)
	binary.LittleEndian.PutUint32(section[0:], 20) // class 0
	binary.LittleEndian.PutUint32(section[4:], 24) // class 1
	binary.LittleEndian.PutUint32(section[8:], 16) // class 2: decreasing → break
	result := inferClassCount(section, 0, 0, len(section))
	assert.Equal(t, 1, result) // 2 entries before break, minus sentinel = 1
}

func TestInferClassCount_LargeSection(t *testing.T) {
	// Section large enough to trigger maxEntries cap
	size := 0x10001 * 4
	section := make([]byte, size)
	for i := 0; i < 0x10001; i++ {
		binary.LittleEndian.PutUint32(section[i*4:], model.NotVerifiedMarker)
	}
	result := inferClassCount(section, 0, 0, size)
	assert.Equal(t, 0x10000-1, result) // capped at 0x10000 entries, minus sentinel
}

func TestParseVerifierDex_DMInfer_ThenBlockTruncated(t *testing.T) {
	// Section too small for inferred class count's offset table
	section := make([]byte, 12) // only 12 bytes
	// infer will find ~2 entries, but offset table needs (2+1)*4=12 bytes exactly
	binary.LittleEndian.PutUint32(section[0:], model.NotVerifiedMarker)
	binary.LittleEndian.PutUint32(section[4:], model.NotVerifiedMarker)
	binary.LittleEndian.PutUint32(section[8:], 0xDEADBEEF) // breaks inference

	raw := make([]byte, 4+len(section))
	binary.LittleEndian.PutUint32(raw[0:], 4)
	copy(raw[4:], section)

	s := model.VdexSection{Offset: 0, Size: uint32(len(raw))}
	_, diags := ParseVerifierSection(raw, s, nil, 1)

	// Should either infer small count or hit truncation
	_ = diags // no crash is the main assertion
}

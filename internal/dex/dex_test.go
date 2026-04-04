package dex

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func buildMinDex(classDefsSize uint32) []byte {
	d := make([]byte, 0x70)
	copy(d[0:4], "dex\n")
	copy(d[4:8], "035\x00")
	binary.LittleEndian.PutUint32(d[0x08:], 0xCAFE)
	binary.LittleEndian.PutUint32(d[0x20:], 0x70)
	binary.LittleEndian.PutUint32(d[0x24:], 0x70)
	binary.LittleEndian.PutUint32(d[0x28:], 0x12345678)
	binary.LittleEndian.PutUint32(d[0x60:], classDefsSize)
	return d
}

// --- Parse ---

func TestParse_Valid(t *testing.T) {
	raw := buildMinDex(3)
	ctx, used, err := Parse(raw, 0x40)
	require.NoError(t, err)
	assert.Equal(t, 0x70, used)
	assert.Equal(t, uint32(0x40), ctx.Rep.Offset)
	assert.Equal(t, "dex\n", ctx.Rep.Magic)
	assert.Equal(t, "035", ctx.Rep.Version)
	assert.Equal(t, uint32(3), ctx.Rep.ClassDefs)
	assert.Equal(t, "little-endian", ctx.Rep.Endian)
	assert.Equal(t, uint32(0xCAFE), ctx.Rep.ChecksumId)
	assert.NotEmpty(t, ctx.Rep.Signature)
}

func TestParse_TooShort(t *testing.T) {
	_, _, err := Parse(make([]byte, 0x50), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shorter than header")
}

func TestParse_BadMagic(t *testing.T) {
	raw := make([]byte, 0x70)
	copy(raw[0:4], "oops")
	_, _, err := Parse(raw, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid magic")
}

func TestParse_BadFileSize(t *testing.T) {
	raw := buildMinDex(0)
	binary.LittleEndian.PutUint32(raw[0x20:], 0x10) // too small
	_, _, err := Parse(raw, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid file_size")
}

func TestParse_DeclaredExceedsAvailable(t *testing.T) {
	raw := buildMinDex(0)
	binary.LittleEndian.PutUint32(raw[0x20:], 0x1000) // claims 4096 but only 112
	ctx, used, err := Parse(raw, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds available bytes")
	assert.NotNil(t, ctx)
	assert.Equal(t, 0x70, used)
}

func TestParse_BigEndianTag(t *testing.T) {
	raw := buildMinDex(0)
	binary.LittleEndian.PutUint32(raw[0x28:], 0x78563412) // big-endian tag
	ctx, _, err := Parse(raw, 0)
	require.NoError(t, err)
	assert.Equal(t, "big-endian", ctx.Rep.Endian)
}

// --- ParseSection ---

func TestParseSection_SingleDex(t *testing.T) {
	dexData := buildMinDex(2)
	raw := make([]byte, 200)
	copy(raw[60:], dexData)
	s := model.VdexSection{Offset: 60, Size: uint32(len(dexData))}
	ctxs, warnings := ParseSection(raw, s, 1)
	require.Len(t, ctxs, 1)
	assert.Equal(t, 0, ctxs[0].Rep.Index)
	_ = warnings
}

func TestParseSection_OutOfRange(t *testing.T) {
	raw := make([]byte, 50)
	s := model.VdexSection{Offset: 100, Size: 50}
	ctxs, diags := ParseSection(raw, s, 1)
	assert.Empty(t, ctxs)
	require.NotEmpty(t, diags)
	assert.Contains(t, diags[0].Message, "out of file range")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestParseSection_Truncated(t *testing.T) {
	raw := make([]byte, 80)
	s := model.VdexSection{Offset: 0, Size: 80} // only 80 bytes, need 0x70=112
	ctxs, diags := ParseSection(raw, s, 1)
	assert.Empty(t, ctxs)
	assert.NotEmpty(t, diags)
}

// --- ParseStrings ---

func TestParseStrings_Empty(t *testing.T) {
	strs, m, err := ParseStrings(nil, 0, 0)
	require.NoError(t, err)
	assert.Empty(t, strs)
	assert.Empty(t, m)
}

func TestParseStrings_OutOfRange(t *testing.T) {
	_, _, err := ParseStrings(make([]byte, 10), 100, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestParseStrings_Valid(t *testing.T) {
	// Build: string_ids table at offset 0, 1 entry pointing to offset 8.
	// At offset 8: ULEB128 length (5) + "hello" + null.
	raw := make([]byte, 20)
	binary.LittleEndian.PutUint32(raw[0:], 8) // string_id[0] → offset 8
	raw[8] = 5                                // ULEB128 length
	copy(raw[9:], "hello\x00")

	strs, m, err := ParseStrings(raw, 1, 0)
	require.NoError(t, err)
	require.Len(t, strs, 1)
	assert.Equal(t, "hello", strs[0])
	assert.Equal(t, "hello", m[8])
}

// --- ParseClassDefs ---

func TestParseClassDefs_Zero(t *testing.T) {
	result, err := ParseClassDefs(nil, nil, 0, 0, 0, 0)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestParseClassDefs_TypeIdsOutOfRange(t *testing.T) {
	_, err := ParseClassDefs(make([]byte, 10), nil, 100, 0, 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type_ids table out of range")
}

func TestParseClassDefs_ClassDefsOutOfRange(t *testing.T) {
	_, err := ParseClassDefs(make([]byte, 100), nil, 0, 0, 0, 100)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "class_defs table out of range")
}

func TestParseClassDefs_ResolvesDescriptor(t *testing.T) {
	strs := []string{"Ljava/lang/Object;", "Lcom/example/Foo;"}
	// type_ids: 2 entries at offset 0. type_id[0]=string 0, type_id[1]=string 1
	// class_defs: 1 entry at offset 8. class_idx=1 (→ type_id[1] → string 1)
	raw := make([]byte, 48)
	binary.LittleEndian.PutUint32(raw[0:], 0) // type_id[0] → string 0
	binary.LittleEndian.PutUint32(raw[4:], 1) // type_id[1] → string 1
	binary.LittleEndian.PutUint32(raw[8:], 1) // class_def[0].class_idx = 1

	classes, err := ParseClassDefs(raw, strs, 2, 0, 8, 1)
	require.NoError(t, err)
	require.Len(t, classes, 1)
	assert.Equal(t, "Lcom/example/Foo;", classes[0])
}

// --- parseModifiedUtf8 edge cases ---

func TestParseStrings_InvalidOffset(t *testing.T) {
	raw := make([]byte, 20)
	binary.LittleEndian.PutUint32(raw[0:], 999) // string_id[0] → offset 999 (out of range)
	_, _, err := ParseStrings(raw, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid offset")
}

func TestParseStrings_MalformedUtf8(t *testing.T) {
	// ULEB128 length pointing past end of data
	raw := make([]byte, 12)
	binary.LittleEndian.PutUint32(raw[0:], 4) // string_id[0] → offset 4
	raw[4] = 0x80                             // ULEB128 continuation but no next byte at boundary
	raw[5] = 0x80
	raw[6] = 0x80
	raw[7] = 0x80
	raw[8] = 0x80 // 5-byte overflow
	raw[9] = 0x01
	_, _, err := ParseStrings(raw, 1, 0)
	require.Error(t, err)
}

func TestParseSection_MultipleDexes(t *testing.T) {
	dex0 := buildMinDex(1)
	dex1 := buildMinDex(2)
	raw := make([]byte, 300)
	copy(raw[60:], dex0)
	copy(raw[60+0x70:], dex1)
	s := model.VdexSection{Offset: 60, Size: uint32(0x70 * 2)}
	ctxs, _ := ParseSection(raw, s, 2)
	assert.Len(t, ctxs, 2)
	assert.Equal(t, 0, ctxs[0].Rep.Index)
	assert.Equal(t, 1, ctxs[1].Rep.Index)
}

func TestParse_HeaderSizeExceedsFileSize(t *testing.T) {
	raw := buildMinDex(0)
	binary.LittleEndian.PutUint32(raw[0x24:], 0x1000) // header_size > file_size
	_, _, err := Parse(raw, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "header_size")
}

func TestParse_UnknownEndianTag(t *testing.T) {
	raw := buildMinDex(0)
	binary.LittleEndian.PutUint32(raw[0x28:], 0x99999999) // neither LE nor BE
	ctx, _, err := Parse(raw, 0)
	require.NoError(t, err)
	assert.Equal(t, "big-endian", ctx.Rep.Endian) // default fallback
}

func TestParseModifiedUtf8_Unterminated(t *testing.T) {
	// ULEB128 length=5 then data with no null terminator (all non-zero)
	raw := make([]byte, 10)
	binary.LittleEndian.PutUint32(raw[0:], 4) // string_id → offset 4
	raw[4] = 5                                // ULEB128 length
	// Fill remaining bytes with non-zero to prevent accidental null
	for i := 5; i < len(raw); i++ {
		raw[i] = 'A'
	}
	_, _, err := ParseStrings(raw, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

func TestParseModifiedUtf8_DataBeyondEnd(t *testing.T) {
	// ULEB128 takes all remaining bytes, no room for string data
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint32(raw[0:], 4) // string_id → offset 4
	raw[4] = 0x80                             // multi-byte ULEB128
	raw[5] = 0x80
	raw[6] = 0x01 // ends at index 7, start=7 == len(raw)-1 but raw[7] exists
	// Actually let's make it so start >= len(raw)
	raw2 := make([]byte, 7)
	binary.LittleEndian.PutUint32(raw2[0:], 4)
	raw2[4] = 0x80
	raw2[5] = 0x01 // ULEB ends at 6, start=6, but len=7 so start < len — needs start==len
	raw3 := make([]byte, 6)
	binary.LittleEndian.PutUint32(raw3[0:], 4)
	raw3[4] = 0x01 // single byte ULEB, start=5, but len=6, raw[5] exists
	// To hit "data starts beyond end": ULEB must consume all bytes after off
	raw4 := make([]byte, 5)
	binary.LittleEndian.PutUint32(raw4[0:], 4)
	raw4[4] = 0x01 // ULEB=1 byte, start=5, but len(raw4)=5, start >= len → error
	_, _, err := ParseStrings(raw4, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "beyond end")
}

func TestParseSection_AutoDetectDexCount(t *testing.T) {
	// expected=0 → auto-detect from section bounds
	dex := buildMinDex(1)
	raw := make([]byte, 300)
	copy(raw[60:], dex)
	s := model.VdexSection{Offset: 60, Size: uint32(len(dex))}
	ctxs, _ := ParseSection(raw, s, 0) // expected=0
	assert.Len(t, ctxs, 1)
}

func TestParseSection_FileSizeClamped(t *testing.T) {
	// Two DEXes concatenated, but second DEX declares file_size larger than remaining section.
	// Parse() returns effectiveFileSize=clamped, then section.go detects offset+size > end.
	dex0 := buildMinDex(0) // 0x70 bytes
	dex1 := buildMinDex(0)
	// dex1 declares 0x1000 but only 0x70 bytes in section
	binary.LittleEndian.PutUint32(dex1[0x20:], 0x1000)

	sectionOff := 60
	raw := make([]byte, sectionOff+0x70+0x70)
	copy(raw[sectionOff:], dex0)
	copy(raw[sectionOff+0x70:], dex1)
	// Section covers both DEXes exactly
	s := model.VdexSection{Offset: uint32(sectionOff), Size: uint32(0x70 + 0x70)}
	ctxs, diags := ParseSection(raw, s, 2)
	require.Len(t, ctxs, 2)
	// dex1 should have a clamped or error diagnostic
	hasDiag := false
	for _, d := range diags {
		if d.Code == model.WarnDexFileSizeClamped || d.Code == model.WarnDexTruncated {
			hasDiag = true
		}
	}
	assert.True(t, hasDiag, "should emit diagnostic for oversized dex file_size")
}

func TestParse_StringTableError(t *testing.T) {
	// Valid header but string_ids points out of range → returns ctx + error
	raw := buildMinDex(0)
	binary.LittleEndian.PutUint32(raw[0x38:], 10)   // string_ids_size = 10
	binary.LittleEndian.PutUint32(raw[0x3C:], 0xFF) // string_ids_off beyond file
	ctx, used, err := Parse(raw, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "string_ids")
	assert.NotNil(t, ctx) // partial result returned
	assert.Equal(t, 0x70, used)
}

func TestParse_ClassDefsTableError(t *testing.T) {
	// Valid header, no strings, but class_defs_off points out of range
	raw := buildMinDex(3) // 3 class defs
	binary.LittleEndian.PutUint32(raw[0x64:], 0xFF) // class_defs_off beyond file
	ctx, _, err := Parse(raw, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "class_defs")
	assert.NotNil(t, ctx)
}

func TestParseSection_CursorExceedsEnd(t *testing.T) {
	// DEX with file_size that after Align4 pushes cursor > section end
	// Section of 113 bytes (0x71) — DEX is 112 (0x70), leaving 1 byte gap
	// After parsing dex (used=0x70), cursor=60+0x70=172, Align4=172, end=60+113=173
	// cursor(172) < end(173) → tries to parse again with 1 byte → truncated
	dex := buildMinDex(0)
	raw := make([]byte, 200)
	copy(raw[60:], dex)
	s := model.VdexSection{Offset: 60, Size: 0x71} // 113 bytes, 1 extra
	ctxs, diags := ParseSection(raw, s, 0) // expected=0 auto-detect
	assert.Len(t, ctxs, 1) // first dex parsed
	// Second iteration should hit truncation
	hasTrunc := false
	for _, d := range diags {
		if d.Code == model.WarnDexTruncated {
			hasTrunc = true
		}
	}
	assert.True(t, hasTrunc)
}

func TestParseModifiedUtf8_OffsetOutOfRange(t *testing.T) {
	// string_id points to negative-equivalent offset (0xFFFFFFFF as uint32 read)
	raw := make([]byte, 12)
	binary.LittleEndian.PutUint32(raw[0:], 0xFFFFFFFF) // huge offset
	_, _, err := ParseStrings(raw, 1, 0)
	require.Error(t, err)
}

func TestParseClassDefs_InvalidClassIdx(t *testing.T) {
	// class_idx points beyond type_ids → should show <invalid>
	strs := []string{"Ljava/lang/Object;"}
	raw := make([]byte, 40)
	binary.LittleEndian.PutUint32(raw[0:], 0) // type_id[0]
	binary.LittleEndian.PutUint32(raw[8:], 99) // class_def[0].class_idx=99, but only 1 type
	classes, err := ParseClassDefs(raw, strs, 1, 0, 8, 1)
	require.NoError(t, err)
	require.Len(t, classes, 1)
	assert.Contains(t, classes[0], "<invalid")
}

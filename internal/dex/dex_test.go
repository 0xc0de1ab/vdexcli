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
	ctxs, warnings := ParseSection(raw, s, 1)
	assert.Empty(t, ctxs)
	require.NotEmpty(t, warnings)
	assert.Contains(t, warnings[0], "out of file range")
}

func TestParseSection_Truncated(t *testing.T) {
	raw := make([]byte, 80)
	s := model.VdexSection{Offset: 0, Size: 80} // only 80 bytes, need 0x70=112
	ctxs, warnings := ParseSection(raw, s, 1)
	assert.Empty(t, ctxs)
	assert.NotEmpty(t, warnings)
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

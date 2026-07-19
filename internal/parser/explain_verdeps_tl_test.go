package parser

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildTestVdex(t *testing.T, dexData []byte, verifierData []byte, tlData []byte) string {
	header := buildRawHeader("vdex", "027\x00", 4)

	checksumOff := uint32(12 + 48)
	checksumSize := uint32(4)

	dexOff := checksumOff + checksumSize
	dexSize := uint32(len(dexData))

	vdOff := dexOff + dexSize
	vdSize := uint32(len(verifierData))

	tlOff := vdOff + vdSize
	tlSize := uint32(len(tlData))

	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, dexOff, dexSize)
	sectionBuf = appendSectionHeader(sectionBuf, 2, vdOff, vdSize)
	sectionBuf = appendSectionHeader(sectionBuf, 3, tlOff, tlSize)

	raw := append(header, sectionBuf...)
	raw = append(raw, []byte{0x11, 0x22, 0x33, 0x44}...) // checksum
	if dexSize > 0 {
		raw = append(raw, dexData...)
	}
	if vdSize > 0 {
		raw = append(raw, verifierData...)
	}
	if tlSize > 0 {
		raw = append(raw, tlData...)
	}

	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	return tmpFile
}

func hasField(pm *model.PrimitiveMap, path string) bool {
	for _, f := range pm.Fields {
		if f.LogicalPath == path {
			return true
		}
	}
	return false
}

func getField(pm *model.PrimitiveMap, path string) *model.PrimitiveField {
	for _, f := range pm.Fields {
		if f.LogicalPath == path {
			return f
		}
	}
	return nil
}

// Group C: VerifierDeps Edge Cases

func TestExplainVdex_Verifier_EmptySection(t *testing.T) {
	path := buildTestVdex(t, nil, nil, nil)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	for _, f := range pm.Fields {
		assert.NotContains(t, f.LogicalPath, "vdex.verifier")
	}
}

func TestExplainVdex_Verifier_OnlyOffsetTable(t *testing.T) {
	vd := make([]byte, 4)
	binary.LittleEndian.PutUint32(vd, 4)
	path := buildTestVdex(t, nil, vd, nil)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	assert.True(t, hasField(pm, "vdex.verifier.dex_offsets[0]"))
	assert.False(t, hasField(pm, "vdex.verifier.dex[0].class_offsets[0]"))
}

func TestExplainVdex_Verifier_TruncatedSection(t *testing.T) {
	vd := []byte{0x04, 0x00} // only 2 bytes
	path := buildTestVdex(t, nil, vd, nil)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	assert.False(t, hasField(pm, "vdex.verifier.dex_offsets[0]"))
}

func TestExplainVdex_Verifier_AllUnverified(t *testing.T) {
	vd := make([]byte, 16)
	binary.LittleEndian.PutUint32(vd[0:4], 4)
	binary.LittleEndian.PutUint32(vd[4:8], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(vd[8:12], 12)

	path := buildTestVdex(t, nil, vd, nil)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	assert.True(t, hasField(pm, "vdex.verifier.dex[0].class_offsets[0]"))
	assert.True(t, hasField(pm, "vdex.verifier.dex[0].class_offsets[1]"))
	assert.False(t, hasField(pm, "vdex.verifier.dex[0].class[0].pair[0].dest"))
}

func TestExplainVdex_Verifier_SingleVerifiedClass(t *testing.T) {
	vd := make([]byte, 16)
	binary.LittleEndian.PutUint32(vd[0:4], 4)
	binary.LittleEndian.PutUint32(vd[4:8], 12)
	binary.LittleEndian.PutUint32(vd[8:12], 14)
	vd[12] = 5
	vd[13] = 10
	vd[14] = 0
	vd[15] = 0

	path := buildTestVdex(t, nil, vd, nil)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	assert.True(t, hasField(pm, "vdex.verifier.dex[0].class_offsets[0]"))
	assert.True(t, hasField(pm, "vdex.verifier.dex[0].class[0].pair[0].dest"))
	assert.True(t, hasField(pm, "vdex.verifier.dex[0].class[0].pair[0].src"))

	f := getField(pm, "vdex.verifier.dex[0].class[0].pair[0].dest")
	require.NotNil(t, f)
	assert.Equal(t, uint32(5), f.ParsedValue)

	f2 := getField(pm, "vdex.verifier.dex[0].class[0].pair[0].src")
	require.NotNil(t, f2)
	assert.Equal(t, uint32(10), f2.ParsedValue)
}

func TestExplainVdex_Verifier_ExtraStringsPresent(t *testing.T) {
	vd := make([]byte, 32)
	binary.LittleEndian.PutUint32(vd[0:4], 4)
	binary.LittleEndian.PutUint32(vd[4:8], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(vd[8:12], 12)
	binary.LittleEndian.PutUint32(vd[12:16], 2)
	binary.LittleEndian.PutUint32(vd[16:20], 24)
	binary.LittleEndian.PutUint32(vd[20:24], 28)
	copy(vd[24:28], "foo\x00")
	copy(vd[28:32], "bar\x00")

	path := buildTestVdex(t, nil, vd, nil)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	f := getField(pm, "vdex.verifier.dex[0].extra_strings[0]")
	require.NotNil(t, f)
	assert.Equal(t, "foo", f.ParsedValue)

	f2 := getField(pm, "vdex.verifier.dex[0].extra_strings[1]")
	require.NotNil(t, f2)
	assert.Equal(t, "bar", f2.ParsedValue)
}

func TestExplainVdex_Verifier_LargeOffsetTableCount(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(12 + 48)
	checksumSize := uint32(400) // implies 100 DEXes

	vdOff := checksumOff + checksumSize
	vdSize := uint32(8) // only space for 2 offsets

	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, vdOff, vdSize)
	sectionBuf = appendSectionHeader(sectionBuf, 3, vdOff+vdSize, 0)

	raw := append(header, sectionBuf...)
	chk := make([]byte, 400) // 100 checksums
	raw = append(raw, chk...)

	vd := make([]byte, 8)
	binary.LittleEndian.PutUint32(vd[0:4], 4)
	binary.LittleEndian.PutUint32(vd[4:8], 4)
	raw = append(raw, vd...)

	tmpFile := filepath.Join(t.TempDir(), "large.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	assert.True(t, hasField(pm, "vdex.verifier.dex_offsets[0]"))
	assert.True(t, hasField(pm, "vdex.verifier.dex_offsets[1]"))
	assert.False(t, hasField(pm, "vdex.verifier.dex_offsets[2]"))
}

func TestExplainVdex_Verifier_ZeroDexCount(t *testing.T) {
	path := buildTestVdex(t, nil, []byte{0x04, 0x00, 0x00, 0x00}, nil)
	data, _ := os.ReadFile(path)
	binary.LittleEndian.PutUint32(data[12+8:12+12], 0) // size of checksum section
	_ = os.WriteFile(path, data, 0644)

	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	assert.False(t, hasField(pm, "vdex.verifier.dex_offsets[0]"))
}

// Group D: TypeLookup Edge Cases

func TestExplainVdex_TypeLookup_EmptySection(t *testing.T) {
	path := buildTestVdex(t, nil, nil, nil)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	for _, f := range pm.Fields {
		assert.NotContains(t, f.LogicalPath, "vdex.typelookup")
	}
}

func TestExplainVdex_TypeLookup_SizeFieldOnly(t *testing.T) {
	tl := make([]byte, 4)
	binary.LittleEndian.PutUint32(tl, 0)

	path := buildTestVdex(t, nil, nil, tl)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	assert.True(t, hasField(pm, "vdex.typelookup.dex[0].size"))
	assert.False(t, hasField(pm, "vdex.typelookup.dex[0].entry[0].string_offset"))
}

func TestExplainVdex_TypeLookup_SingleEntry(t *testing.T) {
	tl := make([]byte, 12)
	binary.LittleEndian.PutUint32(tl[0:4], 8)
	binary.LittleEndian.PutUint32(tl[4:8], 123)
	binary.LittleEndian.PutUint32(tl[8:12], 456)

	path := buildTestVdex(t, nil, nil, tl)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	f1 := getField(pm, "vdex.typelookup.dex[0].entry[0].string_offset")
	require.NotNil(t, f1)
	assert.Equal(t, uint32(123), f1.ParsedValue)

	f2 := getField(pm, "vdex.typelookup.dex[0].entry[0].packed_data")
	require.NotNil(t, f2)
	assert.Equal(t, uint32(456), f2.ParsedValue)
}

func TestExplainVdex_TypeLookup_MaskBitsComputation(t *testing.T) {
	dexData := make([]byte, 112)
	copy(dexData[0:8], "dex\n035\x00")
	binary.LittleEndian.PutUint32(dexData[0x20:0x24], 112)
	binary.LittleEndian.PutUint32(dexData[0x24:0x28], 112)
	binary.LittleEndian.PutUint32(dexData[0x60:0x64], 15)

	tl := make([]byte, 12)
	binary.LittleEndian.PutUint32(tl[0:4], 8)
	binary.LittleEndian.PutUint32(tl[8:12], 801)

	path := buildTestVdex(t, dexData, nil, tl)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	f := getField(pm, "vdex.typelookup.dex[0].entry[0].packed_data")
	require.NotNil(t, f)
	assert.Contains(t, f.Description, "bits[4:8]")
	assert.Contains(t, f.Description, "class_def_idx=2")
	assert.Contains(t, f.Description, "hash_bits=0x3")
	assert.Contains(t, f.Description, "next_pos_delta=1")
}

func TestExplainVdex_TypeLookup_PaddingAfterEntries(t *testing.T) {
	tl := make([]byte, 15)
	binary.LittleEndian.PutUint32(tl[0:4], 11) // size 11

	path := buildTestVdex(t, nil, nil, tl)
	pm, err := ExplainVdex(path)
	require.NoError(t, err)

	f := getField(pm, "vdex.typelookup.dex[0].padding")
	require.NotNil(t, f)
	assert.Equal(t, uint32(3), f.Size)
	assert.Equal(t, model.TypeBytes, f.Type)
}

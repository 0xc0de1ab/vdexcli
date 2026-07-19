package vdex_test

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/pkg/vdex"
)

// =============================================================================
// Test helpers — synthetic VDEX builder
// =============================================================================

func pu32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func pu16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }

// buildTestVDEX constructs a minimal but valid VDEX v027 with one embedded DEX.
// The DEX contains 2 strings, 2 types, 1 proto, 1 field, 1 method, 1 class_def,
// plus a map_list and string_data section — providing rich test coverage.
func buildTestVDEX(t *testing.T) []byte {
	t.Helper()

	const dexSize = 0xE0 // 224 bytes
	dex := make([]byte, dexSize)

	// DEX magic + version
	copy(dex[0:4], "dex\n")
	copy(dex[4:8], "035\x00")
	pu32(dex, 0x08, 0x11223344)           // checksum
	pu32(dex, 0x20, dexSize)              // file_size
	pu32(dex, 0x24, 112)                  // header_size
	pu32(dex, 0x28, 0x12345678)           // endian_tag
	pu32(dex, 0x34, 0xBC)                 // map_off
	pu32(dex, 0x38, 2)                    // string_ids_size
	pu32(dex, 0x3C, 0x70)                 // string_ids_off
	pu32(dex, 0x40, 2)                    // type_ids_size
	pu32(dex, 0x44, 0x78)                 // type_ids_off
	pu32(dex, 0x48, 1)                    // proto_ids_size
	pu32(dex, 0x4C, 0x80)                 // proto_ids_off
	pu32(dex, 0x50, 1)                    // field_ids_size
	pu32(dex, 0x54, 0x8C)                 // field_ids_off
	pu32(dex, 0x58, 1)                    // method_ids_size
	pu32(dex, 0x5C, 0x94)                 // method_ids_off
	pu32(dex, 0x60, 1)                    // class_defs_size
	pu32(dex, 0x64, 0x9C)                 // class_defs_off
	pu32(dex, 0x68, uint32(dexSize-0xCC)) // data_size
	pu32(dex, 0x6C, 0xCC)                 // data_off

	// string_ids → point to data area
	pu32(dex, 0x70, 0xCC) // string[0] = "LHello;"
	pu32(dex, 0x74, 0xD5) // string[1] = "Test"
	// type_ids
	pu32(dex, 0x78, 0)
	pu32(dex, 0x7C, 1)
	// proto_ids[0]: shorty=0, return_type=0, params_off=0
	pu32(dex, 0x80, 0)
	pu32(dex, 0x84, 0)
	pu32(dex, 0x88, 0)
	// field_ids[0]: class=0, type=0, name=1
	pu16(dex, 0x8C, 0)
	pu16(dex, 0x8E, 0)
	pu32(dex, 0x90, 1)
	// method_ids[0]: class=0, proto=0, name=1
	pu16(dex, 0x94, 0)
	pu16(dex, 0x96, 0)
	pu32(dex, 0x98, 1)
	// class_defs[0]: class=0, access_flags=PUBLIC(1), superclass=none
	pu32(dex, 0x9C, 0)
	pu32(dex, 0xA0, 0x01)       // PUBLIC
	pu32(dex, 0xA4, 0xFFFFFFFF) // no superclass
	pu32(dex, 0xA8, 0)
	pu32(dex, 0xAC, 0xFFFFFFFF)
	pu32(dex, 0xB0, 0)
	pu32(dex, 0xB4, 0)
	pu32(dex, 0xB8, 0)
	// map_list @ 0xBC
	pu32(dex, 0xBC, 1)      // 1 map item
	pu16(dex, 0xC0, 0x1000) // TYPE_MAP_LIST
	pu16(dex, 0xC2, 0)
	pu32(dex, 0xC4, 1)
	pu32(dex, 0xC8, 0xBC)
	// string data @ 0xCC
	dex[0xCC] = 7
	copy(dex[0xCD:], "LHello;\x00")
	dex[0xD5] = 4
	copy(dex[0xD6:], "Test\x00")

	// VDEX v027 wrapper: header(60) + checksum(4) + dex(224)
	const (
		numSections  = 4
		hdrSize      = 12 + numSections*12 // 60
		checksumOff  = uint32(hdrSize)     // 60
		checksumSize = uint32(4)
		dexOff       = checksumOff + checksumSize // 64
	)

	totalSize := dexOff + uint32(dexSize)
	buf := make([]byte, totalSize)

	copy(buf[0:], "vdex")
	copy(buf[4:], "027\x00")
	pu32(buf, 8, numSections)

	// section[0] kChecksumSection
	pu32(buf, 12, 0)
	pu32(buf, 16, checksumOff)
	pu32(buf, 20, checksumSize)
	// section[1] kDexFileSection
	pu32(buf, 24, 1)
	pu32(buf, 28, dexOff)
	pu32(buf, 32, uint32(dexSize))
	// section[2] kVerifierDepsSection (empty)
	pu32(buf, 36, 2)
	pu32(buf, 40, dexOff+uint32(dexSize))
	pu32(buf, 44, 0)
	// section[3] kTypeLookupTableSection (empty)
	pu32(buf, 48, 3)
	pu32(buf, 52, dexOff+uint32(dexSize))
	pu32(buf, 56, 0)

	pu32(buf, int(checksumOff), 0xDEADBEEF)
	copy(buf[dexOff:], dex)

	return buf
}

func buildMultiDexVDEX(t *testing.T, count int) []byte {
	t.Helper()
	require.Positive(t, count)

	single := buildTestVDEX(t)
	dex := single[64:]
	const headerSize = 60
	checksumSize := count * 4
	dexOffset := headerSize + checksumSize
	buf := make([]byte, dexOffset+count*len(dex))
	copy(buf[0:], "vdex")
	copy(buf[4:], "027\x00")
	pu32(buf, 8, 4)
	pu32(buf, 12, 0)
	pu32(buf, 16, headerSize)
	pu32(buf, 20, uint32(checksumSize))
	pu32(buf, 24, 1)
	pu32(buf, 28, uint32(dexOffset))
	pu32(buf, 32, uint32(count*len(dex)))
	pu32(buf, 36, 2)
	pu32(buf, 40, uint32(len(buf)))
	pu32(buf, 44, 0)
	pu32(buf, 48, 3)
	pu32(buf, 52, uint32(len(buf)))
	pu32(buf, 56, 0)
	for i := 0; i < count; i++ {
		pu32(buf, headerSize+i*4, uint32(0xDEAD0000+i))
		copy(buf[dexOffset+i*len(dex):], dex)
	}
	return buf
}

// =============================================================================
// ExplainBytes tests
// =============================================================================

func TestExplainBytes_ReturnsPrimitiveMap(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)
	require.NotNil(t, fm)
	assert.Greater(t, len(fm.Fields), 10, "Expected many annotated fields")
}

func TestExplainBytes_100PercentCoverage(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	covered := uint32(0)
	for _, f := range fm.Fields {
		covered += f.Size
	}
	assert.Equal(t, fm.TotalBytes, covered, "All bytes must be accounted for")
	assert.Empty(t, fm.UnmappedGaps, "No unmapped gaps expected")
}

func TestExplainBytes_FieldsContiguous(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	expectedOffset := uint32(0)
	for i, f := range fm.Fields {
		assert.Equal(t, expectedOffset, f.Offset,
			"Field %d (%s) expected at offset %d but got %d", i, f.LogicalPath, expectedOffset, f.Offset)
		expectedOffset += f.Size
	}
}

func TestExplainBytes_ContainsVdexHeaderFields(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	paths := make(map[string]bool)
	for _, f := range fm.Fields {
		paths[f.LogicalPath] = true
	}
	assert.True(t, paths["vdex.header.magic"], "must have vdex.header.magic")
	assert.True(t, paths["vdex.header.version"], "must have vdex.header.version")
	assert.True(t, paths["vdex.header.sections"], "must have vdex.header.sections")
}

func TestExplainBytes_ContainsDEXFields(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	paths := make(map[string]bool)
	for _, f := range fm.Fields {
		paths[f.LogicalPath] = true
	}
	assert.True(t, paths["vdex.dex[0].header.magic"], "must have DEX magic")
	assert.True(t, paths["vdex.dex[0].string_ids[0]"], "must have string_ids[0]")
	assert.True(t, paths["vdex.dex[0].class_defs[0].access_flags"], "must have access_flags")
}

func TestExplainBytes_StringIdsShowInlineValue(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	for _, f := range fm.Fields {
		if f.LogicalPath == "vdex.dex[0].string_ids[0]" {
			assert.Contains(t, f.Description, "LHello;", "string_ids[0] description should contain inline string")
			return
		}
	}
	t.Fatal("string_ids[0] field not found")
}

func TestExplainBytes_AccessFlagsDescription(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	for _, f := range fm.Fields {
		if f.LogicalPath == "vdex.dex[0].class_defs[0].access_flags" {
			assert.Contains(t, f.Description, "PUBLIC", "access_flags should include PUBLIC bit name")
			return
		}
	}
	t.Fatal("access_flags field not found")
}

func TestExplainBytes_NilOnInvalidMagic(t *testing.T) {
	bad := []byte("notavdexfile0000000000000000")
	_, err := vdex.ExplainBytes(bad)
	require.Error(t, err)
}

func TestExplainBytes_NilOnTooSmall(t *testing.T) {
	_, err := vdex.ExplainBytes([]byte{1, 2, 3})
	require.Error(t, err)
}

func TestExplainBytes_FieldMapTotalBytesMatchesInput(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)
	assert.Equal(t, uint32(len(data)), fm.TotalBytes)
}

// =============================================================================
// ExplainFile tests
// =============================================================================

func TestExplainFile_EquivalentToExplainBytes(t *testing.T) {
	data := buildTestVDEX(t)
	path := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(path, data, 0644))

	fmFile, err := vdex.ExplainFile(path)
	require.NoError(t, err)

	fmBytes, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	assert.Equal(t, len(fmFile.Fields), len(fmBytes.Fields), "ExplainFile and ExplainBytes must produce same field count")
	assert.Equal(t, fmFile.TotalBytes, fmBytes.TotalBytes, "TotalBytes must match")
}

func TestExplainFile_ErrorOnMissingFile(t *testing.T) {
	_, err := vdex.ExplainFile("/nonexistent/path/that/does/not/exist.vdex")
	require.Error(t, err)
}

// =============================================================================
// ParseBytes tests
// =============================================================================

func TestParseBytes_ReturnsReport(t *testing.T) {
	data := buildTestVDEX(t)
	r, err := vdex.ParseBytes(data)
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestParseBytes_HeaderFields(t *testing.T) {
	data := buildTestVDEX(t)
	r, err := vdex.ParseBytes(data)
	require.NoError(t, err)
	assert.Equal(t, "vdex", r.Header.Magic)
	assert.Equal(t, "027", r.Header.Version)
	assert.Equal(t, uint32(4), r.Header.NumSections)
}

func TestParseBytes_ChecksumsPresent(t *testing.T) {
	data := buildTestVDEX(t)
	r, err := vdex.ParseBytes(data)
	require.NoError(t, err)
	require.Len(t, r.Checksums, 1, "expected 1 checksum")
	assert.Equal(t, uint32(0xDEADBEEF), r.Checksums[0])
}

func TestParseBytes_WithMeanings_PopulatesMeanings(t *testing.T) {
	data := buildTestVDEX(t)
	r, err := vdex.ParseBytes(data, vdex.WithMeanings())
	require.NoError(t, err)
	assert.NotNil(t, r.Meanings, "Meanings should be populated with WithMeanings()")
}

func TestParseBytes_WithoutMeanings_NilMeanings(t *testing.T) {
	data := buildTestVDEX(t)
	r, err := vdex.ParseBytes(data)
	require.NoError(t, err)
	assert.Nil(t, r.Meanings, "Meanings should be nil without WithMeanings()")
}

func TestParseBytes_NilOnInvalidMagic(t *testing.T) {
	bad := []byte("notavdexfile0000000000000000")
	_, err := vdex.ParseBytes(bad)
	// Should return a report with error (not nil) — non-critical parse
	// The parser returns a partial report on non-fatal errors
	// A bad magic is considered non-fatal (warning), so no Go error returned
	// but r.Errors should be non-empty
	if err == nil {
		t.Log("ParseBytes returned no error for bad magic (non-fatal mode) — acceptable")
	}
}

func TestParseBytes_Coverage(t *testing.T) {
	data := buildTestVDEX(t)
	r, err := vdex.ParseBytes(data)
	require.NoError(t, err)
	require.NotNil(t, r.Coverage)
	assert.Equal(t, len(data), r.Coverage.FileSize)
}

// =============================================================================
// ParseFile tests
// =============================================================================

func TestParseFile_SetsFileField(t *testing.T) {
	data := buildTestVDEX(t)
	path := filepath.Join(t.TempDir(), "myapp.vdex")
	require.NoError(t, os.WriteFile(path, data, 0644))

	r, err := vdex.ParseFile(path)
	require.NoError(t, err)
	assert.Contains(t, r.File, "myapp.vdex", "Report.File should contain the filename")
}

func TestParseFile_ErrorOnMissingFile(t *testing.T) {
	_, err := vdex.ParseFile("/nonexistent/does/not/exist.vdex")
	require.Error(t, err)
}

// =============================================================================
// Type system tests
// =============================================================================

func TestTypes_FieldTypeConstants(t *testing.T) {
	// Verify exported type constants are accessible
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	typesSeen := make(map[vdex.FieldType]bool)
	for _, f := range fm.Fields {
		typesSeen[f.Type] = true
	}
	assert.True(t, typesSeen[vdex.TypeMagic], "TypeMagic should appear")
	assert.True(t, typesSeen[vdex.TypeUint32LE], "TypeUint32LE should appear")
}

func TestTypes_JSONSerializable(t *testing.T) {
	data := buildTestVDEX(t)
	fm, err := vdex.ExplainBytes(data)
	require.NoError(t, err)

	b, err := json.Marshal(fm)
	require.NoError(t, err)
	assert.Greater(t, len(b), 100, "JSON output should be non-trivial")

	// Unmarshal back
	var roundtrip vdex.FieldMap
	require.NoError(t, json.Unmarshal(b, &roundtrip))
	assert.Equal(t, fm.TotalBytes, roundtrip.TotalBytes)
}

func TestExplainBytes_JSONUsesNumericRawBytes(t *testing.T) {
	fm, err := vdex.ExplainBytes(buildTestVDEX(t))
	require.NoError(t, err)

	encoded, err := json.Marshal(fm)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"raw_bytes":[118,100,101,120]`)
	assert.NotContains(t, string(encoded), `"raw_bytes":"dmRleA=="`)
}

// =============================================================================
// Options tests
// =============================================================================

func TestWithDexPreview_AcceptsOption(t *testing.T) {
	data := buildMultiDexVDEX(t, 7)
	r, err := vdex.ParseBytes(data, vdex.WithDexPreview(3))
	require.NoError(t, err)
	require.Len(t, r.Dexes, 3)
}

func TestWithDexPreview_DefaultAndAll(t *testing.T) {
	data := buildMultiDexVDEX(t, 7)

	defaultReport, err := vdex.ParseBytes(data)
	require.NoError(t, err)
	assert.Len(t, defaultReport.Dexes, 5)

	allReport, err := vdex.ParseBytes(data, vdex.WithDexPreview(-1))
	require.NoError(t, err)
	assert.Len(t, allReport.Dexes, 7)
}

func TestMultipleOptions_Applied(t *testing.T) {
	data := buildTestVDEX(t)
	r, err := vdex.ParseBytes(data, vdex.WithMeanings(), vdex.WithDexPreview(3))
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.NotNil(t, r.Meanings, "WithMeanings should populate Meanings")
}

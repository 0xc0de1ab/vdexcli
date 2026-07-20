package parser

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// Helper to build a minimal DEX file with customizable table sizes.
func buildMinimalDex(stringIds, typeIds, protoIds, fieldIds, methodIds, classDefs int) []byte {
	headerSize := 112
	stringIdsSz := stringIds * 4
	typeIdsSz := typeIds * 4
	protoIdsSz := protoIds * 12
	fieldIdsSz := fieldIds * 8
	methodIdsSz := methodIds * 8
	classDefsSz := classDefs * 32
	mapListSz := 4 + 12*2 // 2 items in map_list just to have it

	strOff := headerSize
	typOff := strOff + stringIdsSz
	proOff := typOff + typeIdsSz
	fldOff := proOff + protoIdsSz
	mthOff := fldOff + fieldIdsSz
	clsOff := mthOff + methodIdsSz
	dataOff := clsOff + classDefsSz
	mapOff := dataOff

	fileSize := dataOff + mapListSz + 16 // 16 bytes extra data padding

	dex := make([]byte, fileSize)

	// magic + version
	copy(dex[0:8], "dex\n035\x00")
	// checksum @ 0x08 (4B)
	binary.LittleEndian.PutUint32(dex[0x08:], 0x11223344)
	// file_size @ 0x20
	binary.LittleEndian.PutUint32(dex[0x20:], uint32(fileSize))
	// header_size @ 0x24
	binary.LittleEndian.PutUint32(dex[0x24:], uint32(headerSize))
	// endian_tag @ 0x28
	binary.LittleEndian.PutUint32(dex[0x28:], 0x12345678)
	// map_off @ 0x34
	binary.LittleEndian.PutUint32(dex[0x34:], uint32(mapOff))

	binary.LittleEndian.PutUint32(dex[0x38:], uint32(stringIds))
	binary.LittleEndian.PutUint32(dex[0x3C:], uint32(strOff))

	binary.LittleEndian.PutUint32(dex[0x40:], uint32(typeIds))
	binary.LittleEndian.PutUint32(dex[0x44:], uint32(typOff))

	binary.LittleEndian.PutUint32(dex[0x48:], uint32(protoIds))
	binary.LittleEndian.PutUint32(dex[0x4C:], uint32(proOff))

	binary.LittleEndian.PutUint32(dex[0x50:], uint32(fieldIds))
	binary.LittleEndian.PutUint32(dex[0x54:], uint32(fldOff))

	binary.LittleEndian.PutUint32(dex[0x58:], uint32(methodIds))
	binary.LittleEndian.PutUint32(dex[0x5C:], uint32(mthOff))

	binary.LittleEndian.PutUint32(dex[0x60:], uint32(classDefs))
	binary.LittleEndian.PutUint32(dex[0x64:], uint32(clsOff))

	binary.LittleEndian.PutUint32(dex[0x68:], uint32(fileSize-dataOff))
	binary.LittleEndian.PutUint32(dex[0x6C:], uint32(dataOff))

	// If stringIds > 0, point them to somewhere safe (like dataOff + mapListSz)
	if stringIds > 0 {
		for i := 0; i < stringIds; i++ {
			binary.LittleEndian.PutUint32(dex[strOff+i*4:], uint32(dataOff+mapListSz))
		}
	}

	// map_list
	binary.LittleEndian.PutUint32(dex[mapOff:], 2) // count=2
	// item 1
	binary.LittleEndian.PutUint16(dex[mapOff+4:], 0x1000) // TYPE_MAP_LIST
	binary.LittleEndian.PutUint16(dex[mapOff+6:], 0)      // unused
	binary.LittleEndian.PutUint32(dex[mapOff+8:], 1)      // size
	binary.LittleEndian.PutUint32(dex[mapOff+12:], uint32(mapOff))
	// item 2
	binary.LittleEndian.PutUint16(dex[mapOff+16:], 0x0001)            // TYPE_STRING_ID_ITEM
	binary.LittleEndian.PutUint16(dex[mapOff+18:], 0)                 // unused
	binary.LittleEndian.PutUint32(dex[mapOff+20:], uint32(stringIds)) // size
	binary.LittleEndian.PutUint32(dex[mapOff+24:], uint32(strOff))

	return dex
}

// wrapInVdex encapsulates one or more DEX files into a simple v027 VDEX.
func wrapInVdex(dexes ...[]byte) []byte {
	header := buildRawHeader("vdex", "027\x00", 4)

	checksumsSize := uint32(len(dexes) * 4)
	checksumOff := uint32(12 + 48) // 60
	dexOff := checksumOff + checksumsSize

	totalDexSize := uint32(0)
	for _, d := range dexes {
		// Align to 4 bytes if multiple dexes
		align := (4 - (totalDexSize % 4)) % 4
		totalDexSize += align + uint32(len(d))
	}

	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumsSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, dexOff, totalDexSize)
	sectionBuf = appendSectionHeader(sectionBuf, 2, dexOff+totalDexSize, 0) // verifier
	sectionBuf = appendSectionHeader(sectionBuf, 3, dexOff+totalDexSize, 0) // typelookup

	raw := append(header, sectionBuf...)

	// Checksums
	for i := 0; i < len(dexes); i++ {
		chk := make([]byte, 4)
		binary.LittleEndian.PutUint32(chk, uint32(0xCAFE0000+i))
		raw = append(raw, chk...)
	}

	// DEXes
	var currentSize uint32 = 0
	for _, d := range dexes {
		align := (4 - (currentSize % 4)) % 4
		for i := uint32(0); i < align; i++ {
			raw = append(raw, 0)
			currentSize++
		}
		raw = append(raw, d...)
		currentSize += uint32(len(d))
	}

	return raw
}

// =============================================================================
// Group B: DEX Table Decomposition (10 tests)
// =============================================================================

func TestExplainVdex_DexTable_AllTablesEmpty(t *testing.T) {
	dex := buildMinimalDex(0, 0, 0, 0, 0, 0)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "empty_tables.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	for _, f := range pm.Fields {
		assert.False(t, strings.HasSuffix(f.LogicalPath, ".string_ids"))
		assert.False(t, strings.HasSuffix(f.LogicalPath, ".type_ids"))
		assert.False(t, strings.HasSuffix(f.LogicalPath, ".proto_ids"))
		assert.False(t, strings.HasSuffix(f.LogicalPath, ".field_ids"))
		assert.False(t, strings.HasSuffix(f.LogicalPath, ".method_ids"))
		assert.False(t, strings.HasSuffix(f.LogicalPath, ".class_defs"))
	}
}

func TestExplainVdex_DexTable_StringIdsOOB(t *testing.T) {
	dex := buildMinimalDex(1, 0, 0, 0, 0, 0)
	// Break string_ids_off
	binary.LittleEndian.PutUint32(dex[0x3C:], 0xFFFFFF)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "string_ids_oob.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)
	// Should not panic. Parsing might just gracefully truncate or skip.
}

func TestExplainVdex_StringDataUsesMUTF8ByteLength(t *testing.T) {
	dex := buildMinimalDex(1, 0, 0, 0, 0, 0)
	stringDataOff := len(dex) - 16
	copy(dex[stringDataOff:], []byte{0x01, 0xc3, 0xa9, 0x00})

	pm, err := ExplainVdexBytes(wrapInVdex(dex))
	require.NoError(t, err)

	var stringData *model.PrimitiveField
	for _, field := range pm.Fields {
		if field.LogicalPath == "vdex.dex[0].string_data[0]" {
			stringData = field
			break
		}
	}
	require.NotNil(t, stringData)
	assert.Equal(t, uint32(4), stringData.Size)
	assert.Equal(t, model.ByteArray{0x01, 0xc3, 0xa9, 0x00}, stringData.RawBytes)
	assert.Contains(t, stringData.Summary, "é")
}

func TestExplainVdex_DexTable_LargeStringIdsCount(t *testing.T) {
	dex := buildMinimalDex(1, 0, 0, 0, 0, 0)
	// Set huge string_ids_size
	binary.LittleEndian.PutUint32(dex[0x38:], 1000)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "large_string_ids.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)
	// Should truncate without panic
}

func TestExplainVdex_DexTable_ProtoIdsAllFields(t *testing.T) {
	dex := buildMinimalDex(0, 0, 3, 0, 0, 0)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "proto_ids_fields.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	shortyCount := 0
	returnCount := 0
	paramCount := 0

	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, ".proto_ids[") {
			if strings.HasSuffix(f.LogicalPath, ".shorty_idx") {
				shortyCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".return_type_idx") {
				returnCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".parameters_off") {
				paramCount++
			}
		}
	}
	assert.Equal(t, 3, shortyCount)
	assert.Equal(t, 3, returnCount)
	assert.Equal(t, 3, paramCount)
}

func TestExplainVdex_DexTable_FieldIdsAllFields(t *testing.T) {
	dex := buildMinimalDex(0, 0, 0, 2, 0, 0)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "field_ids_fields.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	classCount := 0
	typeCount := 0
	nameCount := 0

	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, ".field_ids[") {
			if strings.HasSuffix(f.LogicalPath, ".class_idx") {
				classCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".type_idx") {
				typeCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".name_idx") {
				nameCount++
			}
		}
	}
	assert.Equal(t, 2, classCount)
	assert.Equal(t, 2, typeCount)
	assert.Equal(t, 2, nameCount)
}

func TestExplainVdex_DexTable_MethodIdsAllFields(t *testing.T) {
	dex := buildMinimalDex(0, 0, 0, 0, 2, 0)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "method_ids_fields.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	classCount := 0
	protoCount := 0
	nameCount := 0

	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, ".method_ids[") {
			if strings.HasSuffix(f.LogicalPath, ".class_idx") {
				classCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".proto_idx") {
				protoCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".name_idx") {
				nameCount++
			}
		}
	}
	assert.Equal(t, 2, classCount)
	assert.Equal(t, 2, protoCount)
	assert.Equal(t, 2, nameCount)
}

func TestExplainVdex_DexTable_ClassDefsAllFields(t *testing.T) {
	dex := buildMinimalDex(0, 0, 0, 0, 0, 2)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "class_defs_fields.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	fieldsMap := make(map[string]int)
	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, ".class_defs[") {
			parts := strings.Split(f.LogicalPath, ".")
			last := parts[len(parts)-1]
			fieldsMap[last]++
		}
	}
	assert.Equal(t, 2, fieldsMap["class_idx"])
	assert.Equal(t, 2, fieldsMap["access_flags"])
	assert.Equal(t, 2, fieldsMap["superclass_idx"])
	assert.Equal(t, 2, fieldsMap["interfaces_off"])
	assert.Equal(t, 2, fieldsMap["source_file_idx"])
	assert.Equal(t, 2, fieldsMap["annotations_off"])
	assert.Equal(t, 2, fieldsMap["class_data_off"])
	assert.Equal(t, 2, fieldsMap["static_values_off"])
}

func TestExplainVdex_DexTable_MapListMultipleItems(t *testing.T) {
	dex := buildMinimalDex(0, 0, 0, 0, 0, 0)
	// buildMinimalDex creates 2 items in map_list. We will alter it to have 3 items.

	mapOff := binary.LittleEndian.Uint32(dex[0x34:])

	// Reallocate slightly larger array for 3 items
	newDex := make([]byte, len(dex)+12)
	copy(newDex, dex)

	binary.LittleEndian.PutUint32(newDex[mapOff:], 3) // count=3
	// item 3
	item3 := mapOff + 4 + 12*2
	binary.LittleEndian.PutUint16(newDex[item3:], 0x0002) // TYPE_TYPE_ID_ITEM
	binary.LittleEndian.PutUint16(newDex[item3+2:], 0)
	binary.LittleEndian.PutUint32(newDex[item3+4:], 5)
	binary.LittleEndian.PutUint32(newDex[item3+8:], 120)

	// Update filesize
	binary.LittleEndian.PutUint32(newDex[0x20:], uint32(len(newDex)))

	vdex := wrapInVdex(newDex)

	tmpFile := filepath.Join(t.TempDir(), "map_list_multi.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	typeCount, sizeCount, offsetCount := 0, 0, 0
	hasSizeField := false
	for _, f := range pm.Fields {
		if strings.HasSuffix(f.LogicalPath, ".map_list.size") {
			hasSizeField = true
		}
		if strings.Contains(f.LogicalPath, ".map_list.item[") {
			if strings.HasSuffix(f.LogicalPath, ".type") {
				typeCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".count") {
				sizeCount++
			}
			if strings.HasSuffix(f.LogicalPath, ".offset") {
				offsetCount++
			}
		}
	}
	assert.True(t, hasSizeField)
	assert.Equal(t, 3, typeCount)
	assert.Equal(t, 3, sizeCount)
	assert.Equal(t, 3, offsetCount)
}

func TestExplainVdex_DexTable_DataSectionAsBlob(t *testing.T) {
	dex := buildMinimalDex(0, 0, 0, 0, 0, 0)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "data_blob.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	foundData := false
	for _, f := range pm.Fields {
		if strings.HasSuffix(f.LogicalPath, ".data") || strings.HasSuffix(f.LogicalPath, ".data_remaining") {
			foundData = true
			assert.Equal(t, model.TypeBytes, f.Type)
		}
	}
	assert.True(t, foundData)
}

func TestExplainVdex_DexTable_HeaderFieldCount(t *testing.T) {
	dex := buildMinimalDex(0, 0, 0, 0, 0, 0)
	vdex := wrapInVdex(dex)

	tmpFile := filepath.Join(t.TempDir(), "header_fields.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	headerFieldCount := 0
	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, ".dex[0].header.") {
			headerFieldCount++
		}
	}
	// At least 20 header fields expected in a DEX header
	assert.GreaterOrEqual(t, headerFieldCount, 20)
}

// =============================================================================
// Group G: Multi-DEX Scenarios (5 tests)
// =============================================================================

func TestExplainVdex_MultiDex_ThreeDexFiles(t *testing.T) {
	d1 := buildMinimalDex(1, 0, 0, 0, 0, 0)
	d2 := buildMinimalDex(0, 1, 0, 0, 0, 0)
	d3 := buildMinimalDex(0, 0, 1, 0, 0, 0)

	vdex := wrapInVdex(d1, d2, d3)

	tmpFile := filepath.Join(t.TempDir(), "three_dex.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	hasDex0, hasDex1, hasDex2 := false, false, false
	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, ".dex[0].header") {
			hasDex0 = true
		}
		if strings.Contains(f.LogicalPath, ".dex[1].header") {
			hasDex1 = true
		}
		if strings.Contains(f.LogicalPath, ".dex[2].header") {
			hasDex2 = true
		}
	}
	assert.True(t, hasDex0)
	assert.True(t, hasDex1)
	assert.True(t, hasDex2)
}

func TestExplainVdex_MultiDex_DifferentSizes(t *testing.T) {
	d1 := buildMinimalDex(0, 0, 0, 0, 0, 0)
	d2 := buildMinimalDex(5, 5, 5, 5, 5, 5) // larger table means larger file

	vdex := wrapInVdex(d1, d2)

	tmpFile := filepath.Join(t.TempDir(), "diff_sizes.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	var sz1, sz2 uint32
	for _, f := range pm.Fields {
		if strings.HasSuffix(f.LogicalPath, ".dex[0].header.file_size") {
			sz1 = f.ParsedValue.(uint32)
		}
		if strings.HasSuffix(f.LogicalPath, ".dex[1].header.file_size") {
			sz2 = f.ParsedValue.(uint32)
		}
	}
	assert.NotEqual(t, sz1, sz2)
}

func TestExplainVdex_MultiDex_AlignmentBetween(t *testing.T) {
	d1 := buildMinimalDex(0, 0, 0, 0, 0, 0)
	// Force d1 to be unaligned
	d1 = append(d1, 0x00, 0x00) // +2 bytes
	// update file size in dex header
	binary.LittleEndian.PutUint32(d1[0x20:], uint32(len(d1)))

	d2 := buildMinimalDex(0, 0, 0, 0, 0, 0)

	vdex := wrapInVdex(d1, d2)

	tmpFile := filepath.Join(t.TempDir(), "alignment.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	paddingFound := false
	for _, f := range pm.Fields {
		if f.Type == model.TypePadding && strings.Contains(f.LogicalPath, ".dexes.align[1]") {
			paddingFound = true
			assert.Equal(t, uint32(2), f.Size)
		}
	}
	assert.True(t, paddingFound)
}

func TestExplainVdex_MultiDex_SecondDexTruncated(t *testing.T) {
	d1 := buildMinimalDex(0, 0, 0, 0, 0, 0)
	d2 := buildMinimalDex(0, 0, 0, 0, 0, 0)

	vdex := wrapInVdex(d1, d2)
	// Truncate halfway through d2
	vdex = vdex[:len(vdex)-50]
	// Fix section 1 size
	binary.LittleEndian.PutUint32(vdex[32:], binary.LittleEndian.Uint32(vdex[32:])-50)

	tmpFile := filepath.Join(t.TempDir(), "truncated_d2.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	// Shouldn't panic, and we should only see valid fields for the truncated dex
	for _, f := range pm.Fields {
		assert.LessOrEqual(t, f.Offset+f.Size, pm.TotalBytes)
	}
}

func TestExplainVdex_MultiDex_FieldPathIndexing(t *testing.T) {
	d1 := buildMinimalDex(1, 1, 1, 1, 1, 1)
	d2 := buildMinimalDex(1, 1, 1, 1, 1, 1)

	vdex := wrapInVdex(d1, d2)

	tmpFile := filepath.Join(t.TempDir(), "path_indexing.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdex, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	hasDex0Fields, hasDex1Fields := false, false
	for _, f := range pm.Fields {
		if strings.HasPrefix(f.LogicalPath, "vdex.dex[0].class_defs") {
			hasDex0Fields = true
		}
		if strings.HasPrefix(f.LogicalPath, "vdex.dex[1].class_defs") {
			hasDex1Fields = true
		}
	}

	assert.True(t, hasDex0Fields)
	assert.True(t, hasDex1Fields)
}

func TestBuildDexPreviewSamplesRepresentativePackages(t *testing.T) {
	const (
		dexStart      = 16
		stringIDsOff  = 0x20
		typeIDsOff    = 0x30
		classDefsOff  = 0x40
		classDefsSize = 600
	)

	descriptors := []string{
		"Lcom/example/Alpha;",
		"Lcom/example/sub/Beta;",
		"Lorg/other/Gamma;",
	}
	stringDataOff := classDefsOff + classDefsSize*32
	effectiveSize := stringDataOff + 128
	raw := make([]byte, dexStart+effectiveSize)

	cursor := stringDataOff
	for index, descriptor := range descriptors {
		binary.LittleEndian.PutUint32(raw[dexStart+stringIDsOff+index*4:], uint32(cursor))
		raw[dexStart+cursor] = byte(len(descriptor))
		copy(raw[dexStart+cursor+1:], descriptor)
		cursor += len(descriptor) + 2
		binary.LittleEndian.PutUint32(raw[dexStart+typeIDsOff+index*4:], uint32(index))
	}
	for index := 0; index < classDefsSize; index++ {
		classIdx := uint32(0)
		switch index % 5 {
		case 3:
			classIdx = 1
		case 4:
			classIdx = 2
		}
		binary.LittleEndian.PutUint32(raw[dexStart+classDefsOff+index*32:], classIdx)
	}

	preview := buildDexPreview(dexPayloadParams{
		raw: raw, dexIdx: 2, dexStart: dexStart, effectiveSize: uint32(effectiveSize),
		stringIdsOff: stringIDsOff, stringIdsSize: uint32(len(descriptors)),
		typeIdsOff: typeIDsOff, typeIdsSize: uint32(len(descriptors)),
		classDefsOff: classDefsOff, classDefsSize: classDefsSize,
	})

	assert.Equal(t, 2, preview.Index)
	assert.True(t, preview.Embedded)
	assert.Equal(t, uint32(classDefsSize), preview.ClassCount)
	assert.Equal(t, uint32(dexPreviewSampleLimit), preview.SampledClassDefs)
	assert.Equal(t, uint32(dexPreviewSampleLimit), preview.ResolvedClassDescriptors)
	require.Len(t, preview.TopPackages, 3)
	assert.Equal(t, "com.example", preview.TopPackages[0].Name)
	assert.Greater(t, preview.TopPackages[0].ClassCount, preview.TopPackages[1].ClassCount)
	assert.Equal(t, []string{
		"Lcom/example/Alpha;",
		"Lcom/example/sub/Beta;",
		"Lorg/other/Gamma;",
	}, preview.ClassDescriptors)
}

func TestExplainVdexBytesCreatesChecksumOnlyDexPreviews(t *testing.T) {
	const checksumOffset = uint32(60)
	header := buildRawHeader("vdex", "027\x00", 4)
	var sections []byte
	sections = appendSectionHeader(sections, 0, checksumOffset, 8)
	sections = appendSectionHeader(sections, 1, checksumOffset+8, 0)
	sections = appendSectionHeader(sections, 2, checksumOffset+8, 0)
	sections = appendSectionHeader(sections, 3, checksumOffset+8, 0)
	raw := append(header, sections...)
	checksums := make([]byte, 8)
	binary.LittleEndian.PutUint32(checksums[0:], 0)
	binary.LittleEndian.PutUint32(checksums[4:], 0x6348CB98)
	raw = append(raw, checksums...)

	previewMap, err := ExplainVdexBytes(raw)
	require.NoError(t, err)
	require.Len(t, previewMap.DexPreviews, 2)
	assert.False(t, previewMap.DexPreviews[0].Embedded)
	require.NotNil(t, previewMap.DexPreviews[0].LocationChecksum)
	assert.Equal(t, uint32(0), *previewMap.DexPreviews[0].LocationChecksum)
	require.NotNil(t, previewMap.DexPreviews[1].LocationChecksum)
	assert.Equal(t, uint32(0x6348CB98), *previewMap.DexPreviews[1].LocationChecksum)
}

func TestExplainVdexBytesRejectsNonAdvancingDexSize(t *testing.T) {
	dex := make([]byte, 112)
	copy(dex, "dex\n035\x00")
	binary.LittleEndian.PutUint32(dex[0x24:], 112)
	raw := wrapDexSectionWithoutChecksums(dex)

	result := make(chan error, 1)
	go func() {
		_, err := ExplainVdexBytes(raw)
		result <- err
	}()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("DEX parser did not terminate for file_size=0")
	}
}

func TestExplainVdexBytesClampsOverflowingDexSize(t *testing.T) {
	dex := make([]byte, 112)
	copy(dex, "dex\n035\x00")
	binary.LittleEndian.PutUint32(dex[0x20:], math.MaxUint32)
	binary.LittleEndian.PutUint32(dex[0x24:], 112)
	raw := wrapDexSectionWithoutChecksums(dex)

	previewMap, err := ExplainVdexBytes(raw)
	require.NoError(t, err)
	require.Len(t, previewMap.DexPreviews, 1)
	assert.True(t, previewMap.DexPreviews[0].Embedded)
	for _, field := range previewMap.Fields {
		assert.LessOrEqual(t, uint64(field.Offset)+uint64(field.Size), uint64(len(raw)))
	}
}

func wrapDexSectionWithoutChecksums(dex []byte) []byte {
	const dexOffset = uint32(60)
	header := buildRawHeader("vdex", "027\x00", 4)
	var sections []byte
	sections = appendSectionHeader(sections, 0, dexOffset, 0)
	sections = appendSectionHeader(sections, 1, dexOffset, uint32(len(dex)))
	sections = appendSectionHeader(sections, 2, dexOffset+uint32(len(dex)), 0)
	sections = appendSectionHeader(sections, 3, dexOffset+uint32(len(dex)), 0)
	return append(append(header, sections...), dex...)
}

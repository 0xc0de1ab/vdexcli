package parser

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExplainVdex_Minimal(t *testing.T) {
	// Build a minimal valid VDEX v027: header + 4 section headers + 1 checksum + empty sections
	header := buildRawHeader("vdex", "027\x00", 4)

	checksumOff := uint32(12 + 48) // after header + 4 section headers
	checksumSize := uint32(4)

	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)                        // no dex
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+checksumSize, 0) // empty verifier
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+checksumSize, 0) // empty typelookup

	raw := append(header, sectionBuf...)
	// Append checksum data
	chk := make([]byte, 4)
	binary.LittleEndian.PutUint32(chk, 0xCAFEBABE)
	raw = append(raw, chk...)

	tmpFile := filepath.Join(t.TempDir(), "minimal.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)

	// Check total bytes matches the file size
	assert.Equal(t, uint32(len(raw)), pm.TotalBytes)

	// Verify no gaps remain (fields are contiguous from 0 to TotalBytes)
	var expectedOffset uint32 = 0
	for i, f := range pm.Fields {
		assert.Equal(t, expectedOffset, f.Offset, "Field %d offset mismatch: %s", i, f.LogicalPath)
		expectedOffset += f.Size
	}
	assert.Equal(t, pm.TotalBytes, expectedOffset)

	// Verify specific fields
	assert.Equal(t, "vdex.header.magic", pm.Fields[0].LogicalPath)
	assert.Equal(t, "vdex", pm.Fields[0].ParsedValue)
	assert.Equal(t, uint32(4), pm.Fields[0].Size)
}

func TestExplainVdex_Comprehensive(t *testing.T) {
	// Build a mock VDEX file with sections: Checksums, Dex, VerifierDeps, TypeLookup
	// 1. DEX Section data
	// We'll write a basic 112-byte DEX header.
	dexHeader := make([]byte, 112)
	copy(dexHeader[0:8], "dex\n035\x00")
	binary.LittleEndian.PutUint32(dexHeader[8:12], 0x11223344) // checksum
	binary.LittleEndian.PutUint32(dexHeader[0x20:0x24], 120)  // file_size = 120 bytes (header + 8 payload)
	binary.LittleEndian.PutUint32(dexHeader[0x24:0x28], 112)  // header_size
	binary.LittleEndian.PutUint32(dexHeader[0x28:0x2c], 0x12345678) // endian_tag
	binary.LittleEndian.PutUint32(dexHeader[0x60:0x64], 2)    // class_defs_size

	dexPayload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	dexFile := append(dexHeader, dexPayload...) // 120 bytes

	// 2. Checksums Section data (4 bytes)
	checksumData := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumData, 0x99887766)

	// 3. VerifierDeps Section data
	// For 1 DEX, we have a 4-byte offset table pointing to block:
	// block starts at relative offset 4
	// numClass = 2
	// class_offsets size = 3 * 4 = 12 bytes
	// class 0: offset 16 (verified, 1 pair: dest=5, src=10)
	// class 1: NotVerifiedMarker (0xFFFFFFFF)
	// sentinel: offset 18 (pairs data ends at 18)
	// extra strings: numExtraStrings = 1, stringsOffset table (4 bytes) pointing to offset 28 (null terminated string)

	var block []byte
	classOffsets := []uint32{16, 0xFFFFFFFF, 18}
	for _, val := range classOffsets {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, val)
		block = append(block, b...)
	}

	// Pairs data: dest=5, src=10 (both are single byte ULEB128)
	block = append(block, 0x05, 0x0A) // 2 bytes

	// Align to 4: block is 12 + 2 = 14 bytes. Pad 2 bytes to reach 16.
	block = append(block, 0x00, 0x00)

	// Extra strings count: 1 (4 bytes)
	numExtraStrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(numExtraStrBytes, 1)
	block = append(block, numExtraStrBytes...)

	// Extra string offset table: pointing to offset 28.
	extraStrOff := make([]byte, 4)
	binary.LittleEndian.PutUint32(extraStrOff, 28)
	block = append(block, extraStrOff...)

	// Extra strings data: "Ltest;\x00" (7 bytes)
	block = append(block, []byte("Ltest;\x00")...)

	// Assembly of VerifierDeps:
	// offset table: 4 bytes pointing to relative offset 4 (which is where block starts)
	var verifierDepsSection []byte
	perDexOffset := make([]byte, 4)
	binary.LittleEndian.PutUint32(perDexOffset, 4)
	verifierDepsSection = append(verifierDepsSection, perDexOffset...)
	verifierDepsSection = append(verifierDepsSection, block...)

	// 4. TypeLookup Section data
	// For 1 DEX:
	// size = 8 bytes (1 entry)
	// entry: string_offset=0x100, packed_data=0x02
	typeLookupSection := make([]byte, 12)
	binary.LittleEndian.PutUint32(typeLookupSection[0:4], 8) // size = 8
	binary.LittleEndian.PutUint32(typeLookupSection[4:8], 0x100) // string_offset
	binary.LittleEndian.PutUint32(typeLookupSection[8:12], 0x02) // packed_data

	// Construct the VDEX file
	// Let's lay them out with some gaps to test gap filling
	checksumOff := uint32(12 + 48) // 60
	dexOff := checksumOff + 4 // 64
	verifierOff := dexOff + 120 + 4 // 188 (includes a 4-byte gap between DEX and Verifier)
	typeLookupOff := verifierOff + uint32(len(verifierDepsSection)) + 8 // (includes an 8-byte gap)

	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, dexOff, 120)
	sectionBuf = appendSectionHeader(sectionBuf, 2, verifierOff, uint32(len(verifierDepsSection)))
	sectionBuf = appendSectionHeader(sectionBuf, 3, typeLookupOff, uint32(len(typeLookupSection)))

	raw := append(header, sectionBuf...) // 60 bytes

	// Append checksums (offset 60)
	raw = append(raw, checksumData...)

	// Append DEX (offset 64)
	raw = append(raw, dexFile...)

	// Append 4-byte gap (offset 184)
	raw = append(raw, 0, 0, 0, 0)

	// Append Verifier (offset 188)
	raw = append(raw, verifierDepsSection...)

	// Append 8-byte gap
	raw = append(raw, 0, 0, 0, 0, 0, 0, 0, 0)

	// Append TypeLookup
	raw = append(raw, typeLookupSection...)

	tmpFile := filepath.Join(t.TempDir(), "comprehensive.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)

	// Check total bytes matches the file size
	assert.Equal(t, uint32(len(raw)), pm.TotalBytes)

	// Verify no gaps remain (fields are contiguous from 0 to TotalBytes)
	var expectedOffset uint32 = 0
	for i, f := range pm.Fields {
		assert.Equal(t, expectedOffset, f.Offset, "Field %d offset mismatch: %s", i, f.LogicalPath)
		expectedOffset += f.Size
	}
	assert.Equal(t, pm.TotalBytes, expectedOffset)
}

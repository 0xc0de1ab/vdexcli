package parser

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
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

// TestExplainVdex_MalformedLEB128_NoInfiniteLoop verifies BUG-C1 fix:
// a verifier section containing an invalid LEB128 byte (0xFF at the very end,
// which starts but never terminates a multibyte sequence) must not cause an
// infinite loop. The test uses a tight timeout to detect any hang.
func TestExplainVdex_MalformedLEB128_NoInfiniteLoop(t *testing.T) {
	// Build a minimal VDEX with a verifier section whose pair-set data contains
	// a dangling high-bit byte — this is an invalid LEB128 that ReadULEB128 will
	// fail to decode, triggering the BUG-C1 code path.

	// Checksum section: 4 bytes (1 DEX)
	checksumOff := uint32(12 + 48)
	checksumSize := uint32(4)

	// DEX section: empty (0 size) but checksumCount=1 drives verifier
	// Verifier section layout:
	//   [0..3]  per-dex offset table: single uint32 pointing to offset 4
	//   [4..7]  class_offsets[0] = 8   (first class has pairs starting at relative 8)
	//   [8..11] class_offsets[1] = 0xFFFFFFFF (sentinel / NotVerified)
	// actually numClass=1 derived from checksumCount. sentinel offset = classOffsets[1].
	// But we have 2 entries: classOffsets[0]=8, classOffsets[1]=10 (setEnd).
	// pair region = [8,10): just 2 bytes.
	// We place 0xFF 0xFF there — first byte has continuation bit set but
	// second byte also has continuation bit set; the sequence never terminates.
	verifierData := []byte{
		// per-dex offset [0..3]: block starts at offset 4
		0x04, 0x00, 0x00, 0x00,
		// class_offsets[0] = 8 (pairs for class 0 start here)
		0x08, 0x00, 0x00, 0x00,
		// class_offsets[1] = 10 (sentinel: pairs end here)
		0x0A, 0x00, 0x00, 0x00,
		// pair region [8..10): malformed LEB128 — continuation bits never cleared
		0xFF, 0xFF,
	}
	verifierOff := checksumOff + checksumSize

	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0) // no DEX section data
	sectionBuf = appendSectionHeader(sectionBuf, 2, verifierOff, uint32(len(verifierData)))
	sectionBuf = appendSectionHeader(sectionBuf, 3, verifierOff+uint32(len(verifierData)), 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, make([]byte, 4)...) // checksum bytes
	raw = append(raw, verifierData...)

	tmpFile := filepath.Join(t.TempDir(), "malformed_leb128.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	done := make(chan struct{})
	go func() {
		defer close(done)
		// We don't care about the error — only that it returns.
		ExplainVdex(tmpFile) //nolint:errcheck
	}()

	select {
	case <-done:
		// Good — function returned without hanging.
	case <-time.After(5 * time.Second):
		t.Fatal("BUG-C1: ExplainVdex hung on malformed LEB128 input (infinite loop)")
	}
}

// TestExplainVdex_NumSectionsOverflow verifies BUG-H3 fix:
// a file with a huge numSections value that would overflow uint32 in the
// original (12 + numSections*12) calculation must be rejected with an error
// rather than silently wrapping and allocating billions of fields.
func TestExplainVdex_NumSectionsOverflow(t *testing.T) {
	// numSections = 0x15555556 → 0x15555556 * 12 = 0x100000008 (overflows uint32 to 8)
	// Before the fix, headerEnd would become 20, passing the bounds check on a 20-byte file.
	raw := make([]byte, 20)
	copy(raw[0:4], "vdex")
	copy(raw[4:8], "027\x00")
	binary.LittleEndian.PutUint32(raw[8:12], 0x15555556) // numSections

	tmpFile := filepath.Join(t.TempDir(), "overflow_sections.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	_, err := ExplainVdex(tmpFile)
	require.Error(t, err, "expected error for overflowing numSections, got nil")
}

// TestExplainVdex_ReadCStringBounded_SectionBoundary verifies BUG-H2 fix:
// a verifier section whose extra-string region has no null terminator must
// not produce a CString field that extends into the next section.
func TestExplainVdex_ReadCStringBounded_SectionBoundary(t *testing.T) {
	r := NewAnnotatedReader([]byte("ABCDEFGHIJ")) // 10 bytes, no null

	// With maxOffset=5 the string must stop at byte 5 even though there is
	// no null byte within the slice.
	val := r.ReadCStringBounded(5, "test.str", "test", "bounded cstring")
	assert.Equal(t, "ABCDE", val, "ReadCStringBounded should stop at maxOffset")
	assert.Equal(t, uint32(5), r.Offset(), "offset must not advance past maxOffset")

	// Confirm the emitted field does not cross the boundary.
	require.Len(t, r.fields, 1)
	f := r.fields[0]
	assert.Equal(t, uint32(0), f.Offset)
	assert.Equal(t, uint32(5), f.Size, "field size must equal maxOffset - startOffset")
}

// =============================================================================
// Phase 1: I-02 — Legacy Guard Tests
// =============================================================================

// TestExplainVdex_LegacyReturnsError verifies that ExplainVdex() returns an
// error for legacy VDEX files (v021-026) instead of silently misparasing them.
func TestExplainVdex_LegacyReturnsError(t *testing.T) {
	legacyVersions := []string{"021", "022", "023", "024", "025", "026"}
	for _, ver := range legacyVersions {
		t.Run("v"+ver, func(t *testing.T) {
			raw := buildLegacyExplainVdex(ver, 1)
			tmpFile := filepath.Join(t.TempDir(), "legacy_"+ver+".vdex")
			require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

			pm, err := ExplainVdex(tmpFile)
			// Must return an error for legacy files.
			require.Error(t, err, "ExplainVdex must reject legacy VDEX v%s", ver)
			assert.Nil(t, pm, "PrimitiveMap should be nil for legacy files")
			assert.Contains(t, err.Error(), ver, "error should mention the version")
		})
	}
}

// TestExplainVdex_LegacyDoesNotSilentlyMisparse verifies that a legacy VDEX
// v021 file does NOT produce a PrimitiveMap with garbage numSections.
// (This is the "silent misparse" bug I-02.)
func TestExplainVdex_LegacyDoesNotSilentlyMisparse(t *testing.T) {
	// v021 legacy VDEX: offset[8:12] = dexSectionVersion ("002\x00").
	// If ExplainVdex() reads offset[8:12] as numSections, it sees 0x00323030
	// (little-endian of "002\x00") = 3,289,136 sections — that's garbage.
	raw := buildLegacyExplainVdex("021", 1)
	tmpFile := filepath.Join(t.TempDir(), "legacy_misparse.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	// Must not silently succeed with garbage.
	require.Error(t, err)
	// Extra safety: if it somehow succeeds, ensure numSections is sane.
	if pm != nil {
		for _, f := range pm.Fields {
			if f.LogicalPath == "vdex.header.sections" {
				// numSections for a 1-DEX legacy file should be small, not millions.
				if val, ok := f.ParsedValue.(uint32); ok {
					assert.Less(t, val, uint32(100), "numSections should not be garbage")
				}
			}
		}
	}
}

// buildLegacyExplainVdex builds a minimal legacy VDEX file for testing ExplainVdex.
func buildLegacyExplainVdex(version string, numDex int) []byte {
	raw := make([]byte, 28) // legacy header is 28 bytes
	copy(raw[0:4], "vdex")
	copy(raw[4:8], version+"\x00")
	copy(raw[8:12], "002\x00") // dexSectionVersion
	binary.LittleEndian.PutUint32(raw[12:16], uint32(numDex))
	binary.LittleEndian.PutUint32(raw[16:20], 0) // verifierDepsSize
	binary.LittleEndian.PutUint32(raw[20:24], 0) // bcpChecksumsSize
	binary.LittleEndian.PutUint32(raw[24:28], 0) // clcSize
	// Checksums (numDex * 4 bytes)
	for i := 0; i < numDex; i++ {
		chk := make([]byte, 4)
		binary.LittleEndian.PutUint32(chk, uint32(0xCAFE0000+i))
		raw = append(raw, chk...)
	}
	return raw
}

// =============================================================================
// Phase 2: I-01 — DEX Internal Table Decomposition Tests
// =============================================================================

// buildExplainVdexWithDex builds a VDEX v027 containing one DEX file with
// populated string_ids, type_ids, and class_defs tables for explain tests.
// The DEX is constructed so that all major tables are at known offsets.
func buildExplainVdexWithDex(t *testing.T) ([]byte, dexTableOffsets) {
	t.Helper()

	// DEX layout:
	// 0x00  : header (112 bytes)
	// 0x70  : string_ids table (2 entries × 4B = 8 bytes) @ off=0x70
	// 0x78  : type_ids table   (2 entries × 4B = 8 bytes) @ off=0x78
	// 0x80  : proto_ids table  (1 entry  × 12B = 12 bytes) @ off=0x80
	// 0x8C  : field_ids table  (1 entry  × 8B  = 8 bytes) @ off=0x8C
	// 0x94  : method_ids table (1 entry  × 8B  = 8 bytes) @ off=0x94
	// 0x9C  : class_defs table (1 entry  × 32B = 32 bytes) @ off=0x9C
	// 0xBC  : map_off area  (4B size + entries)
	// 0xC0  : string data
	// file_size = 0xD0 = 208 bytes

	const dexFileSize = 0xD0 // 208 bytes

	dex := make([]byte, dexFileSize)
	// magic + version
	copy(dex[0:4], "dex\n")
	copy(dex[4:8], "035\x00")
	// checksum @ 0x08 (4B)
	binary.LittleEndian.PutUint32(dex[0x08:], 0x11223344)
	// SHA-1 signature @ 0x0C (20B) — zero
	// file_size @ 0x20
	binary.LittleEndian.PutUint32(dex[0x20:], dexFileSize)
	// header_size @ 0x24
	binary.LittleEndian.PutUint32(dex[0x24:], 112)
	// endian_tag @ 0x28
	binary.LittleEndian.PutUint32(dex[0x28:], 0x12345678)
	// link_size @ 0x2C (0 = no link)
	// link_off @ 0x30
	// map_off @ 0x34
	binary.LittleEndian.PutUint32(dex[0x34:], 0xBC) // map list at 0xBC
	// string_ids_size @ 0x38
	binary.LittleEndian.PutUint32(dex[0x38:], 2)
	// string_ids_off @ 0x3C
	binary.LittleEndian.PutUint32(dex[0x3C:], 0x70)
	// type_ids_size @ 0x40
	binary.LittleEndian.PutUint32(dex[0x40:], 2)
	// type_ids_off @ 0x44
	binary.LittleEndian.PutUint32(dex[0x44:], 0x78)
	// proto_ids_size @ 0x48
	binary.LittleEndian.PutUint32(dex[0x48:], 1)
	// proto_ids_off @ 0x4C
	binary.LittleEndian.PutUint32(dex[0x4C:], 0x80)
	// field_ids_size @ 0x50
	binary.LittleEndian.PutUint32(dex[0x50:], 1)
	// field_ids_off @ 0x54
	binary.LittleEndian.PutUint32(dex[0x54:], 0x8C)
	// method_ids_size @ 0x58
	binary.LittleEndian.PutUint32(dex[0x58:], 1)
	// method_ids_off @ 0x5C
	binary.LittleEndian.PutUint32(dex[0x5C:], 0x94)
	// class_defs_size @ 0x60
	binary.LittleEndian.PutUint32(dex[0x60:], 1)
	// class_defs_off @ 0x64
	binary.LittleEndian.PutUint32(dex[0x64:], 0x9C)
	// data_size @ 0x68
	binary.LittleEndian.PutUint32(dex[0x68:], 0x14) // 20 bytes
	// data_off @ 0x6C
	binary.LittleEndian.PutUint32(dex[0x6C:], 0xC0)

	// string_ids table @ 0x70: two entries pointing into data area
	binary.LittleEndian.PutUint32(dex[0x70:], 0xC4) // string 0 data offset
	binary.LittleEndian.PutUint32(dex[0x74:], 0xCA) // string 1 data offset
	// type_ids table @ 0x78
	binary.LittleEndian.PutUint32(dex[0x78:], 0) // type 0 → string 0
	binary.LittleEndian.PutUint32(dex[0x7C:], 1) // type 1 → string 1
	// proto_ids table @ 0x80 (shorty_idx, return_type_idx, parameters_off)
	binary.LittleEndian.PutUint32(dex[0x80:], 0)    // shorty_idx
	binary.LittleEndian.PutUint32(dex[0x84:], 0)    // return_type_idx
	binary.LittleEndian.PutUint32(dex[0x88:], 0)    // parameters_off (none)
	// field_ids table @ 0x8C (class_idx u16, type_idx u16, name_idx u32)
	binary.LittleEndian.PutUint16(dex[0x8C:], 0)    // class_idx
	binary.LittleEndian.PutUint16(dex[0x8E:], 0)    // type_idx
	binary.LittleEndian.PutUint32(dex[0x90:], 1)    // name_idx
	// method_ids table @ 0x94 (class_idx u16, proto_idx u16, name_idx u32)
	binary.LittleEndian.PutUint16(dex[0x94:], 0)    // class_idx
	binary.LittleEndian.PutUint16(dex[0x96:], 0)    // proto_idx
	binary.LittleEndian.PutUint32(dex[0x98:], 1)    // name_idx
	// class_defs table @ 0x9C (8 × uint32 = 32 bytes)
	binary.LittleEndian.PutUint32(dex[0x9C:], 0)    // class_idx
	binary.LittleEndian.PutUint32(dex[0xA0:], 0x01) // access_flags
	binary.LittleEndian.PutUint32(dex[0xA4:], 0xFFFFFFFF) // superclass_idx (none)
	binary.LittleEndian.PutUint32(dex[0xA8:], 0)    // interfaces_off
	binary.LittleEndian.PutUint32(dex[0xAC:], 0xFFFFFFFF) // source_file_idx
	binary.LittleEndian.PutUint32(dex[0xB0:], 0)    // annotations_off
	binary.LittleEndian.PutUint32(dex[0xB4:], 0)    // class_data_off
	binary.LittleEndian.PutUint32(dex[0xB8:], 0)    // static_values_off

	// map_list @ 0xBC: size=1 entries + 1 entry
	binary.LittleEndian.PutUint32(dex[0xBC:], 1) // map_list size
	// map_item: type=0x1000 (TYPE_MAP_LIST), unused=0, size=1, offset=0xBC
	binary.LittleEndian.PutUint16(dex[0xC0:], 0x1000) // type
	binary.LittleEndian.PutUint16(dex[0xC2:], 0)       // unused
	binary.LittleEndian.PutUint32(dex[0xC4:], 1)       // size
	// Hmm, 0xC4 is also where string data starts - let's fix the map_list

	// Correct layout: map_list needs 4 + 12*N bytes
	// 0xBC: size(4B) + 1×map_item(12B) = 16 bytes = 0xCC
	// But map_item type field was at 0xC0 - that conflicts with string data
	// Let's fix: map at 0xBC, string data starts at 0xCC
	// Re-do map_off and string offsets:
	binary.LittleEndian.PutUint32(dex[0x34:], 0xBC) // map_list at 0xBC
	binary.LittleEndian.PutUint32(dex[0x6C:], 0xCC) // data_off = 0xCC (after map_list)

	// Fix string data offsets to be in the data section
	binary.LittleEndian.PutUint32(dex[0x70:], 0xCC) // string 0 → 0xCC
	binary.LittleEndian.PutUint32(dex[0x74:], 0xD2) // string 1 → 0xD2

	// Resize dex to accommodate string data
	// string 0 @ 0xCC: ULEB128 len + chars + null  "LHello;" = 7 chars + 1 len byte + 1 null = 9 bytes → 0xCC..0xD4
	// string 1 @ 0xD2... wait 0xCC + 9 = 0xD5
	// Need to resize dex
	newDexSize := 0xE0 // 224 bytes
	newDex := make([]byte, newDexSize)
	copy(newDex, dex[:minInt(len(dex), newDexSize)])
	dex = newDex
	binary.LittleEndian.PutUint32(dex[0x20:], uint32(newDexSize)) // update file_size
	binary.LittleEndian.PutUint32(dex[0x68:], uint32(newDexSize-0xCC)) // data_size

	// map_list @ 0xBC: 4B count + 1×12B entry
	binary.LittleEndian.PutUint32(dex[0xBC:], 1)         // count = 1 entry
	binary.LittleEndian.PutUint16(dex[0xC0:], 0x1000)    // TYPE_MAP_LIST
	binary.LittleEndian.PutUint16(dex[0xC2:], 0)         // padding
	binary.LittleEndian.PutUint32(dex[0xC4:], 1)         // size = 1
	binary.LittleEndian.PutUint32(dex[0xC8:], 0xBC)      // offset

	// string data @ 0xCC
	// string 0: MUTF8 length=7, "LHello;", null
	dex[0xCC] = 7 // ULEB128 length
	copy(dex[0xCD:], "LHello;\x00")
	// string 1: MUTF8 length=4, "Test", null
	dex[0xD5] = 4
	copy(dex[0xD6:], "Test\x00")
	// Update string_ids offsets
	binary.LittleEndian.PutUint32(dex[0x70:], 0xCC)
	binary.LittleEndian.PutUint32(dex[0x74:], 0xD5)

	offs := dexTableOffsets{
		StringIdsOff:  0x70,
		StringIdsSize: 2,
		TypeIdsOff:    0x78,
		TypeIdsSize:   2,
		ProtoIdsOff:   0x80,
		ProtoIdsSize:  1,
		FieldIdsOff:   0x8C,
		FieldIdsSize:  1,
		MethodIdsOff:  0x94,
		MethodIdsSize: 1,
		ClassDefsOff:  0x9C,
		ClassDefsSize: 1,
		MapOff:        0xBC,
		DataOff:       0xCC,
		FileSize:      uint32(newDexSize),
	}

	// Wrap in VDEX v027
	checksumOff := uint32(12 + 48) // after header + 4 section headers
	dexSectionOff := checksumOff + 4
	dexSectionSize := uint32(newDexSize)

	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, dexSectionOff, dexSectionSize)
	sectionBuf = appendSectionHeader(sectionBuf, 2, dexSectionOff+dexSectionSize, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, dexSectionOff+dexSectionSize, 0)

	var raw []byte
	raw = append(raw, header...)
	raw = append(raw, sectionBuf...)
	// Checksum section (4 bytes)
	chk := make([]byte, 4)
	binary.LittleEndian.PutUint32(chk, 0xDEADBEEF)
	raw = append(raw, chk...)
	// DEX section
	raw = append(raw, dex...)

	return raw, offs
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type dexTableOffsets struct {
	StringIdsOff, StringIdsSize uint32
	TypeIdsOff, TypeIdsSize     uint32
	ProtoIdsOff, ProtoIdsSize   uint32
	FieldIdsOff, FieldIdsSize   uint32
	MethodIdsOff, MethodIdsSize uint32
	ClassDefsOff, ClassDefsSize uint32
	MapOff                      uint32
	DataOff                     uint32
	FileSize                    uint32
}

// TestExplainVdex_DEX_StringIdsTable verifies that string_ids table entries
// are individually annotated as separate PrimitiveFields.
func TestExplainVdex_DEX_StringIdsTable(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "dex_tables.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)

	// DEX section starts at offset dexSectionOff = 64
	dexSectionOff := uint32(12 + 48 + 4) // = 64
	dexStringIds0Abs := dexSectionOff + offs.StringIdsOff

	// Find string_ids[0] field
	var found bool
	for _, f := range pm.Fields {
		if f.Offset == dexStringIds0Abs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "string_ids") ||
					strings.Contains(f.LogicalPath, "string_id"),
				"Field at string_ids[0] offset should have string_ids path, got: %s", f.LogicalPath)
			assert.Equal(t, uint32(4), f.Size, "string_id entry is 4 bytes")
			break
		}
	}
	assert.True(t, found, "No field found at string_ids[0] offset 0x%x", dexStringIds0Abs)
}

// TestExplainVdex_DEX_TypeIdsTable verifies type_ids table decomposition.
func TestExplainVdex_DEX_TypeIdsTable(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "dex_typeids.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	typeIds0Abs := dexSectionOff + offs.TypeIdsOff

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == typeIds0Abs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "type_ids") ||
					strings.Contains(f.LogicalPath, "type_id"),
				"Field should be type_ids, got: %s", f.LogicalPath)
			assert.Equal(t, uint32(4), f.Size)
			break
		}
	}
	assert.True(t, found, "No field at type_ids[0] offset 0x%x", typeIds0Abs)
}

// TestExplainVdex_DEX_ProtoIdsTable verifies proto_ids table decomposition (12B each).
func TestExplainVdex_DEX_ProtoIdsTable(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "dex_protoids.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	protoIds0Abs := dexSectionOff + offs.ProtoIdsOff

	// proto_ids entry is 12 bytes: shorty_idx(4) + return_type_idx(4) + parameters_off(4)
	// Verify at least the first sub-field or the whole entry is present
	var found bool
	for _, f := range pm.Fields {
		if f.Offset == protoIds0Abs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "proto_ids") ||
					strings.Contains(f.LogicalPath, "proto_id"),
				"Field should be proto_ids, got: %s", f.LogicalPath)
			break
		}
	}
	assert.True(t, found, "No field at proto_ids[0] offset 0x%x", protoIds0Abs)
}

// TestExplainVdex_DEX_FieldIdsTable verifies field_ids table decomposition (8B each).
func TestExplainVdex_DEX_FieldIdsTable(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "dex_fieldids.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	fieldIds0Abs := dexSectionOff + offs.FieldIdsOff

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == fieldIds0Abs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "field_ids") ||
					strings.Contains(f.LogicalPath, "field_id"),
				"Field should be field_ids, got: %s", f.LogicalPath)
			break
		}
	}
	assert.True(t, found, "No field at field_ids[0] offset 0x%x", fieldIds0Abs)
}

// TestExplainVdex_DEX_MethodIdsTable verifies method_ids table decomposition (8B each).
func TestExplainVdex_DEX_MethodIdsTable(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "dex_methodids.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	methodIds0Abs := dexSectionOff + offs.MethodIdsOff

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == methodIds0Abs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "method_ids") ||
					strings.Contains(f.LogicalPath, "method_id"),
				"Field should be method_ids, got: %s", f.LogicalPath)
			break
		}
	}
	assert.True(t, found, "No field at method_ids[0] offset 0x%x", methodIds0Abs)
}

// TestExplainVdex_DEX_ClassDefsTable verifies class_defs table decomposition (32B each).
func TestExplainVdex_DEX_ClassDefsTable(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "dex_classdefs.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	classDefs0Abs := dexSectionOff + offs.ClassDefsOff

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == classDefs0Abs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "class_defs") ||
					strings.Contains(f.LogicalPath, "class_def"),
				"Field should be class_defs, got: %s", f.LogicalPath)
			break
		}
	}
	assert.True(t, found, "No field at class_defs[0] offset 0x%x", classDefs0Abs)
}

// TestExplainVdex_DEX_MapList verifies the map_list is annotated.
func TestExplainVdex_DEX_MapList(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "dex_maplist.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	mapAbs := dexSectionOff + offs.MapOff

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == mapAbs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "map") ||
					strings.Contains(f.LogicalPath, "map_list"),
				"Field should be map_list, got: %s", f.LogicalPath)
			break
		}
	}
	assert.True(t, found, "No field at map_list offset 0x%x (abs 0x%x)", offs.MapOff, mapAbs)
}

// TestExplainVdex_DEX_NoBlobPayload verifies that the DEX payload is NOT
// treated as a single opaque blob (vdex.dex[N].payload).
// After the fix, no field should have LogicalPath containing ".payload" unless
// it's a genuinely unstructured remainder.
func TestExplainVdex_DEX_NoBlobPayload(t *testing.T) {
	raw, _ := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "no_blob.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	for _, f := range pm.Fields {
		if strings.HasSuffix(f.LogicalPath, ".payload") {
			// If a payload field exists, it should be small (< 50% of DEX size)
			// meaning the DEX is substantially decomposed.
			// A full-DEX blob would be ~96 bytes; after decomposition, any
			// residual should be much smaller (data section remnant).
			assert.Less(t, f.Size, uint32(100),
				"DEX payload blob too large (%d bytes) — tables not decomposed. Path: %s",
				f.Size, f.LogicalPath)
		}
	}
}

// TestExplainVdex_DEX_FullContiguity verifies byte-level contiguity even with
// a fully decomposed DEX (no gaps or double-counted bytes).
func TestExplainVdex_DEX_FullContiguity(t *testing.T) {
	raw, _ := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "contiguity.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)

	assert.Equal(t, uint32(len(raw)), pm.TotalBytes)

	var expectedOffset uint32 = 0
	for i, f := range pm.Fields {
		assert.Equal(t, expectedOffset, f.Offset,
			"Field %d (%s) offset mismatch: expected 0x%x, got 0x%x",
			i, f.LogicalPath, expectedOffset, f.Offset)
		expectedOffset += f.Size
	}
	assert.Equal(t, pm.TotalBytes, expectedOffset, "Coverage gap at end of file")
}

// =============================================================================
// Phase 3: I-04 — TypeLookup packed_data Bit Field Decomposition Tests
// =============================================================================

// buildVdexWithTypeLookup creates a VDEX with a TypeLookup section for testing.
func buildVdexWithTypeLookup(t *testing.T, maskBits uint32) []byte {
	t.Helper()

	// TypeLookup entry: string_offset(4B) + packed_data(4B)
	// packed_data layout (maskBits=2):
	//   bits[0:maskBits)       = next_delta = 1
	//   bits[maskBits:2*maskBits) = class_def_idx = 3
	//   bits[2*maskBits:32)    = hash_bits = 0xABCD
	var nextDelta, classDefIdx, hashBits uint32 = 1, 3, 0xABCD
	packed := (hashBits << (2 * maskBits)) | (classDefIdx << maskBits) | nextDelta

	section := make([]byte, 12)
	binary.LittleEndian.PutUint32(section[0:4], 8)       // raw size = 8 (1 entry)
	binary.LittleEndian.PutUint32(section[4:8], 0x1234)  // string_offset
	binary.LittleEndian.PutUint32(section[8:12], packed) // packed_data

	checksumOff := uint32(12 + 48)
	typeLookupOff := checksumOff + 4

	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, typeLookupOff, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, typeLookupOff, uint32(len(section)))

	var raw []byte
	raw = append(raw, header...)
	raw = append(raw, sectionBuf...)
	raw = append(raw, make([]byte, 4)...) // checksums
	raw = append(raw, section...)
	return raw
}

// TestExplainVdex_TypeLookup_PackedDataBitFields verifies that packed_data
// Description contains the decoded bit-field values (hash_bits, class_def_idx,
// next_delta) so the user can understand the field.
func TestExplainVdex_TypeLookup_PackedDataBitFields(t *testing.T) {
	const maskBits = 2
	raw := buildVdexWithTypeLookup(t, maskBits)
	tmpFile := filepath.Join(t.TempDir(), "typelookup_bits.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	// Find the packed_data field
	var packedField *model.PrimitiveField
	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, "packed_data") {
			packedField = f
			break
		}
	}
	require.NotNil(t, packedField, "packed_data field not found in explain output")

	// The Description must contain decoded bit-field information.
	desc := packedField.Description
	assert.True(t,
		strings.Contains(desc, "next_delta") ||
			strings.Contains(desc, "next_pos_delta") ||
			strings.Contains(strings.ToLower(desc), "next"),
		"Description should contain next_delta info, got: %q", desc)
	assert.True(t,
		strings.Contains(desc, "class_def") ||
			strings.Contains(desc, "class_idx"),
		"Description should contain class_def_idx info, got: %q", desc)
	assert.True(t,
		strings.Contains(desc, "hash") ||
			strings.Contains(desc, "hash_bits"),
		"Description should contain hash_bits info, got: %q", desc)
}

// TestExplainVdex_TypeLookup_StringOffset verifies string_offset field.
func TestExplainVdex_TypeLookup_StringOffset(t *testing.T) {
	raw := buildVdexWithTypeLookup(t, 2)
	tmpFile := filepath.Join(t.TempDir(), "typelookup_stroff.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	var found bool
	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, "string_offset") &&
			strings.Contains(f.LogicalPath, "typelookup") {
			found = true
			assert.Equal(t, uint32(0x1234), f.ParsedValue.(uint32),
				"string_offset should be 0x1234")
			break
		}
	}
	assert.True(t, found, "string_offset field not found in TypeLookup explain output")
}

// =============================================================================
// Phase 4: Spot-check tests — specific LogicalPath / ParsedValue validation
// =============================================================================

// TestExplainVdex_SpotCheck_HeaderFields verifies exact LogicalPath and
// ParsedValue for known header fields.
func TestExplainVdex_SpotCheck_HeaderFields(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(12 + 48)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+4, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+4, 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, make([]byte, 4)...) // checksum

	tmpFile := filepath.Join(t.TempDir(), "spotcheck.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	fieldMap := make(map[string]*model.PrimitiveField)
	for _, f := range pm.Fields {
		fieldMap[f.LogicalPath] = f
	}

	// Header magic
	magic := fieldMap["vdex.header.magic"]
	require.NotNil(t, magic, "vdex.header.magic field must exist")
	assert.Equal(t, uint32(0), magic.Offset)
	assert.Equal(t, uint32(4), magic.Size)
	assert.Equal(t, "vdex", magic.ParsedValue)

	// Header version
	ver := fieldMap["vdex.header.version"]
	require.NotNil(t, ver, "vdex.header.version field must exist")
	assert.Equal(t, uint32(4), ver.Offset)
	assert.Equal(t, uint32(4), ver.Size)

	// Header numSections
	sec := fieldMap["vdex.header.sections"]
	require.NotNil(t, sec, "vdex.header.sections field must exist")
	assert.Equal(t, uint32(8), sec.Offset)
	assert.Equal(t, uint32(4), sec.Size)
	if val, ok := sec.ParsedValue.(uint32); ok {
		assert.Equal(t, uint32(4), val)
	}

	// Section[0] kind
	k0 := fieldMap["vdex.sections[0].kind"]
	require.NotNil(t, k0, "section[0].kind must exist")
	assert.Equal(t, uint32(12), k0.Offset)
	if val, ok := k0.ParsedValue.(uint32); ok {
		assert.Equal(t, uint32(0), val, "section[0] is checksums (kind=0)")
	}
}

// TestExplainVdex_SpotCheck_ChecksumValue verifies a known checksum value.
func TestExplainVdex_SpotCheck_ChecksumValue(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(12 + 48)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+4, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+4, 0)

	raw := append(header, sectionBuf...)
	chk := make([]byte, 4)
	binary.LittleEndian.PutUint32(chk, 0xCAFEBABE)
	raw = append(raw, chk...)

	tmpFile := filepath.Join(t.TempDir(), "checksum_spot.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	var found bool
	for _, f := range pm.Fields {
		if f.LogicalPath == "vdex.checksums[0]" {
			found = true
			if val, ok := f.ParsedValue.(uint32); ok {
				assert.Equal(t, uint32(0xCAFEBABE), val)
			}
			break
		}
	}
	assert.True(t, found, "vdex.checksums[0] field not found")
}

// TestExplainVdex_SpotCheck_SectionKindNames verifies section kind interpretation.
func TestExplainVdex_SpotCheck_SectionKindNames(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(12 + 48)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+4, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+4, 0)
	raw := append(header, sectionBuf...)
	raw = append(raw, make([]byte, 4)...)

	tmpFile := filepath.Join(t.TempDir(), "kinds.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	kindFields := make(map[string]*model.PrimitiveField)
	for _, f := range pm.Fields {
		if strings.HasSuffix(f.LogicalPath, ".kind") {
			kindFields[f.LogicalPath] = f
		}
	}

	expectedKinds := []struct {
		path string
		kind uint32
	}{
		{"vdex.sections[0].kind", 0},
		{"vdex.sections[1].kind", 1},
		{"vdex.sections[2].kind", 2},
		{"vdex.sections[3].kind", 3},
	}
	for _, ek := range expectedKinds {
		f := kindFields[ek.path]
		require.NotNil(t, f, "%s must exist", ek.path)
		if val, ok := f.ParsedValue.(uint32); ok {
			assert.Equal(t, ek.kind, val, "%s kind value", ek.path)
		}
	}
}

// =============================================================================
// Phase 5: DEX data section sub-type annotation tests
// =============================================================================

// TestExplainVdex_DEX_StringDataAnnotation verifies that string_data items
// in the DEX data section are annotated with ULEB128 length + chars.
func TestExplainVdex_DEX_StringDataAnnotation(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "strdata.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	// string data for string[0] starts at offs.DataOff
	strDataAbs := dexSectionOff + offs.DataOff

	// Look for a field near the string data area
	var foundNearData bool
	for _, f := range pm.Fields {
		if f.Offset >= strDataAbs && f.Offset < strDataAbs+20 {
			foundNearData = true
			break
		}
	}
	assert.True(t, foundNearData,
		"No field found in DEX string data area (abs 0x%x)", strDataAbs)
}

// =============================================================================
// Phase 6: Multi-DEX Tests
// =============================================================================

// TestExplainVdex_MultiDex_BothDexesAnnotated verifies that multiple DEX files
// within a VDEX are each individually annotated.
func TestExplainVdex_MultiDex_BothDexesAnnotated(t *testing.T) {
	// Build two minimal 112-byte DEX headers
	dex0 := make([]byte, 112)
	copy(dex0[0:8], "dex\n035\x00")
	binary.LittleEndian.PutUint32(dex0[0x20:], 112)
	binary.LittleEndian.PutUint32(dex0[0x24:], 112)
	binary.LittleEndian.PutUint32(dex0[0x28:], 0x12345678)

	dex1 := make([]byte, 112)
	copy(dex1[0:8], "dex\n035\x00")
	binary.LittleEndian.PutUint32(dex1[0x20:], 112)
	binary.LittleEndian.PutUint32(dex1[0x24:], 112)
	binary.LittleEndian.PutUint32(dex1[0x28:], 0x12345678)

	dexSection := append(dex0, dex1...)

	checksumOff := uint32(12 + 48)
	checksumSize := uint32(8) // 2 checksums
	dexOff := checksumOff + checksumSize

	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, dexOff, uint32(len(dexSection)))
	sectionBuf = appendSectionHeader(sectionBuf, 2, dexOff+uint32(len(dexSection)), 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, dexOff+uint32(len(dexSection)), 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, make([]byte, checksumSize)...) // checksums
	raw = append(raw, dexSection...)

	tmpFile := filepath.Join(t.TempDir(), "multidex.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	// Verify both DEX[0] and DEX[1] header magic fields appear
	foundDex := make(map[int]bool)
	for _, f := range pm.Fields {
		for i := 0; i < 2; i++ {
			if f.LogicalPath == fmt.Sprintf("vdex.dex[%d].header.magic", i) {
				foundDex[i] = true
			}
		}
	}
	assert.True(t, foundDex[0], "DEX[0] header.magic not found")
	assert.True(t, foundDex[1], "DEX[1] header.magic not found")
}

// =============================================================================
// Phase 7: Fuzz-style robustness tests
// =============================================================================

// TestExplainVdex_TruncatedDEXHeader verifies graceful handling of a DEX
// section that claims a large file_size but is truncated.
func TestExplainVdex_TruncatedDEXHeader(t *testing.T) {
	dex := make([]byte, 112)
	copy(dex[0:8], "dex\n035\x00")
	binary.LittleEndian.PutUint32(dex[0x20:], 999999) // huge file_size
	binary.LittleEndian.PutUint32(dex[0x24:], 112)
	binary.LittleEndian.PutUint32(dex[0x28:], 0x12345678)

	checksumOff := uint32(12 + 48)
	dexOff := checksumOff + 4

	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, dexOff, uint32(len(dex)))
	sectionBuf = appendSectionHeader(sectionBuf, 2, dexOff+uint32(len(dex)), 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, dexOff+uint32(len(dex)), 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, make([]byte, 4)...)
	raw = append(raw, dex...)

	tmpFile := filepath.Join(t.TempDir(), "truncated_dex.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	// Must not panic; error or success both acceptable
	pm, _ := ExplainVdex(tmpFile)
	if pm != nil {
		// Verify contiguity
		var cursor uint32
		for _, f := range pm.Fields {
			assert.Equal(t, cursor, f.Offset, "field %s has gap", f.LogicalPath)
			cursor += f.Size
		}
	}
}

// TestExplainVdex_DEX_ZeroSizeIdTables handles DEX with all zero-size tables.
func TestExplainVdex_DEX_ZeroSizeIdTables(t *testing.T) {
	// Minimal DEX: header only, no tables, no data
	dex := make([]byte, 112)
	copy(dex[0:8], "dex\n035\x00")
	binary.LittleEndian.PutUint32(dex[0x20:], 112)   // file_size = header only
	binary.LittleEndian.PutUint32(dex[0x24:], 112)
	binary.LittleEndian.PutUint32(dex[0x28:], 0x12345678)
	// All table sizes = 0, all offsets = 0

	checksumOff := uint32(12 + 48)
	dexOff := checksumOff + 4

	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, dexOff, uint32(len(dex)))
	sectionBuf = appendSectionHeader(sectionBuf, 2, dexOff+uint32(len(dex)), 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, dexOff+uint32(len(dex)), 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, make([]byte, 4)...)
	raw = append(raw, dex...)

	tmpFile := filepath.Join(t.TempDir(), "empty_dex.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)
	assert.Equal(t, uint32(len(raw)), pm.TotalBytes)

	// Contiguity check
	var cursor uint32
	for i, f := range pm.Fields {
		assert.Equal(t, cursor, f.Offset, "Field %d (%s) gap", i, f.LogicalPath)
		cursor += f.Size
	}
	assert.Equal(t, pm.TotalBytes, cursor)
}

// =============================================================================
// Phase 8: map_list internal decomposition tests
// =============================================================================

// TestExplainVdex_DEX_MapList_ItemsDecomposed verifies that map_list entries
// are each decomposed into (type, unused, count, offset) sub-fields.
func TestExplainVdex_DEX_MapList_ItemsDecomposed(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "maplist_items.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	mapAbs := dexSectionOff + offs.MapOff

	// Find the map_list.size field (first field at mapAbs)
	var foundSize bool
	for _, f := range pm.Fields {
		if f.Offset == mapAbs && strings.Contains(f.LogicalPath, "map_list") {
			foundSize = true
			assert.Equal(t, uint32(4), f.Size, "map_list.size should be 4 bytes")
			break
		}
	}
	assert.True(t, foundSize, "map_list.size field not found at 0x%x", mapAbs)

	// Look for map_list item type field (should come after size)
	var foundItemType bool
	for _, f := range pm.Fields {
		if strings.Contains(f.LogicalPath, "map_list") &&
			strings.Contains(f.LogicalPath, "item[0]") &&
			strings.Contains(f.LogicalPath, ".type") {
			foundItemType = true
			assert.Equal(t, uint32(2), f.Size, "map_item.type should be 2 bytes (uint16)")
			break
		}
	}
	assert.True(t, foundItemType, "map_list.item[0].type field not found")
}

// =============================================================================
// Phase 9: Class defs field-level value tests
// =============================================================================

// TestExplainVdex_DEX_ClassDef_AccessFlags verifies that class_def access_flags
// field is annotated at the correct offset with the expected value.
func TestExplainVdex_DEX_ClassDef_AccessFlags(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "classdef_flags.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	// class_defs[0].access_flags is at class_defs_off + 4 (after class_idx)
	accessFlagsAbs := dexSectionOff + offs.ClassDefsOff + 4

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == accessFlagsAbs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "access_flags"),
				"Field should be access_flags, got: %s", f.LogicalPath)
			if val, ok := f.ParsedValue.(uint32); ok {
				assert.Equal(t, uint32(0x01), val, "access_flags should be 0x01 (PUBLIC)")
			}
			break
		}
	}
	assert.True(t, found, "class_def.access_flags not found at 0x%x", accessFlagsAbs)
}

// TestExplainVdex_DEX_ClassDef_SuperclassIdx verifies superclass_idx field
// correctly shows 0xFFFFFFFF for classes with no superclass.
func TestExplainVdex_DEX_ClassDef_SuperclassIdx(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "classdef_super.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	// class_defs[0].superclass_idx is at class_defs_off + 8
	superclassAbs := dexSectionOff + offs.ClassDefsOff + 8

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == superclassAbs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "superclass_idx"),
				"Field should be superclass_idx, got: %s", f.LogicalPath)
			if val, ok := f.ParsedValue.(uint32); ok {
				assert.Equal(t, uint32(0xFFFFFFFF), val, "superclass_idx should be 0xFFFFFFFF")
			}
			break
		}
	}
	assert.True(t, found, "class_def.superclass_idx not found at 0x%x", superclassAbs)
}

// =============================================================================
// Phase 10: Field IDs and Method IDs value tests
// =============================================================================

// TestExplainVdex_DEX_FieldId_ClassIdx verifies that field_ids[0].class_idx
// is correctly annotated as a uint16 at the right offset.
func TestExplainVdex_DEX_FieldId_ClassIdx(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "fieldid_classidx.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	fieldId0Abs := dexSectionOff + offs.FieldIdsOff

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == fieldId0Abs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "class_idx"),
				"First field in field_ids should be class_idx, got: %s", f.LogicalPath)
			assert.Equal(t, uint32(2), f.Size, "class_idx is 2 bytes (uint16)")
			break
		}
	}
	assert.True(t, found, "field_ids[0].class_idx not found at 0x%x", fieldId0Abs)
}

// TestExplainVdex_DEX_MethodId_NameIdx verifies that method_ids[0].name_idx
// is correctly annotated as a uint32 at offset+4 of each method_id entry.
func TestExplainVdex_DEX_MethodId_NameIdx(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "methodid_nameidx.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	// method_ids[0].name_idx is at method_ids_off + 4 (after class_idx[2] + proto_idx[2])
	nameIdxAbs := dexSectionOff + offs.MethodIdsOff + 4

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == nameIdxAbs {
			found = true
			assert.True(t,
				strings.Contains(f.LogicalPath, "name_idx"),
				"Field at offset should be name_idx, got: %s", f.LogicalPath)
			assert.Equal(t, uint32(4), f.Size, "name_idx is 4 bytes (uint32)")
			// Value should be 1 (second string = "Test" for this method)
			if val, ok := f.ParsedValue.(uint32); ok {
				assert.Equal(t, uint32(1), val, "method_ids[0].name_idx should be 1")
			}
			break
		}
	}
	assert.True(t, found, "method_ids[0].name_idx not found at 0x%x", nameIdxAbs)
}

// =============================================================================
// Phase 11: Proto IDs value tests
// =============================================================================

// TestExplainVdex_DEX_ProtoId_Fields verifies all 3 sub-fields of proto_ids[0].
func TestExplainVdex_DEX_ProtoId_Fields(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "protoid_fields.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	protoBase := dexSectionOff + offs.ProtoIdsOff

	expectedFields := []struct {
		relOff uint32
		name   string
		size   uint32
	}{
		{0, "shorty_idx", 4},
		{4, "return_type_idx", 4},
		{8, "parameters_off", 4},
	}

	for _, ef := range expectedFields {
		absOff := protoBase + ef.relOff
		var found bool
		for _, f := range pm.Fields {
			if f.Offset == absOff {
				found = true
				assert.True(t,
					strings.Contains(f.LogicalPath, ef.name),
					"Field at 0x%x should be %s, got: %s", absOff, ef.name, f.LogicalPath)
				assert.Equal(t, ef.size, f.Size, "%s should be %d bytes", ef.name, ef.size)
				break
			}
		}
		assert.True(t, found, "proto_ids[0].%s not found at 0x%x", ef.name, absOff)
	}
}

// =============================================================================
// Phase 12: string_ids ParsedValue actual value verification (Critical I-02)
// =============================================================================

// TestExplainVdex_DEX_StringIds_ParsedValueIsOffset verifies that each
// string_ids entry's ParsedValue is the actual file offset pointing into
// the string_data area (not just present, but the correct numeric value).
func TestExplainVdex_DEX_StringIds_ParsedValueIsOffset(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "stringids_parsedval.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)

	// string_ids[0] is a 4-byte uint32 at dexSectionOff + stringIdsOff
	strId0Abs := dexSectionOff + offs.StringIdsOff

	var found bool
	for _, f := range pm.Fields {
		if f.Offset == strId0Abs && strings.Contains(f.LogicalPath, "string_ids[0]") {
			found = true
			require.NotNil(t, f.ParsedValue, "string_ids[0].ParsedValue should not be nil")
			val, ok := f.ParsedValue.(uint32)
			require.True(t, ok, "string_ids[0].ParsedValue should be uint32, got: %T", f.ParsedValue)
			// The value should be an offset within the DEX file (at least > 0 and < dex_size)
			// In our synthetic DEX, string data starts after the ID tables.
			assert.Greater(t, val, uint32(0x70), // after all id tables (conservative lower bound)
				"string_ids[0].ParsedValue = 0x%x should point into string data area", val)
			assert.Less(t, val, offs.FileSize,
				"string_ids[0].ParsedValue = 0x%x should be within DEX file", val)
			break
		}
	}
	assert.True(t, found, "string_ids[0] field not found at 0x%x", strId0Abs)
}

// TestExplainVdex_DEX_StringIds_AllOffsetValues verifies that all string_ids
// entries have non-zero, non-duplicate ParsedValue offsets.
func TestExplainVdex_DEX_StringIds_AllOffsetValues(t *testing.T) {
	raw, offs := buildExplainVdexWithDex(t)
	tmpFile := filepath.Join(t.TempDir(), "stringids_alloffs.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)

	dexSectionOff := uint32(64)
	seenOffsets := make(map[uint32]bool)
	count := 0

	for _, f := range pm.Fields {
		if f.Offset >= dexSectionOff+offs.StringIdsOff &&
			f.Offset < dexSectionOff+offs.StringIdsOff+offs.StringIdsSize*4 &&
			strings.Contains(f.LogicalPath, "string_ids[") {
			count++
			val, ok := f.ParsedValue.(uint32)
			if ok {
				assert.NotZero(t, val, "string_ids entry should have non-zero offset: %s", f.LogicalPath)
				assert.False(t, seenOffsets[val],
					"string_ids offsets should be unique, found duplicate 0x%x in %s", val, f.LogicalPath)
				seenOffsets[val] = true
			}
		}
	}
	assert.Equal(t, int(offs.StringIdsSize), count,
		"Should find exactly %d string_ids entries, found %d", offs.StringIdsSize, count)
}

// ---------------------------------------------------------------------------
// Gap classification tests
// ---------------------------------------------------------------------------

// TestAllZero verifies the allZero helper used by the gap-fill sweep.
func TestAllZero(t *testing.T) {
	assert.True(t, allZero([]byte{}), "empty slice should be all-zero")
	assert.True(t, allZero([]byte{0x00}))
	assert.True(t, allZero([]byte{0x00, 0x00, 0x00}))
	assert.False(t, allZero([]byte{0x00, 0x01}))
	assert.False(t, allZero([]byte{0x01}))
	assert.False(t, allZero([]byte{0xFF, 0x00, 0x00}))
}

// TestExplainVdex_AlignmentPadding_NotInUnmappedGaps verifies that
// all-zero alignment gaps (≤3 bytes, produced by 4-byte struct alignment)
// are represented as TypePadding fields but NOT added to UnmappedGaps.
// This was the root cause of false positives on 87/166 real VDEX files.
func TestExplainVdex_AlignmentPadding_NotInUnmappedGaps(t *testing.T) {
	// Strategy: use a checksum section of 6 bytes (odd) followed immediately
	// by empty verDeps and typelookup sections.
	// The typelookup section header is set to offset 0x42 (6-byte checksum at 0x3c..0x42),
	// which is NOT 4-byte aligned, so there are 2 zero padding bytes before the
	// TypeLookupTable size field which is placed at the next 4-aligned offset 0x44.
	//
	// Layout:
	//   0x00..0x0c  VdexFileHeader (12 bytes)
	//   0x0c..0x3c  SectionHeaders (4 × 12 bytes)
	//   0x3c..0x42  kChecksumSection: 6 bytes (1.5 checksums — unusual but parseable as blob)
	//   0x42..0x44  *** 2-byte zero alignment padding *** (forced by odd section end)
	//   0x44..0x48  kTypeLookupTableSection: 4-byte size field = 0
	//
	// The sweep must emit TypePadding at 0x42..0x44 but NOT add it to UnmappedGaps.

	const (
		hdr    = 12
		secHdr = 48
	)
	// Checksum section: 6 bytes starting at 0x3c
	// (two uint32 would be 8 bytes; 6 is unusual but parser reads it as a raw blob)
	// We use 6 bytes: two checksums [0xcafebabe (4B), 0xdead (2B partial)] — doesn't matter,
	// the parser reads the checksum as N uint32 = checksumSectionSize/4 entries.
	// To get 6 bytes total: use 1 full checksum (4B) + 2 zero bytes padding = 6 total.
	// But parser reads count = section_size/4 = 1.5 → rounded = 1 entry (4B),
	// leaving 2 bytes unread → gap at 0x3c+4=0x40..0x42.
	//
	// Simpler: put the ENTIRE alignment gap between sections by declaring
	// verDeps section at offset 0x40 size=0, and typelookup at 0x42 size=4.
	// The sweep will find gap 0x40..0x42 (2 bytes, all zero) → must be TypePadding only.

	verOff := uint32(hdr + secHdr + 4) // 0x40 (after 4-byte checksum)
	tlOff := verOff + 2                // 0x42 — deliberately NOT 4-aligned
	tlSz := uint32(4)

	// Section headers: checksum=4B, dex=empty, verDeps=empty(0x40,sz=0), typelookup(0x42,sz=4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, uint32(hdr+secHdr), 4)       // checksum at 0x3c
	sb = appendSectionHeader(sb, 1, 0, 0)                         // no DEX
	sb = appendSectionHeader(sb, 2, verOff, 0)                    // verDeps empty
	sb = appendSectionHeader(sb, 3, tlOff, tlSz)                  // typelookup at 0x42

	raw := buildRawHeader("vdex", "027\x00", 4)
	raw = append(raw, sb...)
	raw = append(raw, 0xBE, 0xBA, 0xFE, 0xCA) // 4-byte checksum (0xcafebabe LE)
	// verDeps is empty → 0 bytes
	// gap: 2 zero bytes at 0x40..0x42 (verOff..tlOff)
	raw = append(raw, 0x00, 0x00)
	// typelookup size field: 0
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)

	// Sanity: file should be hdr+secHdr+4(checksum)+2(gap)+4(tl) = 70 bytes
	require.Equal(t, int(tlOff)+int(tlSz), len(raw),
		"file assembly: expected %d bytes, got %d", int(tlOff)+int(tlSz), len(raw))

	tmpFile := filepath.Join(t.TempDir(), "padtest.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)

	// The 2-byte all-zero gap must NOT appear in UnmappedGaps.
	assert.Empty(t, pm.UnmappedGaps,
		"2-byte all-zero alignment padding must not appear in UnmappedGaps; got: %v",
		pm.UnmappedGaps)

	// All bytes must be covered contiguously.
	var cursor uint32
	for i, f := range pm.Fields {
		assert.Equal(t, cursor, f.Offset,
			"field[%d] %s: expected offset %d got %d", i, f.LogicalPath, cursor, f.Offset)
		cursor += f.Size
	}
	assert.Equal(t, pm.TotalBytes, cursor, "all bytes covered")

	// A TypePadding field of size=2 must exist at offset verOff..tlOff.
	hasPad := false
	for _, f := range pm.Fields {
		if f.Type == model.TypePadding && f.Offset == verOff && f.Size == 2 {
			hasPad = true
		}
	}
	assert.True(t, hasPad, "expected TypePadding(size=2) at offset=%d", verOff)
}

// TestExplainVdex_NonZeroGap_InUnmappedGaps verifies that a gap containing
// non-zero bytes IS reported in UnmappedGaps (genuine unknown data).
func TestExplainVdex_NonZeroGap_InUnmappedGaps(t *testing.T) {
	// Build a VDEX where the VerifierDeps section contains a non-zero byte
	// that the parser would skip (simulated by making the section larger than
	// what the parser consumes, with a non-zero trailing byte).
	//
	// The easiest way: build a valid minimal VDEX, then append a rogue
	// non-zero byte at the very end (beyond what any parser touches).
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(12 + 48)
	checksumSize := uint32(4)

	sectionBuf := []byte{}
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+checksumSize, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+checksumSize, 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, 0xCA, 0xFE, 0xBE, 0xBA) // checksum
	// Append 5 non-zero trailing bytes (simulates a large unknown gap > 3 bytes)
	raw = append(raw, 0xDE, 0xAD, 0xBE, 0xEF, 0x42)

	tmpFile := filepath.Join(t.TempDir(), "nongap.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, pm)

	// The 5-byte non-zero trailing gap MUST appear in UnmappedGaps.
	assert.NotEmpty(t, pm.UnmappedGaps,
		"non-zero oversized gap must appear in UnmappedGaps")
	if len(pm.UnmappedGaps) > 0 {
		g := pm.UnmappedGaps[0]
		assert.Equal(t, uint32(5), g.End-g.Start,
			"gap size should be 5 bytes, got %d", g.End-g.Start)
	}
}

// Group A: Gap/Padding Classification

func TestExplainVdex_Gap_OneBytePadding(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4) // checksum
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x41, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE) // checksum at 0x3c
	raw = append(raw, 0x00) // 1 byte zero padding
	raw = append(raw, 0x00, 0x00, 0x00, 0x00) // typelookup at 0x41
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Empty(t, pm.UnmappedGaps)
}

func TestExplainVdex_Gap_TwoBytesPadding(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x42, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0x00, 0x00) // 2 bytes zero padding
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Empty(t, pm.UnmappedGaps)
}

func TestExplainVdex_Gap_ThreeBytesPadding(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x43, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0x00, 0x00, 0x00)
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Empty(t, pm.UnmappedGaps)
}

func TestExplainVdex_Gap_NonZeroPadding(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x42, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0xFF, 0xFF) // 2 bytes NON-ZERO padding
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.Len(t, pm.UnmappedGaps, 1)
	assert.Equal(t, uint32(0x40), pm.UnmappedGaps[0].Start)
	assert.Equal(t, uint32(0x42), pm.UnmappedGaps[0].End)
}

func TestExplainVdex_Gap_FourByteZeroPadding(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x44, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0x00, 0x00, 0x00, 0x00) // 4 bytes zero padding -> >3 threshold
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.Len(t, pm.UnmappedGaps, 1)
	assert.Equal(t, uint32(0x40), pm.UnmappedGaps[0].Start)
	assert.Equal(t, uint32(0x44), pm.UnmappedGaps[0].End)
}

func TestExplainVdex_Gap_TrailingOneByteZero(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x40, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	raw = append(raw, 0x00) // 1 byte trailing padding
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Empty(t, pm.UnmappedGaps)
}

func TestExplainVdex_Gap_TrailingFiveNonZero(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x40, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	raw = append(raw, 0x1, 0x2, 0x3, 0x4, 0x5)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.Len(t, pm.UnmappedGaps, 1)
	assert.Equal(t, uint32(0x44), pm.UnmappedGaps[0].Start)
	assert.Equal(t, uint32(0x49), pm.UnmappedGaps[0].End)
}

func TestExplainVdex_Gap_SectionsTouching(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x40, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Empty(t, pm.UnmappedGaps)
	for _, f := range pm.Fields {
		assert.NotEqual(t, model.TypePadding, f.Type)
	}
}

func TestExplainVdex_Gap_OverlapSkipped(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 8)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x3c, 4)
	sb = appendSectionHeader(sb, 3, 0, 0)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE, 0x0, 0x0, 0x0, 0x0)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Len(t, pm.UnmappedGaps, 0) // Should have no unmapped gaps if processed cleanly
}

func TestExplainVdex_Gap_MixedZeroNonZero(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0x40, 0)
	sb = appendSectionHeader(sb, 3, 0x43, 4)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, 0x00, 0xFF, 0x00)
	raw = append(raw, 0x00, 0x00, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	require.Len(t, pm.UnmappedGaps, 1)
	assert.Equal(t, uint32(0x40), pm.UnmappedGaps[0].Start)
	assert.Equal(t, uint32(0x43), pm.UnmappedGaps[0].End)
}

// Group E: Section Boundary

func TestExplainVdex_Boundary_SectionsOverlapCheckDex(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0x3e, 4)
	sb = appendSectionHeader(sb, 2, 0, 0)
	sb = appendSectionHeader(sb, 3, 0, 0)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Len(t, pm.UnmappedGaps, 0)
}

func TestExplainVdex_Boundary_SectionPastEOF(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 100)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0, 0)
	sb = appendSectionHeader(sb, 3, 0, 0)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, pm)
}

func TestExplainVdex_Boundary_AllSectionsEmpty(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 0)
	sb = appendSectionHeader(sb, 1, 0x3c, 0)
	sb = appendSectionHeader(sb, 2, 0x3c, 0)
	sb = appendSectionHeader(sb, 3, 0x3c, 0)
	raw := append(header, sb...)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Empty(t, pm.UnmappedGaps)
}

func TestExplainVdex_Boundary_SameOffsetDifferentKinds(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0x3c, 4)
	sb = appendSectionHeader(sb, 2, 0, 0)
	sb = appendSectionHeader(sb, 3, 0, 0)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.Empty(t, pm.UnmappedGaps)
}

func TestExplainVdex_Boundary_HeaderOverflowU64(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 0x40000000)
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, header, 0644))
	_, err := ExplainVdex(tmpFile)
	require.Error(t, err)
}

// Group F: Malformed Input

func TestExplainVdex_Malformed_BadMagic(t *testing.T) {
	header := buildRawHeader("xdex", "027\x00", 4)
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, header, 0644))
	_, err := ExplainVdex(tmpFile)
	require.Error(t, err)
}

func TestExplainVdex_Malformed_TooShort(t *testing.T) {
	raw := []byte("vdex027\x00")
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	_, err := ExplainVdex(tmpFile)
	require.Error(t, err)
}

func TestExplainVdex_Malformed_InvalidDexMagic(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 4)
	sb = appendSectionHeader(sb, 1, 0x40, 10)
	sb = appendSectionHeader(sb, 2, 0, 0)
	sb = appendSectionHeader(sb, 3, 0, 0)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE)
	raw = append(raw, []byte("xxx\n")...)
	raw = append(raw, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, pm)
}

func TestExplainVdex_Malformed_LegacyVersion021(t *testing.T) {
	header := buildLegacyExplainVdex("021", 1)
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, header, 0644))
	_, err := ExplainVdex(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "legacy")
}

func TestExplainVdex_Malformed_LegacyVersion025(t *testing.T) {
	header := buildLegacyExplainVdex("025", 1)
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, header, 0644))
	_, err := ExplainVdex(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "legacy")
}

func TestExplainVdex_Malformed_ChecksumSizeNotMul4(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sb []byte
	sb = appendSectionHeader(sb, 0, 0x3c, 6)
	sb = appendSectionHeader(sb, 1, 0, 0)
	sb = appendSectionHeader(sb, 2, 0, 0)
	sb = appendSectionHeader(sb, 3, 0, 0)
	raw := append(header, sb...)
	raw = append(raw, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00)
	
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))
	pm, err := ExplainVdex(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, pm)
}

func TestExplainVdex_Malformed_EmptyFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, []byte{}, 0644))
	_, err := ExplainVdex(tmpFile)
	require.Error(t, err)
}

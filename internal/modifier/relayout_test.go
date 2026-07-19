package modifier

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func buildTestVdex(sections []model.VdexSection, sectionData map[uint32][]byte) []byte {
	header := make([]byte, 12)
	copy(header[:4], "vdex")
	copy(header[4:8], "027\x00")
	binary.LittleEndian.PutUint32(header[8:], uint32(len(sections)))

	sectionHeaders := make([]byte, len(sections)*12)
	for i, s := range sections {
		binary.LittleEndian.PutUint32(sectionHeaders[i*12:], s.Kind)
		binary.LittleEndian.PutUint32(sectionHeaders[i*12+4:], s.Offset)
		binary.LittleEndian.PutUint32(sectionHeaders[i*12+8:], s.Size)
	}

	raw := append(header, sectionHeaders...)
	// Pad to max offset+size
	maxEnd := len(raw)
	for _, s := range sections {
		end := int(s.Offset) + int(s.Size)
		if end > maxEnd {
			maxEnd = end
		}
	}
	for len(raw) < maxEnd {
		raw = append(raw, 0)
	}
	// Fill section data
	for kind, data := range sectionData {
		for _, s := range sections {
			if s.Kind == kind {
				copy(raw[s.Offset:], data)
			}
		}
	}
	return raw
}

func TestRelayoutVdex_ExpandVerifier(t *testing.T) {
	// Original: checksum(4B) + verifier(28B) + typelookup(32B)
	sections := []model.VdexSection{
		{Kind: model.SectionChecksum, Offset: 60, Size: 4},
		{Kind: model.SectionDex, Offset: 0, Size: 0},
		{Kind: model.SectionVerifierDeps, Offset: 64, Size: 28},
		{Kind: model.SectionTypeLookup, Offset: 92, Size: 32},
	}
	checksumData := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	verifierData := make([]byte, 28)
	for i := range verifierData {
		verifierData[i] = 0xAA
	}
	typelookupData := make([]byte, 32)
	for i := range typelookupData {
		typelookupData[i] = 0xBB
	}

	raw := buildTestVdex(sections, map[uint32][]byte{
		model.SectionChecksum:     checksumData,
		model.SectionVerifierDeps: verifierData,
		model.SectionTypeLookup:   typelookupData,
	})

	// New verifier is 100 bytes (was 28)
	newVerifier := make([]byte, 100)
	for i := range newVerifier {
		newVerifier[i] = 0xCC
	}

	result, err := RelayoutVdex(raw, sections, model.SectionVerifierDeps, newVerifier)
	require.NoError(t, err)

	// Header preserved
	assert.Equal(t, "vdex", string(result[:4]))
	assert.Equal(t, uint32(4), binary.LittleEndian.Uint32(result[8:12]))

	// Parse new section headers
	for i := 0; i < 4; i++ {
		base := 12 + i*12
		kind := binary.LittleEndian.Uint32(result[base:])
		offset := binary.LittleEndian.Uint32(result[base+4:])
		size := binary.LittleEndian.Uint32(result[base+8:])

		switch kind {
		case model.SectionChecksum:
			assert.Equal(t, uint32(4), size)
			assert.Equal(t, checksumData, result[offset:offset+size])
		case model.SectionDex:
			assert.Equal(t, uint32(0), size)
		case model.SectionVerifierDeps:
			assert.Equal(t, uint32(100), size)
			assert.Equal(t, newVerifier, result[offset:offset+size])
		case model.SectionTypeLookup:
			assert.Equal(t, uint32(32), size)
			assert.Equal(t, typelookupData, result[offset:offset+size])
		}
	}

	// Result must be larger than original
	assert.Greater(t, len(result), len(raw))
}

func TestRelayoutVdex_ShrinkVerifier(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: model.SectionChecksum, Offset: 60, Size: 4},
		{Kind: model.SectionDex, Offset: 0, Size: 0},
		{Kind: model.SectionVerifierDeps, Offset: 64, Size: 100},
		{Kind: model.SectionTypeLookup, Offset: 164, Size: 32},
	}
	raw := buildTestVdex(sections, map[uint32][]byte{
		model.SectionChecksum:     {0x01, 0x02, 0x03, 0x04},
		model.SectionVerifierDeps: make([]byte, 100),
		model.SectionTypeLookup:   make([]byte, 32),
	})

	newVerifier := make([]byte, 20) // shrink from 100 to 20
	result, err := RelayoutVdex(raw, sections, model.SectionVerifierDeps, newVerifier)
	require.NoError(t, err)

	assert.Less(t, len(result), len(raw))

	// Verify section data integrity
	for i := 0; i < 4; i++ {
		base := 12 + i*12
		kind := binary.LittleEndian.Uint32(result[base:])
		offset := binary.LittleEndian.Uint32(result[base+4:])
		size := binary.LittleEndian.Uint32(result[base+8:])
		if kind == model.SectionVerifierDeps {
			assert.Equal(t, uint32(20), size)
		}
		if size > 0 {
			require.LessOrEqual(t, int(offset+size), len(result))
		}
	}
}

func TestRelayoutVdex_PreservesAlignment(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: model.SectionChecksum, Offset: 60, Size: 4},
		{Kind: model.SectionDex, Offset: 0, Size: 0},
		{Kind: model.SectionVerifierDeps, Offset: 64, Size: 28},
		{Kind: model.SectionTypeLookup, Offset: 92, Size: 32},
	}
	raw := buildTestVdex(sections, map[uint32][]byte{
		model.SectionChecksum:     {0x01, 0x02, 0x03, 0x04},
		model.SectionVerifierDeps: make([]byte, 28),
		model.SectionTypeLookup:   make([]byte, 32),
	})

	// 13 bytes — not aligned to 4
	newVerifier := make([]byte, 13)
	result, err := RelayoutVdex(raw, sections, model.SectionVerifierDeps, newVerifier)
	require.NoError(t, err)

	// All non-zero section offsets must be 4-byte aligned
	for i := 0; i < 4; i++ {
		base := 12 + i*12
		offset := binary.LittleEndian.Uint32(result[base+4:])
		size := binary.LittleEndian.Uint32(result[base+8:])
		if size > 0 {
			assert.Equal(t, 0, int(offset)%4, "section offset %d must be 4-byte aligned", offset)
		}
	}
}

func TestRelayoutVdex_SameSize(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: model.SectionChecksum, Offset: 60, Size: 4},
		{Kind: model.SectionDex, Offset: 0, Size: 0},
		{Kind: model.SectionVerifierDeps, Offset: 64, Size: 28},
		{Kind: model.SectionTypeLookup, Offset: 92, Size: 32},
	}
	raw := buildTestVdex(sections, map[uint32][]byte{
		model.SectionChecksum:     {0x01, 0x02, 0x03, 0x04},
		model.SectionVerifierDeps: make([]byte, 28),
		model.SectionTypeLookup:   make([]byte, 32),
	})

	newVerifier := make([]byte, 28) // same size
	result, err := RelayoutVdex(raw, sections, model.SectionVerifierDeps, newVerifier)
	require.NoError(t, err)

	// Should produce same-size result (no gaps in original)
	assert.Equal(t, len(raw), len(result))
}

func TestRelayoutVdex_HeaderPreserved(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: model.SectionChecksum, Offset: 60, Size: 4},
		{Kind: model.SectionDex, Offset: 0, Size: 0},
		{Kind: model.SectionVerifierDeps, Offset: 64, Size: 28},
		{Kind: model.SectionTypeLookup, Offset: 92, Size: 32},
	}
	raw := buildTestVdex(sections, map[uint32][]byte{
		model.SectionChecksum:     {0xDE, 0xAD, 0xBE, 0xEF},
		model.SectionVerifierDeps: make([]byte, 28),
		model.SectionTypeLookup:   make([]byte, 32),
	})

	result, err := RelayoutVdex(raw, sections, model.SectionVerifierDeps, make([]byte, 50))
	require.NoError(t, err)

	// Magic and version preserved
	assert.Equal(t, raw[:8], result[:8])
	// NumSections preserved
	assert.Equal(t, raw[8:12], result[8:12])
}

func TestRelayoutVdex_PreservesGapsAndTrailingBytes(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: model.SectionChecksum, Offset: 60, Size: 4},
		{Kind: model.SectionDex, Offset: 0, Size: 0},
		{Kind: model.SectionVerifierDeps, Offset: 68, Size: 4},
		{Kind: model.SectionTypeLookup, Offset: 80, Size: 4},
	}
	raw := buildTestVdex(sections, map[uint32][]byte{
		model.SectionChecksum:     {1, 2, 3, 4},
		model.SectionVerifierDeps: {5, 6, 7, 8},
		model.SectionTypeLookup:   {9, 10, 11, 12},
	})
	copy(raw[64:68], []byte("GAP1"))
	copy(raw[72:80], []byte("GAP-TWO!"))
	raw = append(raw, []byte("TRAILING")...)

	result, err := RelayoutVdex(raw, sections, model.SectionVerifierDeps, []byte("NEW-VERIFIER"))
	require.NoError(t, err)

	typeLookupOffset := binary.LittleEndian.Uint32(result[52:56])
	assert.Equal(t, []byte("GAP1"), result[64:68])
	assert.Equal(t, []byte("GAP-TWO!"), result[typeLookupOffset-8:typeLookupOffset])
	assert.Equal(t, []byte{9, 10, 11, 12}, result[typeLookupOffset:typeLookupOffset+4])
	assert.Equal(t, []byte("TRAILING"), result[len(result)-8:])
}

func TestRelayoutVdex_RejectsOutOfRangeSection(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: model.SectionVerifierDeps, Offset: 60, Size: 4},
		{Kind: model.SectionTypeLookup, Offset: ^uint32(0), Size: 4},
	}
	raw := buildTestVdex(sections[:1], map[uint32][]byte{model.SectionVerifierDeps: {1, 2, 3, 4}})

	result, err := RelayoutVdex(raw, sections, model.SectionVerifierDeps, []byte("larger"))

	require.Error(t, err)
	assert.Nil(t, result)
}

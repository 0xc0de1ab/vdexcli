package parser

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func buildTypeLookupEntry(strOffset, data uint32) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], strOffset)
	binary.LittleEndian.PutUint32(buf[4:], data)
	return buf
}

func TestParseTypeLookupSection_OutOfRange(t *testing.T) {
	raw := make([]byte, 50)
	s := model.VdexSection{Offset: 200, Size: 20}
	report, diags := ParseTypeLookupSection(raw, s, nil, 1)
	assert.NotNil(t, report)
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "out of file range")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestParseTypeLookupSection_Truncated(t *testing.T) {
	raw := make([]byte, 6) // need 4 bytes for size, but section says 2 dexes
	s := model.VdexSection{Offset: 0, Size: 6}
	report, diags := ParseTypeLookupSection(raw, s, nil, 2)
	assert.NotNil(t, report)
	require.Len(t, report.Dexes, 1) // first dex parsed, second truncated
	assert.NotEmpty(t, diags)
}

func TestParseTypeLookupSection_DexExceedsSection(t *testing.T) {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint32(raw[0:], 9999) // size=9999 but only 4 bytes left
	s := model.VdexSection{Offset: 0, Size: 8}
	report, diags := ParseTypeLookupSection(raw, s, nil, 1)
	assert.NotNil(t, report)
	assert.Empty(t, report.Dexes)
	require.NotEmpty(t, diags)
	assert.Contains(t, diags[0].Message, "exceeds section")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestParseTypeLookupSection_SingleDex(t *testing.T) {
	// Build: 4 buckets (32 bytes), 2 non-empty
	entries := make([]byte, 0, 32)
	entries = append(entries, buildTypeLookupEntry(0x100, 0x00000001)...) // non-empty
	entries = append(entries, buildTypeLookupEntry(0, 0)...)              // empty
	entries = append(entries, buildTypeLookupEntry(0x200, 0x00000002)...) // non-empty
	entries = append(entries, buildTypeLookupEntry(0, 0)...)              // empty

	// Section: uint32 size + entries
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(entries)))
	section := append(sizeBytes, entries...)

	raw := section
	s := model.VdexSection{Offset: 0, Size: uint32(len(raw))}
	dex := &model.DexContext{
		Rep:                model.DexReport{ClassDefs: 4},
		StringOffsetToName: map[uint32]string{0x100: "Lfoo/Bar;", 0x200: "Lbaz/Qux;"},
	}
	report, warnings := ParseTypeLookupSection(raw, s, []*model.DexContext{dex}, 1)

	require.Len(t, report.Dexes, 1)
	d := report.Dexes[0]
	assert.Equal(t, 4, d.BucketCount)
	assert.Equal(t, 2, d.EntryCount)
	assert.Equal(t, 2, d.NonEmptyBuckets)
	assert.Equal(t, uint32(32), d.RawSize)
	// Verify descriptors resolved
	require.GreaterOrEqual(t, len(d.Samples), 2)
	assert.Equal(t, "Lfoo/Bar;", d.Samples[0].Descriptor)
	assert.Equal(t, "Lbaz/Qux;", d.Samples[1].Descriptor)
	// No critical warnings expected (class_defs_size=4 is valid)
	for _, w := range warnings {
		assert.NotContains(t, w, "truncated")
		assert.NotContains(t, w, "exceeds")
	}
}

func TestParseTypeLookupDex_EmptyPayload(t *testing.T) {
	d := parseTypeLookupDex(nil, nil)
	assert.Equal(t, uint32(0), d.RawSize)
	require.NotEmpty(t, d.Warnings)
	assert.Contains(t, d.Warnings[0], "empty payload")
}

func TestParseTypeLookupDex_UnalignedPayload(t *testing.T) {
	raw := make([]byte, 10) // not multiple of 8
	d := parseTypeLookupDex(raw, nil)
	require.NotEmpty(t, d.Warnings)
	assert.Contains(t, d.Warnings[0], "not aligned")
	assert.Equal(t, 1, d.BucketCount) // truncated to 8 bytes = 1 bucket
}

func TestParseTypeLookupDex_ZeroClassDefs(t *testing.T) {
	raw := make([]byte, 8) // 1 empty bucket
	dex := &model.DexContext{Rep: model.DexReport{ClassDefs: 0}}
	d := parseTypeLookupDex(raw, dex)
	assert.Equal(t, uint32(0), d.MaskBits)
	require.NotEmpty(t, d.Warnings)
	assert.Contains(t, d.Warnings[0], "class_defs_size is 0")
}

func TestParseTypeLookupDex_ChainStats(t *testing.T) {
	// Build: 2 buckets. Bucket 0 has entry with next_delta=1 pointing to bucket 1.
	// maskBits for classDefs=2: MinimumBitsToStore(1) = 1, so mask=1.
	// Entry packed: (hash << 2*maskBits) | (classIdx << maskBits) | nextDelta
	// Bucket 0: strOff=0x100, classIdx=0, nextDelta=1, hash=0
	//   packed = (0 << 2) | (0 << 1) | 1 = 1
	// Bucket 1: strOff=0x200, classIdx=1, nextDelta=0 (last), hash=0
	//   packed = (0 << 2) | (1 << 1) | 0 = 2

	entries := make([]byte, 16)
	binary.LittleEndian.PutUint32(entries[0:], 0x100)
	binary.LittleEndian.PutUint32(entries[4:], 1) // nextDelta=1
	binary.LittleEndian.PutUint32(entries[8:], 0x200)
	binary.LittleEndian.PutUint32(entries[12:], 2) // classIdx=1, nextDelta=0

	dex := &model.DexContext{
		Rep:                model.DexReport{ClassDefs: 2},
		StringOffsetToName: map[uint32]string{0x100: "La;", 0x200: "Lb;"},
	}
	d := parseTypeLookupDex(entries, dex)

	assert.Equal(t, 2, d.BucketCount)
	assert.Equal(t, 2, d.NonEmptyBuckets)
	assert.Equal(t, 2, d.MaxChainLen, "chain from bucket 0→1 has length 2")
	assert.InDelta(t, 1.5, d.AvgChainLen, 0.01, "avg of chain(0→1)=2 and chain(1)=1")
}

func TestParseTypeLookupSection_MultipleDexes(t *testing.T) {
	// Dex 0: 1 bucket (8 bytes), Dex 1: 2 buckets (16 bytes)
	dex0Entries := buildTypeLookupEntry(0x100, 0)
	dex1Entries := append(buildTypeLookupEntry(0x200, 0), buildTypeLookupEntry(0x300, 0)...)

	var section []byte
	sz0 := make([]byte, 4)
	binary.LittleEndian.PutUint32(sz0, uint32(len(dex0Entries)))
	section = append(section, sz0...)
	section = append(section, dex0Entries...)

	sz1 := make([]byte, 4)
	binary.LittleEndian.PutUint32(sz1, uint32(len(dex1Entries)))
	section = append(section, sz1...)
	section = append(section, dex1Entries...)

	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	report, _ := ParseTypeLookupSection(section, s, nil, 2)

	require.Len(t, report.Dexes, 2)
	assert.Equal(t, 0, report.Dexes[0].DexIndex)
	assert.Equal(t, 1, report.Dexes[0].BucketCount)
	assert.Equal(t, 1, report.Dexes[1].DexIndex)
	assert.Equal(t, 2, report.Dexes[1].BucketCount)
}

func TestParseTypeLookupDex_EmptyAfterAlignment(t *testing.T) {
	// 7 bytes → after %8 trim → 0 bytes → "empty table"
	raw := make([]byte, 7)
	for i := range raw {
		raw[i] = 0xFF
	}
	s := model.VdexSection{Offset: 0, Size: uint32(4 + len(raw))}
	section := make([]byte, 4+len(raw))
	binary.LittleEndian.PutUint32(section[0:], uint32(len(raw)))
	copy(section[4:], raw)

	report, _ := ParseTypeLookupSection(section, s, nil, 1)
	require.Len(t, report.Dexes, 1)
	assert.Contains(t, report.Dexes[0].Warnings, "payload size is not aligned to 8-byte entries; last entry may be truncated")
	assert.Contains(t, report.Dexes[0].Warnings, "empty table")
}

func TestParseTypeLookupDex_HugeClassDefs(t *testing.T) {
	// classDefs > MaxTypeLookupClasses → unsupported warning + clamped bits
	entries := make([]byte, 16) // 2 buckets
	entries = append(entries, buildTypeLookupEntry(0x100, 0x01)...)
	entries = append(entries, buildTypeLookupEntry(0, 0)...)

	section := make([]byte, 4+len(entries))
	binary.LittleEndian.PutUint32(section[0:], uint32(len(entries)))
	copy(section[4:], entries)

	dex := &model.DexContext{Rep: model.DexReport{ClassDefs: 0xFFFF + 1}} // > MaxTypeLookupClasses
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	report, _ := ParseTypeLookupSection(section, s, []*model.DexContext{dex}, 1)
	require.Len(t, report.Dexes, 1)

	hasUnsupported := false
	for _, w := range report.Dexes[0].Warnings {
		if strings.Contains(w, "unsupported") {
			hasUnsupported = true
		}
	}
	assert.True(t, hasUnsupported, "should warn about unsupported class_defs_size")
}

func TestParseTypeLookupDex_CycleDetection(t *testing.T) {
	// 2 buckets: bucket 0 has next_delta=0 (self-loop if mask allows)
	// With classDefs=2, maskBits=1, mask=1. packed=0x02 → classIdx=(0x02>>1)&1=1, next=(0x02)&1=0
	// next_delta=0 means end of chain. Need delta that loops back.
	// With 2 buckets, maskBits=1. bucket 0: packed with next_delta=1 → goes to bucket 1
	// bucket 1: packed with next_delta=1 → goes to bucket 0 → cycle!
	entries := make([]byte, 16)
	// bucket 0: offset=0x100, packed: classIdx=0 (<<1), next_delta=1 → packed = 0|1 = 1
	binary.LittleEndian.PutUint32(entries[0:], 0x100)
	binary.LittleEndian.PutUint32(entries[4:], 1) // next_delta=1
	// bucket 1: offset=0x200, packed with next_delta=1 → loops to bucket 0
	binary.LittleEndian.PutUint32(entries[8:], 0x200)
	binary.LittleEndian.PutUint32(entries[12:], 1) // next_delta=1

	section := make([]byte, 4+len(entries))
	binary.LittleEndian.PutUint32(section[0:], uint32(len(entries)))
	copy(section[4:], entries)

	dex := &model.DexContext{Rep: model.DexReport{ClassDefs: 2}}
	s := model.VdexSection{Offset: 0, Size: uint32(len(section))}
	report, _ := ParseTypeLookupSection(section, s, []*model.DexContext{dex}, 1)
	require.Len(t, report.Dexes, 1)

	hasCycle := false
	for _, w := range report.Dexes[0].Warnings {
		if strings.Contains(w, "cycle") {
			hasCycle = true
		}
	}
	assert.True(t, hasCycle, "should detect cycle in lookup chain")
}

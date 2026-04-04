package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func sampleReport(file string) *model.VdexReport {
	return &model.VdexReport{
		File:      file,
		Size:      200,
		Header:    model.VdexHeader{Magic: "vdex", Version: "027", NumSections: 4},
		Sections:  []model.VdexSection{{Kind: 0, Offset: 60, Size: 4, Name: "kChecksumSection"}},
		Checksums: []uint32{0xCAFE},
		Dexes:     []model.DexReport{{Index: 0, ChecksumId: 0xBEEF, ClassDefs: 3, Signature: "abc"}},
		Verifier: &model.VerifierReport{Dexes: []model.VerifierDexReport{
			{DexIndex: 0, VerifiedClasses: 2, UnverifiedClasses: 1, AssignabilityPairs: 5, ExtraStringCount: 1},
		}},
		TypeLookup: &model.TypeLookupReport{Dexes: []model.TypeLookupDexReport{
			{DexIndex: 0, BucketCount: 8, EntryCount: 6},
		}},
	}
}

func TestDiff_Identical(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	d := Diff(a, b)
	assert.True(t, d.Summary.Identical)
	assert.Empty(t, d.SectionDiffs)
	assert.Nil(t, d.ChecksumDiff)
	assert.Empty(t, d.DexDiffs)
	assert.Nil(t, d.VerifierDiff)
	assert.Nil(t, d.TypeLookupDiff)
}

func TestDiff_HeaderChanged(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Header.Version = "028"
	d := Diff(a, b)
	assert.True(t, d.HeaderChanged)
	assert.Equal(t, "027", d.HeaderDiff.VersionA)
	assert.Equal(t, "028", d.HeaderDiff.VersionB)
}

func TestDiff_SectionSizeChanged(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Sections[0].Size = 100
	d := Diff(a, b)
	assert.Len(t, d.SectionDiffs, 1)
	assert.Equal(t, 96, d.SectionDiffs[0].SizeDelta)
}

func TestDiff_ChecksumChanged(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Checksums = []uint32{0xDEAD}
	d := Diff(a, b)
	assert.NotNil(t, d.ChecksumDiff)
	assert.Len(t, d.ChecksumDiff.Changed, 1)
}

func TestDiff_ChecksumAdded(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Checksums = []uint32{0xCAFE, 0xBEEF}
	d := Diff(a, b)
	assert.NotNil(t, d.ChecksumDiff)
	assert.Equal(t, 1, d.ChecksumDiff.AddedB)
}

func TestDiff_ChecksumRemoved(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Checksums = nil
	d := Diff(a, b)
	assert.NotNil(t, d.ChecksumDiff)
	assert.Equal(t, 1, d.ChecksumDiff.RemovedA)
}

func TestDiff_DexModified(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Dexes[0].ChecksumId = 0x1111
	d := Diff(a, b)
	assert.Len(t, d.DexDiffs, 1)
	assert.Equal(t, "modified", d.DexDiffs[0].Status)
}

func TestDiff_DexAdded(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Dexes = append(b.Dexes, model.DexReport{Index: 1, ChecksumId: 0x2222})
	d := Diff(a, b)
	assert.Len(t, d.DexDiffs, 1)
	assert.Equal(t, "added", d.DexDiffs[0].Status)
}

func TestDiff_DexRemoved(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Dexes = nil
	d := Diff(a, b)
	assert.Len(t, d.DexDiffs, 1)
	assert.Equal(t, "removed", d.DexDiffs[0].Status)
}

func TestDiff_VerifierChanged(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Verifier.Dexes[0].VerifiedClasses = 0
	b.Verifier.Dexes[0].UnverifiedClasses = 3
	d := Diff(a, b)
	assert.NotNil(t, d.VerifierDiff)
	assert.Equal(t, 2, d.VerifierDiff.TotalChanged)
	assert.Len(t, d.VerifierDiff.DexDiffs, 1)
	assert.Equal(t, -2, d.VerifierDiff.DexDiffs[0].VerifiedDelta)
}

func TestDiff_VerifierNil(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	a.Verifier = nil
	b.Verifier = nil
	d := Diff(a, b)
	assert.Nil(t, d.VerifierDiff)
}

func TestDiff_TypeLookupChanged(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.TypeLookup.Dexes[0].EntryCount = 10
	d := Diff(a, b)
	assert.NotNil(t, d.TypeLookupDiff)
	assert.Len(t, d.TypeLookupDiff.DexDiffs, 1)
	assert.Equal(t, 4, d.TypeLookupDiff.DexDiffs[0].EntriesDelta)
}

func TestDiff_TypeLookupNil(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	a.TypeLookup = nil
	b.TypeLookup = nil
	d := Diff(a, b)
	assert.Nil(t, d.TypeLookupDiff)
}

func TestDiff_SummaryCountsAll(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Header.Version = "028"
	b.Sections[0].Size = 100
	b.Checksums = []uint32{0xDEAD}
	b.Dexes[0].ChecksumId = 0x1111
	b.Verifier.Dexes[0].VerifiedClasses = 0
	b.TypeLookup.Dexes[0].EntryCount = 10
	d := Diff(a, b)
	assert.False(t, d.Summary.Identical)
	assert.Equal(t, 1, d.Summary.SectionsChanged)
	assert.Equal(t, 1, d.Summary.ChecksumsChanged)
	assert.Equal(t, 1, d.Summary.DexFilesChanged)
	assert.Equal(t, 2, d.Summary.VerifierChanged)
	assert.Equal(t, 4, d.Summary.TypeLookupChanged)
}

func TestDiff_VerifierOneSideNil(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	a.Verifier = nil
	d := Diff(a, b)
	assert.NotNil(t, d.VerifierDiff)
}

func TestDiff_TypeLookupOneSideNil(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.TypeLookup = nil
	d := Diff(a, b)
	assert.NotNil(t, d.TypeLookupDiff)
}

func TestDiff_HeaderMagicChanged(t *testing.T) {
	a := sampleReport("a.vdex")
	b := sampleReport("b.vdex")
	b.Header.Magic = "oatx"
	d := Diff(a, b)
	assert.True(t, d.HeaderChanged)
	assert.Equal(t, "vdex", d.HeaderDiff.MagicA)
	assert.Equal(t, "oatx", d.HeaderDiff.MagicB)
}

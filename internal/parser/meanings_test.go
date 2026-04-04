package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParserMeanings_NotNil(t *testing.T) {
	m := NewParserMeanings()
	require.NotNil(t, m)
}

func TestNewParserMeanings_VdexFileFields(t *testing.T) {
	m := NewParserMeanings()
	assert.NotEmpty(t, m.VdexFile.Magic)
	assert.NotEmpty(t, m.VdexFile.Version)
	assert.NotEmpty(t, m.VdexFile.Sections)
	assert.NotEmpty(t, m.VdexFile.Checksums)
	assert.NotEmpty(t, m.VdexFile.DexFiles)
	assert.NotEmpty(t, m.VdexFile.Verifier)
	assert.NotEmpty(t, m.VdexFile.TypeLookup)
	assert.NotEmpty(t, m.VdexFile.Warnings)
	assert.NotEmpty(t, m.VdexFile.Errors)
	assert.NotEmpty(t, m.VdexFile.SchemaVer)
	assert.NotEmpty(t, m.VdexFile.WarningsByCategory)
}

func TestNewParserMeanings_SectionKinds(t *testing.T) {
	m := NewParserMeanings()
	assert.Contains(t, m.SectionKind, "0")
	assert.Contains(t, m.SectionKind, "1")
	assert.Contains(t, m.SectionKind, "2")
	assert.Contains(t, m.SectionKind, "3")
	assert.Equal(t, "kChecksumSection", m.SectionKind["0"])
}

func TestNewParserMeanings_DexHeader(t *testing.T) {
	m := NewParserMeanings()
	assert.NotEmpty(t, m.DexHeader.Magic)
	assert.NotEmpty(t, m.DexHeader.Signature)
	assert.NotEmpty(t, m.DexHeader.StringIds)
	assert.NotEmpty(t, m.DexHeader.StringIdsOff)
	assert.NotEmpty(t, m.DexHeader.ClassDefs)
	assert.NotEmpty(t, m.DexHeader.ClassDefsOff)
	assert.NotEmpty(t, m.DexHeader.ClassPreview)
}

func TestNewParserMeanings_VerifierDeps(t *testing.T) {
	m := NewParserMeanings()
	assert.NotEmpty(t, m.VerifierDeps.VerifiedClasses)
	assert.NotEmpty(t, m.VerifierDeps.AssignabilityPair)
	assert.NotEmpty(t, m.VerifierDeps.ExtraStringCount)
}

func TestNewParserMeanings_TypeLookup(t *testing.T) {
	m := NewParserMeanings()
	assert.NotEmpty(t, m.TypeLookup.BucketCount)
	assert.NotEmpty(t, m.TypeLookup.MaxChainLen)
	assert.NotEmpty(t, m.TypeLookup.SampleEntries)
}

package parser

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func buildLegacyVdex(version string, numDex uint32, verifierSize uint32) []byte {
	raw := make([]byte, legacyHeaderSize)
	copy(raw[0:4], "vdex")
	copy(raw[4:8], version+"\x00")
	copy(raw[8:12], "002\x00")
	binary.LittleEndian.PutUint32(raw[12:16], numDex)
	binary.LittleEndian.PutUint32(raw[16:20], verifierSize)
	binary.LittleEndian.PutUint32(raw[20:24], 0) // bcp checksums
	binary.LittleEndian.PutUint32(raw[24:28], 0) // clc

	// Checksums
	for i := uint32(0); i < numDex; i++ {
		chk := make([]byte, 4)
		binary.LittleEndian.PutUint32(chk, 0xCAFE0000+i)
		raw = append(raw, chk...)
	}

	// DexSectionHeader (all zeros = no dex section)
	raw = append(raw, make([]byte, dexSectionHeaderSize)...)

	// Verifier deps data
	raw = append(raw, make([]byte, verifierSize)...)

	return raw
}

func TestIsLegacyVersion(t *testing.T) {
	assert.True(t, IsLegacyVersion("021"))
	assert.True(t, IsLegacyVersion("023"))
	assert.True(t, IsLegacyVersion("026"))
	assert.False(t, IsLegacyVersion("027"))
	assert.False(t, IsLegacyVersion("020"))
	assert.False(t, IsLegacyVersion("028"))
}

func TestParseLegacyHeader(t *testing.T) {
	raw := buildLegacyVdex("021", 2, 100)
	h, lf := parseLegacyHeader(raw)
	assert.Equal(t, "vdex", h.Magic)
	assert.Equal(t, "021", h.Version)
	assert.Equal(t, "002", lf.dexSectionVersion)
	assert.Equal(t, uint32(2), lf.numDexFiles)
	assert.Equal(t, uint32(100), lf.verifierDepsSize)
}

func TestParseVdexLegacy_Basic(t *testing.T) {
	raw := buildLegacyVdex("021", 1, 20)
	tmpFile := filepath.Join(t.TempDir(), "legacy.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdexLegacy(tmpFile, false)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "vdex", report.Header.Magic)
	assert.Equal(t, "021", report.Header.Version)
	require.Len(t, report.Checksums, 1)
	assert.Equal(t, uint32(0xCAFE0000), report.Checksums[0])
	assert.NotEmpty(t, report.Sections)
}

func TestParseVdexLegacy_MultiDex(t *testing.T) {
	raw := buildLegacyVdex("024", 3, 0)
	tmpFile := filepath.Join(t.TempDir(), "legacy3.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdexLegacy(tmpFile, false)
	require.NoError(t, err)
	require.Len(t, report.Checksums, 3)
	assert.Equal(t, uint32(0xCAFE0002), report.Checksums[2])
}

func TestParseVdexLegacy_TooSmall(t *testing.T) {
	raw := []byte("vdex021")
	tmpFile := filepath.Join(t.TempDir(), "tiny.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdexLegacy(tmpFile, false)
	require.Error(t, err)
	assert.NotEmpty(t, report.Errors)
}

func TestParseVdexLegacy_InvalidMagic(t *testing.T) {
	raw := buildLegacyVdex("021", 1, 0)
	copy(raw[0:4], "oops")
	tmpFile := filepath.Join(t.TempDir(), "badmagic.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, _ := ParseVdexLegacy(tmpFile, false)
	assert.NotEmpty(t, report.Errors)
}

func TestParseVdex_AutoDetectsLegacy(t *testing.T) {
	raw := buildLegacyVdex("021", 1, 0)
	tmpFile := filepath.Join(t.TempDir(), "auto.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	// ParseVdex should auto-detect and delegate to ParseVdexLegacy
	report, _, err := ParseVdex(tmpFile, false)
	require.NoError(t, err)
	assert.Equal(t, "021", report.Header.Version)
	assert.NotEmpty(t, report.Checksums)
}

func TestParseLegacy_WithVerifierSection(t *testing.T) {
	raw := buildLegacyVdex("025", 1, 32)
	tmpFile := filepath.Join(t.TempDir(), "verifier.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdexLegacy(tmpFile, false)
	require.NoError(t, err)

	hasVerifier := false
	for _, s := range report.Sections {
		if s.Kind == model.SectionVerifierDeps {
			hasVerifier = true
			assert.Equal(t, uint32(32), s.Size)
		}
	}
	assert.True(t, hasVerifier)
}

func TestParseLegacy_WithMeanings(t *testing.T) {
	raw := buildLegacyVdex("026", 1, 0)
	tmpFile := filepath.Join(t.TempDir(), "meanings.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, _ := ParseVdexLegacy(tmpFile, true)
	assert.NotNil(t, report.Meanings)
}

func TestParseLegacy_WarnsAboutLimitedSupport(t *testing.T) {
	raw := buildLegacyVdex("022", 1, 0)
	tmpFile := filepath.Join(t.TempDir(), "limited.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, _ := ParseVdexLegacy(tmpFile, false)
	hasLimitedWarn := false
	for _, d := range report.Diagnostics {
		if d.Code == model.WarnVersionMismatch {
			hasLimitedWarn = true
		}
	}
	assert.True(t, hasLimitedWarn, "should warn about limited legacy support")
}

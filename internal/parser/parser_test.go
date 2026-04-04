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

// buildRawHeader writes a 12-byte VDEX file header into a new byte slice.
func buildRawHeader(magic string, version string, numSections uint32) []byte {
	buf := make([]byte, 12)
	copy(buf[0:4], magic)
	copy(buf[4:8], version)
	binary.LittleEndian.PutUint32(buf[8:12], numSections)
	return buf
}

// appendSectionHeader appends a 12-byte section header entry.
func appendSectionHeader(buf []byte, kind, offset, size uint32) []byte {
	entry := make([]byte, 12)
	binary.LittleEndian.PutUint32(entry[0:4], kind)
	binary.LittleEndian.PutUint32(entry[4:8], offset)
	binary.LittleEndian.PutUint32(entry[8:12], size)
	return append(buf, entry...)
}

// --- parseHeader tests (internal, same package) ---

func TestParseHeader_Valid(t *testing.T) {
	raw := buildRawHeader("vdex", "027\x00", 4)
	h := parseHeader(raw)

	assert.Equal(t, "vdex", h.Magic)
	assert.Equal(t, "027", h.Version)
	assert.Equal(t, uint32(4), h.NumSections)
}

func TestParseHeader_VersionTrimNulls(t *testing.T) {
	raw := buildRawHeader("vdex", "027\x00", 4)
	h := parseHeader(raw)
	assert.Equal(t, "027", h.Version, "trailing null should be trimmed")

	raw2 := buildRawHeader("vdex", "28\x00\x00", 4)
	h2 := parseHeader(raw2)
	assert.Equal(t, "28", h2.Version, "multiple trailing nulls should be trimmed")
}

func TestParseHeader_InvalidMagic(t *testing.T) {
	raw := buildRawHeader("oatx", "027\x00", 4)
	h := parseHeader(raw)
	assert.Equal(t, "oatx", h.Magic)
}

// --- ParseSections tests ---

func TestParseSections_StandardFour(t *testing.T) {
	var buf []byte
	buf = appendSectionHeader(buf, 0, 60, 8)    // checksum
	buf = appendSectionHeader(buf, 1, 68, 112)  // dex
	buf = appendSectionHeader(buf, 2, 180, 256) // verifier
	buf = appendSectionHeader(buf, 3, 436, 64)  // typelookup

	sections, index, diags := ParseSections(buf, 4)
	assert.Empty(t, diags)
	require.Len(t, sections, 4)

	assert.Equal(t, "kChecksumSection", sections[0].Name)
	assert.Equal(t, "kDexFileSection", sections[1].Name)
	assert.Equal(t, "kVerifierDepsSection", sections[2].Name)
	assert.Equal(t, "kTypeLookupTableSection", sections[3].Name)

	assert.Equal(t, 0, index[model.SectionChecksum])
	assert.Equal(t, 1, index[model.SectionDex])
	assert.Equal(t, 2, index[model.SectionVerifierDeps])
	assert.Equal(t, 3, index[model.SectionTypeLookup])

	assert.Equal(t, uint32(60), sections[0].Offset)
	assert.Equal(t, uint32(8), sections[0].Size)
}

func TestParseSections_UnknownKind(t *testing.T) {
	var buf []byte
	buf = appendSectionHeader(buf, 99, 60, 4)

	sections, _, diags := ParseSections(buf, 1)
	assert.Empty(t, diags)
	require.Len(t, sections, 1)

	assert.Equal(t, "unknown(99)", sections[0].Name)
	assert.Equal(t, "unknown section kind", sections[0].Meaning)
}

func TestParseSections_DuplicateKind(t *testing.T) {
	var buf []byte
	buf = appendSectionHeader(buf, 0, 60, 4)
	buf = appendSectionHeader(buf, 0, 68, 4) // duplicate kind 0

	sections, index, diags := ParseSections(buf, 2)
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "duplicate section kind 0")
	assert.Len(t, sections, 2)
	assert.Equal(t, 0, index[0], "first occurrence should be used")
}

// --- ValidateSections tests ---

func TestValidateSections_ValidNoWarnings(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: 0, Offset: 60, Size: 8},
		{Kind: 1, Offset: 68, Size: 112},
		{Kind: 2, Offset: 180, Size: 100},
		{Kind: 3, Offset: 280, Size: 64},
	}
	diags := ValidateSections(344, sections)
	assert.Empty(t, diags)
}

func TestValidateSections_ExceedsFileSize(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: 0, Offset: 60, Size: 999},
	}
	diags := ValidateSections(100, sections)
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "exceeds file")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestValidateSections_ZeroSize(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: 1, Offset: 0, Size: 0},
	}
	diags := ValidateSections(100, sections)
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "zero size")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestValidateSections_Overlap(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: 0, Offset: 60, Size: 20},
		{Kind: 1, Offset: 70, Size: 20}, // overlaps with kind 0 (60..80 ∩ 70..90)
	}
	diags := ValidateSections(200, sections)
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "overlaps")
	assert.NotEmpty(t, diags[0].Hint)
}

func TestValidateSections_BeyondFileStart(t *testing.T) {
	sections := []model.VdexSection{
		{Kind: 0, Offset: 9999, Size: 4},
	}
	diags := ValidateSections(100, sections)
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "beyond file")
	assert.NotEmpty(t, diags[0].Hint)
}

// --- ParseVdex integration tests ---

func TestParseVdex_MinimalValidFile(t *testing.T) {
	// Build a minimal VDEX: header + 4 section headers + 1 checksum + empty dex section
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

	report, _, err := ParseVdex(tmpFile, false)
	require.NoError(t, err)

	assert.Equal(t, "vdex", report.Header.Magic)
	assert.Equal(t, "027", report.Header.Version)
	assert.Equal(t, uint32(4), report.Header.NumSections)
	require.Len(t, report.Checksums, 1)
	assert.Equal(t, uint32(0xCAFEBABE), report.Checksums[0])
	assert.Empty(t, report.Dexes)
	assert.Empty(t, report.Errors)
	assert.NotNil(t, report.Coverage)
}

func TestParseVdex_InvalidMagic(t *testing.T) {
	header := buildRawHeader("oops", "027\x00", 4)
	sectionBuf := make([]byte, 48) // 4 empty section headers
	raw := append(header, sectionBuf...)

	tmpFile := filepath.Join(t.TempDir(), "badmagic.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdex(tmpFile, false)
	require.Error(t, err)
	require.NotNil(t, report)
	assert.Contains(t, report.Errors[0], "invalid VDEX magic")
}

func TestParseVdex_VersionMismatch(t *testing.T) {
	header := buildRawHeader("vdex", "999\x00", 4)
	sectionBuf := make([]byte, 48)
	raw := append(header, sectionBuf...)

	tmpFile := filepath.Join(t.TempDir(), "badver.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, _ := ParseVdex(tmpFile, false)
	require.NotNil(t, report)
	assert.NotEmpty(t, report.Warnings)
	assert.Contains(t, report.Warnings[0], "version mismatch")
}

func TestParseVdex_FileTooSmall(t *testing.T) {
	raw := []byte("vdex027") // only 7 bytes, need 12

	tmpFile := filepath.Join(t.TempDir(), "tiny.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdex(tmpFile, false)
	require.Error(t, err)
	require.NotNil(t, report)
	assert.Contains(t, report.Errors[0], "file too small for VDEX header")
}

func TestParseVdex_TruncatedSectionTable(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4) // claims 4 sections
	// Only provide 1 section header (12 bytes) instead of 4 (48 bytes)
	raw := append(header, make([]byte, 12)...)

	tmpFile := filepath.Join(t.TempDir(), "truncated.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdex(tmpFile, false)
	require.Error(t, err)
	require.NotNil(t, report)
	assert.Contains(t, report.Errors[0], "file too small for section header table")
}

func TestParseVdex_IncludesMeanings(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	sectionBuf := make([]byte, 48)
	raw := append(header, sectionBuf...)

	tmpFile := filepath.Join(t.TempDir(), "meanings.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	withMeanings, _, _ := ParseVdex(tmpFile, true)
	assert.NotNil(t, withMeanings.Meanings)

	withoutMeanings, _, _ := ParseVdex(tmpFile, false)
	assert.Nil(t, withoutMeanings.Meanings)
}

func TestParseVdex_MultipleChecksums(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(60)
	checksumSize := uint32(12) // 3 checksums

	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+checksumSize, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+checksumSize, 0)

	raw := append(header, sectionBuf...)
	for _, v := range []uint32{0x11111111, 0x22222222, 0x33333333} {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		raw = append(raw, b...)
	}

	tmpFile := filepath.Join(t.TempDir(), "multi_chk.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdex(tmpFile, false)
	require.NoError(t, err)
	require.Len(t, report.Checksums, 3)
	assert.Equal(t, uint32(0x11111111), report.Checksums[0])
	assert.Equal(t, uint32(0x22222222), report.Checksums[1])
	assert.Equal(t, uint32(0x33333333), report.Checksums[2])
}

func TestParseVdex_ByteCoverageGaps(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	// Place checksum at offset 64 instead of 60 → 4-byte gap after section headers
	checksumOff := uint32(64)
	checksumSize := uint32(4)

	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+checksumSize, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+checksumSize, 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, 0, 0, 0, 0) // 4-byte gap padding
	chk := make([]byte, 4)
	binary.LittleEndian.PutUint32(chk, 0xDEAD)
	raw = append(raw, chk...)

	tmpFile := filepath.Join(t.TempDir(), "gap.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdex(tmpFile, false)
	require.NoError(t, err)
	require.NotNil(t, report.Coverage)

	cov := report.Coverage
	assert.Equal(t, len(raw), cov.FileSize)
	assert.Greater(t, cov.ParsedBytes, 0)

	require.NotEmpty(t, cov.Gaps)
	assert.Equal(t, 60, cov.Gaps[0].Offset, "gap should start right after section headers")
	assert.Equal(t, 4, cov.Gaps[0].Size, "gap should be 4 bytes")
	assert.Equal(t, "gap/padding", cov.Gaps[0].Label)
}

// --- Diagnostic code tests ---

func TestParseVdex_DiagnosticCodes(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		wantCode model.DiagCode
		inErrors bool // true=check Errors, false=check Warnings
	}{
		{
			name:     "file too small",
			raw:      []byte("vdex"),
			wantCode: model.ErrFileTooSmall,
			inErrors: true,
		},
		{
			name:     "invalid magic",
			raw:      append(buildRawHeader("nope", "027\x00", 4), make([]byte, 48)...),
			wantCode: model.ErrInvalidMagic,
			inErrors: true,
		},
		{
			name:     "version mismatch",
			raw:      append(buildRawHeader("vdex", "999\x00", 4), make([]byte, 48)...),
			wantCode: model.WarnVersionMismatch,
			inErrors: false,
		},
		{
			name:     "section table truncated",
			raw:      append(buildRawHeader("vdex", "027\x00", 4), make([]byte, 12)...),
			wantCode: model.ErrSectionTableTrunc,
			inErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "diag.vdex")
			require.NoError(t, os.WriteFile(tmpFile, tt.raw, 0644))

			report, _, err := ParseVdex(tmpFile, false)
			require.NotNil(t, report)

			if tt.inErrors {
				require.Error(t, err)
				diag, ok := err.(model.ParseDiagnostic)
				if ok {
					assert.Equal(t, tt.wantCode, diag.Code)
				}
			} else {
				assert.NotEmpty(t, report.Warnings)
			}
		})
	}
}

func TestParseVdex_ChecksumSectionCorrupted(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	// Checksum section offset beyond file
	sectionBuf = appendSectionHeader(sectionBuf, 0, 9999, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, 0, 0)
	raw := append(header, sectionBuf...)

	tmpFile := filepath.Join(t.TempDir(), "badchk.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, err := ParseVdex(tmpFile, false)
	require.Error(t, err)
	require.NotNil(t, report)
	assert.NotEmpty(t, report.Errors)
}

func TestParseVdex_ChecksumOddSize(t *testing.T) {
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(60)
	checksumSize := uint32(5) // not multiple of 4

	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, checksumSize)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+checksumSize, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+checksumSize, 0)

	raw := append(header, sectionBuf...)
	raw = append(raw, 0, 0, 0, 0, 0) // 5 bytes checksum data

	tmpFile := filepath.Join(t.TempDir(), "oddchk.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, _ := ParseVdex(tmpFile, false)
	require.NotNil(t, report)
	assert.Len(t, report.Checksums, 1) // 5/4 = 1
	hasAlignWarn := false
	for _, w := range report.Warnings {
		if containsStr(w, "multiple of 4") {
			hasAlignWarn = true
		}
	}
	assert.True(t, hasAlignWarn)
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstr(s, substr))
}
func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// === Scenario B: Parser → Diagnostics propagation ===
// Criteria: ParseVdex must populate report.Diagnostics with Code, Hint, and
// keep Warnings/Errors in sync via AddDiag.

func TestParseVdex_DiagnosticsPopulated_VersionMismatch(t *testing.T) {
	// GIVEN: VDEX with wrong version
	header := buildRawHeader("vdex", "999\x00", 4)
	raw := append(header, make([]byte, 48)...)
	tmpFile := filepath.Join(t.TempDir(), "diag_ver.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	// WHEN: parse
	report, _, _ := ParseVdex(tmpFile, false)

	// THEN: Diagnostics has entry with code + hint
	require.NotEmpty(t, report.Diagnostics)
	found := false
	for _, d := range report.Diagnostics {
		if d.Code == model.WarnVersionMismatch {
			found = true
			assert.Contains(t, d.Hint, "v027")
			assert.Contains(t, d.Message, "999")
		}
	}
	assert.True(t, found, "WarnVersionMismatch diagnostic must be present")

	// THEN: Warnings also populated (backward compat)
	assert.NotEmpty(t, report.Warnings)
}

func TestParseVdex_DiagnosticsPopulated_SectionZeroSize(t *testing.T) {
	// GIVEN: VDEX with empty dex section (size=0)
	header := buildRawHeader("vdex", "027\x00", 4)
	checksumOff := uint32(60)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, checksumOff, 4)
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0) // empty dex
	sectionBuf = appendSectionHeader(sectionBuf, 2, checksumOff+4, 0)
	sectionBuf = appendSectionHeader(sectionBuf, 3, checksumOff+4, 0)
	raw := append(header, sectionBuf...)
	chk := make([]byte, 4)
	binary.LittleEndian.PutUint32(chk, 0xBEEF)
	raw = append(raw, chk...)
	tmpFile := filepath.Join(t.TempDir(), "diag_zero.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	// WHEN: parse
	report, _, err := ParseVdex(tmpFile, false)
	require.NoError(t, err)

	// THEN: multiple zero-size diagnostics present with hints
	zeroCount := 0
	for _, d := range report.Diagnostics {
		if d.Code == model.WarnSectionZeroSize {
			zeroCount++
			assert.NotEmpty(t, d.Hint)
			assert.Contains(t, d.Message, "zero size")
		}
	}
	assert.GreaterOrEqual(t, zeroCount, 1, "at least one zero-size section diagnostic expected")
}

func TestParseVdex_DiagnosticsPopulated_ErrorHasHint(t *testing.T) {
	// GIVEN: file too small
	raw := []byte("vdex027")
	tmpFile := filepath.Join(t.TempDir(), "diag_small.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	// WHEN: parse
	report, _, err := ParseVdex(tmpFile, false)
	require.Error(t, err)

	// THEN: error diagnostic has hint
	require.NotEmpty(t, report.Diagnostics)
	assert.Equal(t, model.ErrFileTooSmall, report.Diagnostics[0].Code)
	assert.Contains(t, report.Diagnostics[0].Hint, "truncated")

	// THEN: Errors also populated
	require.Len(t, report.Errors, 1)
}

func TestParseVdex_DiagnosticsAndWarningsInSync(t *testing.T) {
	// GIVEN: VDEX that triggers multiple warnings
	header := buildRawHeader("vdex", "027\x00", 4)
	var sectionBuf []byte
	sectionBuf = appendSectionHeader(sectionBuf, 0, 60, 5) // odd size → alignment warning
	sectionBuf = appendSectionHeader(sectionBuf, 1, 0, 0)  // zero size
	sectionBuf = appendSectionHeader(sectionBuf, 2, 65, 0)  // zero size
	sectionBuf = appendSectionHeader(sectionBuf, 3, 65, 0)  // zero size
	raw := append(header, sectionBuf...)
	raw = append(raw, 0, 0, 0, 0, 0) // 5 bytes checksum
	tmpFile := filepath.Join(t.TempDir(), "diag_sync.vdex")
	require.NoError(t, os.WriteFile(tmpFile, raw, 0644))

	report, _, _ := ParseVdex(tmpFile, false)

	// THEN: count of warning diagnostics == count of Warnings strings
	warnDiags := 0
	for _, d := range report.Diagnostics {
		if d.Severity == model.SeverityWarning {
			warnDiags++
		}
	}
	assert.Equal(t, len(report.Warnings), warnDiags,
		"Diagnostics warning count must equal Warnings string count")

	// THEN: every diagnostic has a code
	for _, d := range report.Diagnostics {
		assert.NotEmpty(t, d.Code, "every diagnostic must have a Code")
	}
}

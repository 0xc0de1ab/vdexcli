package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === Scenario A: AddDiag pipeline ===
// Criteria: AddDiag must populate Diagnostics AND derive Warnings/Errors from severity.

func TestAddDiag_WarningPopulatesBoth(t *testing.T) {
	r := &VdexReport{}
	d := DiagVersionMismatch("027", "999")

	r.AddDiag(d)

	// Success: Diagnostics contains the full diagnostic
	require.Len(t, r.Diagnostics, 1)
	assert.Equal(t, WarnVersionMismatch, r.Diagnostics[0].Code)
	assert.NotEmpty(t, r.Diagnostics[0].Hint)

	// Success: Warnings derived from Message
	require.Len(t, r.Warnings, 1)
	assert.Equal(t, d.Message, r.Warnings[0])

	// Success: Errors NOT populated for warnings
	assert.Empty(t, r.Errors)
}

func TestAddDiag_ErrorPopulatesBoth(t *testing.T) {
	r := &VdexReport{}
	d := DiagFileTooSmall(5)

	r.AddDiag(d)

	require.Len(t, r.Diagnostics, 1)
	assert.Equal(t, ErrFileTooSmall, r.Diagnostics[0].Code)
	assert.NotEmpty(t, r.Diagnostics[0].Hint)

	// Success: Errors derived from Message
	require.Len(t, r.Errors, 1)
	assert.Equal(t, d.Message, r.Errors[0])

	// Success: Warnings NOT populated for errors
	assert.Empty(t, r.Warnings)
}

func TestAddDiags_Multiple(t *testing.T) {
	r := &VdexReport{}
	ds := []ParseDiagnostic{
		DiagSectionZeroSize(1),
		DiagSectionZeroSize(3),
		DiagChecksumExceedsFile(),
	}

	r.AddDiags(ds)

	// 3 diagnostics total
	assert.Len(t, r.Diagnostics, 3)
	// 2 warnings (zero size) + 1 error (checksum exceeds)
	assert.Len(t, r.Warnings, 2)
	assert.Len(t, r.Errors, 1)
}

func TestAddDiag_NoDuplication(t *testing.T) {
	r := &VdexReport{}
	d := DiagSectionOverlap(0, 1)

	r.AddDiag(d)
	r.AddDiag(d)

	// Each call adds one entry — no dedup (caller responsibility)
	assert.Len(t, r.Diagnostics, 2)
	assert.Len(t, r.Warnings, 2)
}

// === Scenario: Every constructor produces a non-empty Hint ===

func TestAllDiagConstructors_HaveHints(t *testing.T) {
	constructors := []ParseDiagnostic{
		// header
		DiagFileTooSmall(0),
		DiagInvalidMagic("bad"),
		DiagVersionMismatch("027", "999"),
		DiagSectionTableTruncated(60, 24),
		// checksum
		DiagChecksumExceedsFile(),
		DiagChecksumAlignment(),
		DiagNoChecksumSection(),
		// section
		DiagSectionExceedsFile(0, 60, 999),
		DiagSectionBeyondFile(0, 9999),
		DiagSectionZeroSize(1),
		DiagSectionOverlap(0, 1),
		DiagSectionDuplicate(0),
		// dex
		DiagDexTooShort(0, 10),
		DiagDexInvalidMagic(0, "bad"),
		DiagDexInvalidFileSize(0, 999, 100),
		DiagDexSectionRange(),
		DiagDexTruncated(0),
		DiagDexFileSizeClamped(0, 999, 100),
		DiagDexStringsRange(0),
		DiagDexTypeIdsRange(0),
		DiagDexClassDefsRange(0),
		// verifier
		DiagVerifierSectionRange(),
		DiagVerifierIndexTruncated(0),
		DiagVerifierBlockOutside(0, 0x100),
		DiagVerifierBlockTruncated(0),
		DiagVerifierMalformedChain(0, 5),
		DiagVerifierMalformedBounds(0, 5),
		DiagVerifierInvalidLEB128(0, 5, "destination"),
		DiagVerifierExtrasTruncated(0),
		DiagVerifierExtraInvalid(0, 0, 0x100),
		// typelookup
		DiagTypeLookupSectionRange(),
		DiagTypeLookupTruncated(0),
		DiagTypeLookupDexExceeds(0, 9999),
	}

	for _, d := range constructors {
		t.Run(string(d.Code), func(t *testing.T) {
			assert.NotEmpty(t, d.Hint, "constructor %s must have a non-empty Hint", d.Code)
			assert.NotEmpty(t, d.Message, "constructor %s must have a non-empty Message", d.Code)
			assert.NotEmpty(t, d.Code, "constructor must have a DiagCode")
			assert.NotEmpty(t, d.Category, "constructor must have a Category")
		})
	}
}

// === Scenario: ForJSON includes hint when present ===

func TestForJSON_IncludesHint(t *testing.T) {
	d := DiagFileTooSmall(5)
	m := d.ForJSON()

	assert.Equal(t, string(ErrFileTooSmall), m["code"])
	assert.Equal(t, "error", m["severity"])
	assert.Equal(t, string(CatHeader), m["category"])
	assert.NotEmpty(t, m["hint"])
}

func TestForJSON_OmitsEmptyHint(t *testing.T) {
	d := ParseDiagnostic{
		Severity: SeverityWarning,
		Category: CatDex,
		Code:     WarnDexTruncated,
		Message:  "test",
		Hint:     "",
	}
	m := d.ForJSON()
	_, hasHint := m["hint"]
	assert.False(t, hasHint, "empty hint should not appear in ForJSON output")
}

func TestError_WithHint(t *testing.T) {
	d := DiagFileTooSmall(5)
	s := d.Error()
	assert.Contains(t, s, "[ERR_FILE_TOO_SMALL]")
	assert.Contains(t, s, "hint:")
}

func TestError_WithoutHint(t *testing.T) {
	d := ParseDiagnostic{Code: WarnDexTruncated, Message: "test"}
	s := d.Error()
	assert.Contains(t, s, "[WARN_DEX_TRUNCATED]")
	assert.NotContains(t, s, "hint:")
}

func TestSeverityString(t *testing.T) {
	assert.Equal(t, "error", ParseDiagnostic{Severity: SeverityError}.SeverityString())
	assert.Equal(t, "warning", ParseDiagnostic{Severity: SeverityWarning}.SeverityString())
}

func TestUnknownSectionName(t *testing.T) {
	assert.Equal(t, "unknown(99)", UnknownSectionName(99))
}

func TestDiagSectionZeroSize_UnknownKind(t *testing.T) {
	d := DiagSectionZeroSize(99) // unknown kind
	assert.Contains(t, d.Message, "kind 99")
}

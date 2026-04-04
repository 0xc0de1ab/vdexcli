package presenter

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func sampleReport() *model.VdexReport {
	return &model.VdexReport{
		SchemaVersion: "1.0.0",
		File:          "test.vdex",
		Size:          204,
		Header:        model.VdexHeader{Magic: "vdex", Version: "027", NumSections: 4},
		Sections: []model.VdexSection{
			{Kind: 0, Offset: 60, Size: 4, Name: "kChecksumSection"},
			{Kind: 1, Offset: 64, Size: 112, Name: "kDexFileSection"},
			{Kind: 2, Offset: 176, Size: 28, Name: "kVerifierDepsSection"},
			{Kind: 3, Offset: 204, Size: 0, Name: "kTypeLookupTableSection"},
		},
		Checksums: []uint32{0xCAFEBABE},
		Coverage: &model.ByteCoverageReport{
			FileSize: 204, ParsedBytes: 204, CoveragePercent: 100.0,
			Ranges: []model.ByteCoverageRange{{Offset: 0, Size: 204, Label: "all"}},
		},
		Warnings: []string{"section kind 3 has zero size"},
	}
}

// --- ValidateFormat ---

func TestValidateFormat_Valid(t *testing.T) {
	for _, f := range []string{"", "text", "json", "jsonl", "summary", "sections", "coverage", "table"} {
		assert.NoError(t, ValidateFormat(f), f)
	}
}

func TestValidateFormat_Invalid(t *testing.T) {
	err := ValidateFormat("xml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestValidateFormat_CaseInsensitive(t *testing.T) {
	assert.NoError(t, ValidateFormat("JSON"))
	assert.NoError(t, ValidateFormat("Table"))
}

// --- WriteJSON ---

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, map[string]int{"a": 1}))
	assert.Contains(t, buf.String(), `"a": 1`)
	assert.Contains(t, buf.String(), "\n")
}

// --- WriteJSONL ---

func TestWriteJSONL(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteJSONL(&buf, map[string]int{"a": 1}))
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 1)
	var m map[string]int
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &m))
	assert.Equal(t, 1, m["a"])
}

// --- WriteSummary ---

func TestWriteSummary(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	WriteSummary(&buf, r)
	out := buf.String()
	assert.Contains(t, out, "status=warn")
	assert.Contains(t, out, "size=204")
	assert.Contains(t, out, "coverage=100.0%")
	assert.Contains(t, out, "version=027")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1)
}

func TestWriteSummary_Nil(t *testing.T) {
	var buf bytes.Buffer
	WriteSummary(&buf, nil)
	assert.Contains(t, buf.String(), "status=error")
}

func TestWriteSummary_NoWarnings(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	r.Warnings = nil
	r.Errors = nil
	WriteSummary(&buf, r)
	assert.Contains(t, buf.String(), "status=ok")
}

func TestWriteSummary_WithErrors(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	r.Errors = []string{"fatal"}
	WriteSummary(&buf, r)
	assert.Contains(t, buf.String(), "status=error")
}

// --- WriteSections ---

func TestWriteSections(t *testing.T) {
	var buf bytes.Buffer
	WriteSections(&buf, sampleReport())
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Equal(t, "kind\tname\toffset\tsize", lines[0])
	assert.Len(t, lines, 5) // header + 4 sections
	assert.Contains(t, lines[1], "kChecksumSection")
}

func TestWriteSections_Nil(t *testing.T) {
	var buf bytes.Buffer
	WriteSections(&buf, nil)
	assert.Empty(t, buf.String())
}

// --- WriteCoverage ---

func TestWriteCoverage(t *testing.T) {
	var buf bytes.Buffer
	WriteCoverage(&buf, sampleReport())
	out := buf.String()
	assert.Contains(t, out, "coverage=100.00%")
	assert.Contains(t, out, "parsed=204")
}

func TestWriteCoverage_Nil(t *testing.T) {
	var buf bytes.Buffer
	WriteCoverage(&buf, nil)
	assert.Contains(t, buf.String(), "no coverage data")
}

func TestWriteCoverage_NoCoverage(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	r.Coverage = nil
	WriteCoverage(&buf, r)
	assert.Contains(t, buf.String(), "no coverage data")
}

// --- WriteTable ---

func TestWriteTable(t *testing.T) {
	SetColor(false)
	defer SetColor(false)

	var buf bytes.Buffer
	WriteTable(&buf, sampleReport())
	out := buf.String()
	assert.Contains(t, out, "VDEX vdex  v027")
	assert.Contains(t, out, "kChecksumSection")
	assert.Contains(t, out, "KIND")
	assert.Contains(t, out, "coverage:")
}

func TestWriteTable_Nil(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, nil)
	assert.Empty(t, buf.String())
}

func TestWriteTable_WithWarnings(t *testing.T) {
	SetColor(false)
	var buf bytes.Buffer
	WriteTable(&buf, sampleReport())
	assert.Contains(t, buf.String(), "warnings: 1")
	assert.Contains(t, buf.String(), "! section kind 3 has zero size")
}

func TestWriteTable_WithErrors(t *testing.T) {
	SetColor(false)
	var buf bytes.Buffer
	r := sampleReport()
	r.Errors = []string{"fatal error"}
	WriteTable(&buf, r)
	assert.Contains(t, buf.String(), "errors: 1")
	assert.Contains(t, buf.String(), "! fatal error")
}

// --- WriteModifySummary ---

func TestWriteModifySummary(t *testing.T) {
	var buf bytes.Buffer
	s := model.ModifySummary{Status: "ok", Mode: "replace", TotalClasses: 10, ModifiedClasses: 3}
	WriteModifySummary(&buf, s)
	out := buf.String()
	assert.Contains(t, out, "status=ok")
	assert.Contains(t, out, "mode=replace")
	assert.Contains(t, out, "classes_total=10")
}

// --- WriteExtractSummary ---

func TestWriteExtractSummary(t *testing.T) {
	var buf bytes.Buffer
	s := model.ExtractSummary{File: "app.vdex", ExtractDir: "./out", Extracted: 3, Failed: 0}
	WriteExtractSummary(&buf, s)
	out := buf.String()
	assert.Contains(t, out, "status=ok")
	assert.Contains(t, out, "extracted=3")
}

func TestWriteExtractSummary_WithErrors(t *testing.T) {
	var buf bytes.Buffer
	s := model.ExtractSummary{Errors: []string{"fail"}}
	WriteExtractSummary(&buf, s)
	assert.Contains(t, buf.String(), "status=error")
}

// --- CategorizeWarning ---

func TestCategorizeWarning(t *testing.T) {
	tests := []struct{ input, want string }{
		{"invalid magic", "header"},
		{"version mismatch", "header"},
		{"section kind 3", "section"},
		{"dex[0] truncated", "dex"},
		{"verifier block", "verifier"},
		{"type-lookup overflow", "type_lookup"},
		{"type_lookup bad", "type_lookup"},
		{"extract failed", "extract"},
		{"template unknown", "extract"},
		{"random warning", "other"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, CategorizeWarning(tt.input), tt.input)
	}
}

// --- GroupWarnings ---

func TestGroupWarnings(t *testing.T) {
	warnings := []string{"invalid magic", "section kind 3", "dex[0] bad"}
	grouped := GroupWarnings(warnings)
	assert.Len(t, grouped["header"], 1)
	assert.Len(t, grouped["section"], 1)
	assert.Len(t, grouped["dex"], 1)
}

func TestGroupWarnings_Empty(t *testing.T) {
	grouped := GroupWarnings(nil)
	assert.Empty(t, grouped)
}

// --- StrictMatchingWarnings ---

func TestStrictMatchingWarnings_AllMatch(t *testing.T) {
	warnings := []string{"bad magic", "bad version"}
	matched, filterWarn := StrictMatchingWarnings(warnings, "")
	assert.Len(t, matched, 2, "empty filter matches all")
	assert.Empty(t, filterWarn)
}

func TestStrictMatchingWarnings_SubstringMatch(t *testing.T) {
	warnings := []string{"checksum mismatch", "version ok", "checksum bad"}
	matched, _ := StrictMatchingWarnings(warnings, "checksum")
	assert.Len(t, matched, 2)
}

func TestStrictMatchingWarnings_RegexMatch(t *testing.T) {
	warnings := []string{"checksum mismatch", "version bad", "section overlap"}
	matched, _ := StrictMatchingWarnings(warnings, "re:(checksum|version)")
	assert.Len(t, matched, 2)
}

func TestStrictMatchingWarnings_InvalidRegex(t *testing.T) {
	warnings := []string{"test"}
	_, filterWarn := StrictMatchingWarnings(warnings, "re:[invalid")
	assert.NotEmpty(t, filterWarn)
}

func TestStrictMatchingWarnings_NoMatch(t *testing.T) {
	warnings := []string{"test warning"}
	matched, _ := StrictMatchingWarnings(warnings, "nonexistent")
	assert.Empty(t, matched)
}

func TestStrictMatchingWarnings_EmptyInput(t *testing.T) {
	matched, filterWarn := StrictMatchingWarnings(nil, "anything")
	assert.Nil(t, matched)
	assert.Nil(t, filterWarn)
}

// --- SetColor ---

func TestSetColor(t *testing.T) {
	SetColor(true)
	assert.Equal(t, "\033[1mtest\033[0m", c(bold, "test"))
	SetColor(false)
	assert.Equal(t, "test", c(bold, "test"))
}

// --- PrintText (stdout capture) ---

func TestPrintText_NonNil(t *testing.T) {
	SetColor(false)
	old := captureStdout(func() { PrintText(sampleReport()) })
	assert.Contains(t, old, `vdex magic="vdex"`)
	assert.Contains(t, old, "checksums: 1")
	assert.Contains(t, old, "byte_coverage:")
}

func TestPrintText_Nil(t *testing.T) {
	old := captureStdout(func() { PrintText(nil) })
	assert.Empty(t, old)
}

func TestPrintGroupedWarnings_Output(t *testing.T) {
	out := captureStdout(func() {
		PrintGroupedWarnings([]string{"section kind 3 has zero size", "verifier block truncated"})
	})
	assert.Contains(t, out, "section warnings (1):")
	assert.Contains(t, out, "verifier warnings (1):")
}

func TestPrintGroupedWarnings_Empty(t *testing.T) {
	out := captureStdout(func() { PrintGroupedWarnings(nil) })
	assert.Empty(t, out)
}

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestWriteTable_WithDexAndVerifier(t *testing.T) {
	SetColor(false)
	r := sampleReport()
	r.Dexes = []model.DexReport{{
		Index: 0, Offset: 64, Size: 112, Magic: "dex\n", Version: "035",
		Endian: "little-endian", Signature: "abcdef1234567890abcdef1234567890abcdef12",
		ChecksumId: 0xCAFE, ClassDefs: 3,
	}}
	r.Verifier = &model.VerifierReport{
		Offset: 176, Size: 28,
		Dexes: []model.VerifierDexReport{{
			DexIndex: 0, VerifiedClasses: 2, UnverifiedClasses: 1,
			AssignabilityPairs: 1, ExtraStringCount: 0,
		}},
	}
	r.Coverage.Gaps = []model.ByteCoverageRange{{Offset: 175, Size: 1, Label: "gap/padding"}}

	var buf bytes.Buffer
	WriteTable(&buf, r)
	out := buf.String()
	assert.Contains(t, out, "dex\\n035")
	assert.Contains(t, out, "sha1=abcdef1234567890abcd...")
	assert.Contains(t, out, "checksum=0xcafe")
	assert.Contains(t, out, "classes=3")
	assert.Contains(t, out, "verified=2")
	assert.Contains(t, out, "unverified=1")
	assert.Contains(t, out, "gap")
	assert.Contains(t, out, "gap/padding")
}

func TestWriteTable_LowCoverage(t *testing.T) {
	SetColor(true)
	defer SetColor(false)
	r := sampleReport()
	r.Coverage.CoveragePercent = 50.0
	var buf bytes.Buffer
	WriteTable(&buf, r)
	assert.Contains(t, buf.String(), "50.0%")
}

func TestPrintTextMeanings_Output(t *testing.T) {
	out := captureStdout(func() {
		PrintTextMeanings(&model.ParserMeanings{
			VdexFile: struct {
				Magic              string "json:\"magic\""
				Version            string "json:\"version\""
				Sections           string "json:\"sections\""
				Checksums          string "json:\"checksums\""
				DexFiles           string "json:\"dex_files\""
				Verifier           string "json:\"verifier_deps\""
				TypeLookup         string "json:\"type_lookup\""
				Warnings           string "json:\"warnings\""
				WarningsByCategory string "json:\"warnings_by_category\""
				Errors             string "json:\"errors\""
				SchemaVer          string "json:\"schema_version\""
			}{Magic: "test magic"},
			SectionKind: map[string]string{"0": "kChecksum"},
		})
	})
	assert.Contains(t, out, "meanings:")
	assert.Contains(t, out, "test magic")
}

// === Scenario C: Presenter hint display ===

func TestPrintGroupedDiagnostics_ShowsHints(t *testing.T) {
	SetColor(false)
	defer SetColor(false)

	diags := []model.ParseDiagnostic{
		{Severity: model.SeverityWarning, Category: model.CatSection, Code: model.WarnSectionZeroSize,
			Message: "section kDexFileSection has zero size",
			Hint:    "this section is empty; normal for DM-format VDEX"},
		{Severity: model.SeverityWarning, Category: model.CatVerifier, Code: model.WarnVerifierBlockTruncated,
			Message: "dex 0 verifier block truncated",
			Hint:    "class offset table extends beyond section"},
	}

	out := captureStdout(func() { PrintGroupedDiagnostics(diags) })

	// Success: grouped by category
	assert.Contains(t, out, "section warnings (1):")
	assert.Contains(t, out, "verifier warnings (1):")
	// Success: messages shown
	assert.Contains(t, out, "section kDexFileSection has zero size")
	assert.Contains(t, out, "dex 0 verifier block truncated")
	// Success: hints shown
	assert.Contains(t, out, "hint:")
	assert.Contains(t, out, "normal for DM-format")
	assert.Contains(t, out, "class offset table extends beyond section")
}

func TestPrintGroupedDiagnostics_Empty(t *testing.T) {
	out := captureStdout(func() { PrintGroupedDiagnostics(nil) })
	assert.Empty(t, out)
}

func TestPrintGroupedDiagnostics_SkipsErrors(t *testing.T) {
	SetColor(false)
	defer SetColor(false)

	diags := []model.ParseDiagnostic{
		{Severity: model.SeverityError, Category: model.CatHeader, Code: model.ErrFileTooSmall,
			Message: "file too small", Hint: "re-extract"},
	}

	out := captureStdout(func() { PrintGroupedDiagnostics(diags) })
	// PrintGroupedDiagnostics only shows warnings, errors shown separately
	assert.Empty(t, out)
}

func TestPrintGroupedDiagnostics_HintlessWarning(t *testing.T) {
	SetColor(false)
	defer SetColor(false)

	diags := []model.ParseDiagnostic{
		{Severity: model.SeverityWarning, Category: model.CatDex, Code: model.WarnDexTruncated,
			Message: "dex truncated", Hint: ""},
	}

	out := captureStdout(func() { PrintGroupedDiagnostics(diags) })
	assert.Contains(t, out, "dex truncated")
	assert.NotContains(t, out, "hint:", "empty hint must not produce hint: line")
}

func TestPrintText_DiagnosticsPreferredOverWarnings(t *testing.T) {
	SetColor(false)
	defer SetColor(false)

	r := sampleReport()
	r.Diagnostics = []model.ParseDiagnostic{
		{Severity: model.SeverityWarning, Category: model.CatSection, Code: model.WarnSectionZeroSize,
			Message: "section kTypeLookupTableSection has zero size",
			Hint:    "normal for DM-format VDEX"},
	}
	// Warnings also present (legacy)
	r.Warnings = []string{"section kTypeLookupTableSection has zero size"}

	out := captureStdout(func() { PrintText(r) })
	// When Diagnostics present, hint should appear
	assert.Contains(t, out, "hint:")
	assert.Contains(t, out, "normal for DM-format")
}

func TestPrintText_ErrorDiagnosticsShowHints(t *testing.T) {
	SetColor(false)
	defer SetColor(false)

	r := &model.VdexReport{
		File:   "bad.vdex",
		Size:   5,
		Header: model.VdexHeader{Magic: "vdex", Version: "027"},
		Diagnostics: []model.ParseDiagnostic{
			{Severity: model.SeverityError, Category: model.CatHeader, Code: model.ErrFileTooSmall,
				Message: "file too small for VDEX header: 5 bytes",
				Hint:    "verify the file is a complete VDEX"},
		},
		Errors: []string{"file too small for VDEX header: 5 bytes"},
	}

	out := captureStdout(func() { PrintText(r) })
	assert.Contains(t, out, "errors:")
	assert.Contains(t, out, "file too small")
	assert.Contains(t, out, "hint:")
	assert.Contains(t, out, "verify the file is a complete VDEX")
}

// === Scenario C2: JSON output includes diagnostics with hints ===

func TestWriteJSON_IncludesDiagnostics(t *testing.T) {
	r := &model.VdexReport{
		File:   "test.vdex",
		Size:   100,
		Header: model.VdexHeader{Magic: "vdex", Version: "027", NumSections: 4},
		Diagnostics: []model.ParseDiagnostic{
			model.DiagVersionMismatch("027", "999"),
			model.DiagSectionZeroSize(1),
		},
		Warnings: []string{"version mismatch", "zero size"},
	}

	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, r))
	out := buf.String()

	// Success: diagnostics array present in JSON with lowercase keys
	assert.Contains(t, out, `"diagnostics"`)
	assert.Contains(t, out, `"code"`)
	assert.Contains(t, out, `"WARN_VERSION_MISMATCH"`)
	assert.Contains(t, out, `"WARN_SECTION_ZERO_SIZE"`)

	// Verify it's valid JSON
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	diags, ok := parsed["diagnostics"].([]any)
	require.True(t, ok, "diagnostics must be an array")
	require.Len(t, diags, 2)

	// First diagnostic has hint, code, category (all lowercase json keys)
	first := diags[0].(map[string]any)
	assert.NotEmpty(t, first["hint"], "diagnostic must include hint in JSON")
	assert.NotEmpty(t, first["code"], "diagnostic must include code in JSON")
	assert.NotEmpty(t, first["category"], "diagnostic must include category in JSON")
}

func TestWriteJSON_NoDiagnosticsWhenEmpty(t *testing.T) {
	r := &model.VdexReport{
		File:   "test.vdex",
		Size:   100,
		Header: model.VdexHeader{Magic: "vdex", Version: "027", NumSections: 4},
	}

	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, r))

	// diagnostics field omitted (omitempty)
	assert.NotContains(t, buf.String(), `"diagnostics"`)
}

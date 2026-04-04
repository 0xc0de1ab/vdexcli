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

// === WriteDiffText tests (was 0% coverage) ===

func TestWriteDiffText_Identical(t *testing.T) {
	SetColor(false)
	defer SetColor(false)
	d := model.VdexDiff{
		FileA: "a.vdex", FileB: "b.vdex", SizeA: 100, SizeB: 100,
		Summary: model.DiffSummary{Identical: true},
	}
	var buf bytes.Buffer
	WriteDiffText(&buf, d)
	assert.Contains(t, buf.String(), "identical")
	assert.Contains(t, buf.String(), "a.vdex")
	assert.Contains(t, buf.String(), "b.vdex")
}

func TestWriteDiffText_AllSectionsChanged(t *testing.T) {
	SetColor(false)
	defer SetColor(false)
	d := model.VdexDiff{
		FileA: "a.vdex", FileB: "b.vdex", SizeA: 100, SizeB: 200,
		HeaderChanged: true,
		HeaderDiff:    &model.HeaderDiff{MagicA: "vdex", MagicB: "vdex", VersionA: "027", VersionB: "028"},
		SectionDiffs:  []model.SectionDiff{{Name: "kVerifierDepsSection", SizeA: 28, SizeB: 100, SizeDelta: 72}},
		ChecksumDiff:  &model.ChecksumDiff{CountA: 1, CountB: 2, Changed: []int{0}, AddedB: 1},
		DexDiffs: []model.DexFileDiff{
			{Index: 0, Status: "modified", ChecksumA: 0xAA, ChecksumB: 0xBB, ClassDefsA: 3, ClassDefsB: 5},
			{Index: 1, Status: "added", ChecksumB: 0xCC, ClassDefsB: 2},
			{Index: 2, Status: "removed", ChecksumA: 0xDD, ClassDefsA: 1},
		},
		VerifierDiff: &model.VerifierDiffInfo{
			TotalChanged: 5,
			DexDiffs: []model.VerifierDexDiff{
				{DexIndex: 0, VerifiedA: 10, VerifiedB: 15, VerifiedDelta: 5, PairsA: 20, PairsB: 25, PairsDelta: 5, ExtraStringsA: 1, ExtraStringsB: 2},
			},
		},
		TypeLookupDiff: &model.TypeLookupDiffInfo{
			DexDiffs: []model.TypeLookupDexDiff{
				{DexIndex: 0, BucketsA: 8, BucketsB: 16, EntriesA: 6, EntriesB: 10, EntriesDelta: 4},
			},
		},
		Summary: model.DiffSummary{
			SectionsChanged: 1, ChecksumsChanged: 1, DexFilesChanged: 3,
			VerifierChanged: 5, TypeLookupChanged: 4,
		},
	}
	var buf bytes.Buffer
	WriteDiffText(&buf, d)
	out := buf.String()

	assert.Contains(t, out, "VDEX diff")
	assert.Contains(t, out, "+100 bytes")
	// header
	assert.Contains(t, out, "header:")
	assert.Contains(t, out, "027")
	assert.Contains(t, out, "028")
	// sections
	assert.Contains(t, out, "kVerifierDepsSection")
	assert.Contains(t, out, "+72")
	// checksums
	assert.Contains(t, out, "checksums:")
	assert.Contains(t, out, "+1")
	// dex files
	assert.Contains(t, out, "modified")
	assert.Contains(t, out, "added")
	assert.Contains(t, out, "removed")
	// verifier
	assert.Contains(t, out, "verifier_deps:")
	assert.Contains(t, out, "5 classes changed")
	// type lookup
	assert.Contains(t, out, "type_lookup:")
	// summary
	assert.Contains(t, out, "summary:")
}

func TestWriteDiffText_NegativeDelta(t *testing.T) {
	SetColor(false)
	defer SetColor(false)
	d := model.VdexDiff{
		FileA: "a.vdex", FileB: "b.vdex", SizeA: 200, SizeB: 200,
		VerifierDiff: &model.VerifierDiffInfo{
			TotalChanged: 1,
			DexDiffs: []model.VerifierDexDiff{
				{DexIndex: 0, VerifiedA: 10, VerifiedB: 5, VerifiedDelta: -5, PairsA: 20, PairsB: 15, PairsDelta: -5},
			},
		},
		Summary: model.DiffSummary{VerifierChanged: 1},
	}
	var buf bytes.Buffer
	WriteDiffText(&buf, d)
	assert.Contains(t, buf.String(), "-5")
}

func TestWriteDiffText_ZeroDelta(t *testing.T) {
	SetColor(false)
	defer SetColor(false)
	d := model.VdexDiff{
		FileA: "a.vdex", FileB: "b.vdex", SizeA: 100, SizeB: 100,
		TypeLookupDiff: &model.TypeLookupDiffInfo{
			DexDiffs: []model.TypeLookupDexDiff{
				{DexIndex: 0, BucketsA: 8, BucketsB: 8, EntriesA: 6, EntriesB: 6, EntriesDelta: 0},
			},
		},
		Summary: model.DiffSummary{TypeLookupChanged: 0},
	}
	var buf bytes.Buffer
	WriteDiffText(&buf, d)
	assert.Contains(t, buf.String(), "+0")
}

func TestWriteDiffText_ChecksumRemoved(t *testing.T) {
	SetColor(false)
	defer SetColor(false)
	d := model.VdexDiff{
		FileA: "a.vdex", FileB: "b.vdex", SizeA: 100, SizeB: 100,
		ChecksumDiff: &model.ChecksumDiff{CountA: 3, CountB: 1, RemovedA: 2},
		Summary:      model.DiffSummary{ChecksumsChanged: 2},
	}
	var buf bytes.Buffer
	WriteDiffText(&buf, d)
	assert.Contains(t, buf.String(), "-2")
}

// === PrintText full path coverage ===

func TestPrintText_FullReport(t *testing.T) {
	SetColor(false)
	defer SetColor(false)

	r := sampleReport()
	r.Dexes = []model.DexReport{{
		Index: 0, Offset: 64, Size: 112, Magic: "dex\n", Version: "035",
		Endian: "little-endian", Signature: "abc", ChecksumId: 0xCAFE,
		ClassDefs: 3, StringIds: 10, TypeIds: 5, ProtoIds: 3,
		FieldIds: 2, MethodIds: 4,
		Classes: []string{"Lcom/Foo;", "Lcom/Bar;"},
	}}
	r.Verifier = &model.VerifierReport{Offset: 176, Size: 28, Dexes: []model.VerifierDexReport{
		{DexIndex: 0, VerifiedClasses: 2, UnverifiedClasses: 1, AssignabilityPairs: 3, ExtraStringCount: 1,
			FirstPairs: []model.VerifierPair{{ClassDefIndex: 0, Dest: "Ljava/lang/Object;", DestID: 1, Src: "Lcom/Foo;", SrcID: 2}}},
	}}
	r.TypeLookup = &model.TypeLookupReport{Offset: 204, Size: 32, Dexes: []model.TypeLookupDexReport{
		{DexIndex: 0, RawSize: 32, BucketCount: 4, EntryCount: 2, NonEmptyBuckets: 2, MaxChainLen: 1, AvgChainLen: 1.0,
			Samples:  []model.TypeLookupSample{{Bucket: 0, ClassDef: 0, Descriptor: "Lcom/Foo;", NextDelta: 0, HashBits: 3}},
			Warnings: []string{"cycle detected"}},
	}}
	r.Coverage.Gaps = []model.ByteCoverageRange{{Offset: 60, Size: 4, Label: "gap/padding"}}

	out := captureStdout(func() { PrintText(r) })

	// dex section
	assert.Contains(t, out, `magic="dex\n"`)
	assert.Contains(t, out, "Lcom/Foo;")
	assert.Contains(t, out, "...")
	// verifier section
	assert.Contains(t, out, "verifier_deps:")
	assert.Contains(t, out, "Ljava/lang/Object;")
	// type lookup section
	assert.Contains(t, out, "type_lookup:")
	assert.Contains(t, out, "cycle detected")
	// coverage gaps
	assert.Contains(t, out, "gaps:")
	assert.Contains(t, out, "gap/padding")
}

// === WriteCoverage gaps path ===

func TestWriteCoverage_WithGaps(t *testing.T) {
	r := &model.VdexReport{
		File: "test.vdex",
		Coverage: &model.ByteCoverageReport{
			FileSize: 100, ParsedBytes: 96, UnparsedBytes: 4, CoveragePercent: 96.0,
			Ranges: []model.ByteCoverageRange{{Offset: 0, Size: 96, Label: "data"}},
			Gaps:   []model.ByteCoverageRange{{Offset: 96, Size: 4, Label: "gap/padding"}},
		},
	}
	var buf bytes.Buffer
	WriteCoverage(&buf, r)
	out := buf.String()
	assert.Contains(t, out, "96.00%")
	assert.Contains(t, out, "gaps:")
	assert.Contains(t, out, "gap/padding")
}

func TestWriteCoverage_NilReport(t *testing.T) {
	var buf bytes.Buffer
	WriteCoverage(&buf, nil)
	assert.Contains(t, buf.String(), "no coverage data")
}

func TestWriteCoverage_NilCoverage(t *testing.T) {
	var buf bytes.Buffer
	WriteCoverage(&buf, &model.VdexReport{File: "test.vdex"})
	assert.Contains(t, buf.String(), "no coverage data")
}

// === Interface default impl coverage ===

func TestDefaultDiffWriter(t *testing.T) {
	SetColor(false)
	defer SetColor(false)
	w := DefaultDiffWriter{}
	var buf bytes.Buffer
	d := model.VdexDiff{
		FileA: "a.vdex", FileB: "b.vdex", SizeA: 100, SizeB: 100,
		Summary: model.DiffSummary{Identical: true},
	}
	w.WriteDiff(&buf, d)
	assert.Contains(t, buf.String(), "identical")
}

func TestTextWriter(t *testing.T) {
	SetColor(false)
	defer SetColor(false)
	w := TextWriter{}
	old := captureStdout(func() {
		_ = w.Write(nil, sampleReport())
	})
	assert.Contains(t, old, "vdex")
}

func TestSummaryLineWriter(t *testing.T) {
	w := SummaryLineWriter{}
	var buf bytes.Buffer
	_ = w.Write(&buf, sampleReport())
	assert.Contains(t, buf.String(), "status=")
}

func TestSectionsWriter(t *testing.T) {
	w := SectionsWriter{}
	var buf bytes.Buffer
	_ = w.Write(&buf, sampleReport())
	assert.Contains(t, buf.String(), "kChecksumSection")
}

func TestCoverageWriter(t *testing.T) {
	w := CoverageWriter{}
	var buf bytes.Buffer
	_ = w.Write(&buf, sampleReport())
	assert.Contains(t, buf.String(), "100.00%")
}

func TestDefaultWarningProcessor(t *testing.T) {
	p := DefaultWarningProcessor{}
	g := p.Group([]string{"section bad", "verifier bad"})
	assert.Len(t, g, 2)
	m, _ := p.StrictMatch([]string{"a", "b"}, "a")
	assert.Len(t, m, 1)
}

func TestDefaultSummaryWriter(t *testing.T) {
	w := DefaultSummaryWriter{}
	var buf bytes.Buffer
	w.WriteModify(&buf, model.ModifySummary{Status: "ok"})
	assert.Contains(t, buf.String(), "status=ok")
	buf.Reset()
	w.WriteExtract(&buf, model.ExtractSummary{File: "test.vdex", Extracted: 1})
	assert.Contains(t, buf.String(), "extracted=1")
}

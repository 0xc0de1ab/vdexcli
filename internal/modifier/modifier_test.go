package modifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// --- ParseVerifierPatch ---

func TestParseVerifierPatch_ValidFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "patch.json")
	data := `{"mode":"replace","dexes":[{"dex_index":0,"classes":[{"class_index":0,"verified":false}]}]}`
	require.NoError(t, os.WriteFile(tmp, []byte(data), 0644))

	spec, warnings, err := ParseVerifierPatch(tmp)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, "replace", spec.Mode)
	require.Len(t, spec.Dexes, 1)
	assert.Equal(t, 0, spec.Dexes[0].DexIndex)
}

func TestParseVerifierPatch_Stdin(t *testing.T) {
	// "-" means stdin; we can't easily test stdin, so test file with "-" prefix path fails gracefully
	_, _, err := ParseVerifierPatch("/nonexistent/path.json")
	assert.Error(t, err)
}

func TestParseVerifierPatch_EmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.json")
	require.NoError(t, os.WriteFile(tmp, []byte(""), 0644))

	_, _, err := ParseVerifierPatch(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestParseVerifierPatch_InvalidJSON(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(tmp, []byte("{not json}"), 0644))

	_, _, err := ParseVerifierPatch(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid verifier patch json")
}

func TestParseVerifierPatch_UnsupportedMode(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "patch.json")
	require.NoError(t, os.WriteFile(tmp, []byte(`{"mode":"bogus"}`), 0644))

	_, _, err := ParseVerifierPatch(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported patch mode")
}

func TestParseVerifierPatch_MergeMode(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "patch.json")
	require.NoError(t, os.WriteFile(tmp, []byte(`{"mode":"merge","dexes":[]}`), 0644))

	spec, _, err := ParseVerifierPatch(tmp)
	require.NoError(t, err)
	assert.Equal(t, "merge", spec.Mode)
}

func TestParseVerifierPatch_EmptyMode(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "patch.json")
	require.NoError(t, os.WriteFile(tmp, []byte(`{"dexes":[]}`), 0644))

	spec, _, err := ParseVerifierPatch(tmp)
	require.NoError(t, err)
	assert.Equal(t, "", spec.Mode)
}

// --- ValidateVerifierPatchIndices ---

func TestValidateVerifierPatchIndices_Valid(t *testing.T) {
	patch := model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{
			{DexIndex: 0, Classes: []model.VerifierPatchClass{{ClassIndex: 0}, {ClassIndex: 1}}},
			{DexIndex: 1},
		},
	}
	assert.NoError(t, ValidateVerifierPatchIndices(patch))
}

func TestValidateVerifierPatchIndices_DuplicateDex(t *testing.T) {
	patch := model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{DexIndex: 0}, {DexIndex: 0}},
	}
	err := ValidateVerifierPatchIndices(patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate patch dex_index")
}

func TestValidateVerifierPatchIndices_NegativeDex(t *testing.T) {
	patch := model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{DexIndex: -1}},
	}
	err := ValidateVerifierPatchIndices(patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid dex_index")
}

func TestValidateVerifierPatchIndices_DuplicateClass(t *testing.T) {
	patch := model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{
			DexIndex: 0,
			Classes:  []model.VerifierPatchClass{{ClassIndex: 5}, {ClassIndex: 5}},
		}},
	}
	err := ValidateVerifierPatchIndices(patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate class_index")
}

// --- BuildVerifierSectionReplacement ---

func TestBuildVerifierSectionReplacement_AllUnverified(t *testing.T) {
	falseVal := false
	dexes := []model.DexReport{{ClassDefs: 3}}
	checksums := []uint32{0xCAFE}
	patch := model.VerifierPatchSpec{
		Mode: "replace",
		Dexes: []model.VerifierPatchDex{{
			DexIndex: 0,
			Classes: []model.VerifierPatchClass{
				{ClassIndex: 0, Verified: &falseVal},
				{ClassIndex: 1, Verified: &falseVal},
				{ClassIndex: 2, Verified: &falseVal},
			},
		}},
	}

	payload, _, err := BuildVerifierSectionReplacement(dexes, checksums, patch)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
}

func TestBuildVerifierSectionReplacement_NoDex(t *testing.T) {
	patch := model.VerifierPatchSpec{Mode: "replace"}
	_, _, err := BuildVerifierSectionReplacement(nil, nil, patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot infer dex count")
}

func TestBuildVerifierSectionReplacement_DexIndexExceedsCount(t *testing.T) {
	dexes := []model.DexReport{{ClassDefs: 1}}
	checksums := []uint32{0x1}
	patch := model.VerifierPatchSpec{
		Mode:  "replace",
		Dexes: []model.VerifierPatchDex{{DexIndex: 99}},
	}
	_, _, err := BuildVerifierSectionReplacement(dexes, checksums, patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds dex count")
}

// --- VerifierSectionClassEqual ---

func TestVerifierSectionClassEqual_Same(t *testing.T) {
	a := model.VerifierSectionClass{Verified: true, Pairs: []model.VerifierPatchPair{{Dest: 5, Src: 10}}}
	assert.True(t, VerifierSectionClassEqual(a, a))
}

func TestVerifierSectionClassEqual_DifferentVerified(t *testing.T) {
	a := model.VerifierSectionClass{Verified: true}
	b := model.VerifierSectionClass{Verified: false}
	assert.False(t, VerifierSectionClassEqual(a, b))
}

func TestVerifierSectionClassEqual_DifferentPairs(t *testing.T) {
	a := model.VerifierSectionClass{Verified: true, Pairs: []model.VerifierPatchPair{{Dest: 5, Src: 10}}}
	b := model.VerifierSectionClass{Verified: true, Pairs: []model.VerifierPatchPair{{Dest: 5, Src: 99}}}
	assert.False(t, VerifierSectionClassEqual(a, b))
}

func TestVerifierSectionClassEqual_DifferentPairCount(t *testing.T) {
	a := model.VerifierSectionClass{Verified: true, Pairs: []model.VerifierPatchPair{{Dest: 1, Src: 2}}}
	b := model.VerifierSectionClass{Verified: true}
	assert.False(t, VerifierSectionClassEqual(a, b))
}

// --- MakeFailureReason / MakeFailureCategory ---

func TestMakeFailureReason_StrictFailed(t *testing.T) {
	s := model.ModifySummary{Status: "strict_failed"}
	reason := MakeFailureReason(s, nil, nil, nil, []string{"warn1"})
	assert.Contains(t, reason, "strict mode")
}

func TestMakeFailureReason_ParseError(t *testing.T) {
	s := model.ModifySummary{Status: "failed"}
	reason := MakeFailureReason(s, assert.AnError, nil, nil, nil)
	assert.Contains(t, reason, assert.AnError.Error())
}

func TestMakeFailureReason_OK(t *testing.T) {
	s := model.ModifySummary{Status: "ok"}
	reason := MakeFailureReason(s, nil, nil, nil, nil)
	assert.Empty(t, reason)
}

func TestMakeFailureCategory_Strict(t *testing.T) {
	s := model.ModifySummary{Status: "strict_failed"}
	cat := MakeFailureCategory(s, nil, nil, nil, []string{"w"})
	assert.Equal(t, "strict", cat)
}

func TestMakeFailureCategory_Parse(t *testing.T) {
	s := model.ModifySummary{Status: "failed"}
	cat := MakeFailureCategory(s, assert.AnError, nil, nil, nil)
	assert.Equal(t, "parse", cat)
}

func TestMakeFailureCategory_Compare(t *testing.T) {
	s := model.ModifySummary{Status: "failed"}
	cat := MakeFailureCategory(s, nil, assert.AnError, nil, nil)
	assert.Equal(t, "compare", cat)
}

func TestMakeFailureCategory_Write(t *testing.T) {
	s := model.ModifySummary{Status: "failed"}
	cat := MakeFailureCategory(s, nil, nil, assert.AnError, nil)
	assert.Equal(t, "write", cat)
}

func TestMakeFailureCategory_OK(t *testing.T) {
	s := model.ModifySummary{Status: "ok"}
	cat := MakeFailureCategory(s, nil, nil, nil, nil)
	assert.Empty(t, cat)
}

// --- WriteOutputFileAtomic ---

func TestWriteOutputFileAtomic_WritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.bin")
	data := []byte("hello vdex")
	require.NoError(t, WriteOutputFileAtomic(path, data))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestWriteOutputFileAtomic_BadDir(t *testing.T) {
	err := WriteOutputFileAtomic("/nonexistent/dir/file.bin", []byte("data"))
	assert.Error(t, err)
}

// --- AppendModifyLog ---

func TestAppendModifyLog_WritesNDJSON(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "modify.log")
	summary := model.ModifySummary{Status: "ok", Mode: "replace"}
	args := map[string]string{"mode": "replace"}

	require.NoError(t, AppendModifyLog(logPath, summary, args, nil, "", ""))
	require.NoError(t, AppendModifyLog(logPath, summary, args, nil, "", ""))

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	assert.Equal(t, 2, lines, "should have 2 NDJSON lines")

	var entry model.ModifyLogEntry
	require.NoError(t, json.Unmarshal(data[:len(data)/2], &entry))
	assert.Equal(t, "ok", entry.Summary.Status)
	assert.NotEmpty(t, entry.Timestamp)
}

// --- BuildVerifierDexBlock ---

func TestBuildVerifierDexBlock_AllUnverified(t *testing.T) {
	block, warnings, err := BuildVerifierDexBlock(3, 0, []bool{false, false, false}, make([][]model.VerifierPatchPair, 3), nil, 0)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.NotEmpty(t, block)
}

func TestBuildVerifierDexBlock_InvalidClassCount(t *testing.T) {
	_, _, err := BuildVerifierDexBlock(-1, 0, nil, nil, nil, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid classCount")
}

func TestBuildVerifierDexBlock_ShortVerifiedArray(t *testing.T) {
	_, _, err := BuildVerifierDexBlock(3, 0, []bool{true}, make([][]model.VerifierPatchPair, 3), nil, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "class verified array shorter")
}

// --- Default interface impls ---

func TestDefaultFailureClassifier(t *testing.T) {
	fc := DefaultFailureClassifier{}
	s := model.ModifySummary{Status: "ok"}
	reason := fc.Reason(s, nil, nil, nil, nil)
	assert.Empty(t, reason)
	cat := fc.Category(s, nil, nil, nil, nil)
	assert.Empty(t, cat)
}

func TestDefaultFailureClassifier_WithError(t *testing.T) {
	fc := DefaultFailureClassifier{}
	s := model.ModifySummary{Status: "failed"}
	reason := fc.Reason(s, fmt.Errorf("parse fail"), nil, nil, nil)
	assert.NotEmpty(t, reason)
	cat := fc.Category(s, fmt.Errorf("parse fail"), nil, nil, nil)
	assert.NotEmpty(t, cat)
}

func TestDefaultPatchLoader_Validate(t *testing.T) {
	pl := DefaultPatchLoader{}
	// Valid patch
	err := pl.Validate(model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{DexIndex: 0, Classes: []model.VerifierPatchClass{{ClassIndex: 0}}}},
	})
	assert.NoError(t, err)
}

func TestDefaultOutputWriter_WriteAtomic(t *testing.T) {
	ow := DefaultOutputWriter{}
	path := filepath.Join(t.TempDir(), "test.bin")
	err := ow.WriteAtomic(path, []byte("hello"))
	require.NoError(t, err)
	data, _ := os.ReadFile(path)
	assert.Equal(t, "hello", string(data))
}

func TestDefaultOutputWriter_AppendLog(t *testing.T) {
	ow := DefaultOutputWriter{}
	path := filepath.Join(t.TempDir(), "log.jsonl")
	err := ow.AppendLog(path, model.ModifySummary{Status: "ok"}, nil, nil, "", "")
	require.NoError(t, err)
	data, _ := os.ReadFile(path)
	assert.Contains(t, string(data), "ok")
}

func TestMakeFailureReason_StrictMatched(t *testing.T) {
	s := model.ModifySummary{Status: "strict_failed"}
	reason := MakeFailureReason(s, nil, nil, nil, []string{"warn1"})
	assert.Contains(t, reason, "strict")
	cat := MakeFailureCategory(s, nil, nil, nil, []string{"warn1"})
	assert.Equal(t, "strict", cat)
}

func TestMakeFailureReason_CompareError(t *testing.T) {
	s := model.ModifySummary{Status: "failed"}
	reason := MakeFailureReason(s, nil, fmt.Errorf("compare fail"), nil, nil)
	assert.Contains(t, reason, "compare fail")
	cat := MakeFailureCategory(s, nil, fmt.Errorf("compare fail"), nil, nil)
	assert.Equal(t, "compare", cat)
}

func TestMakeFailureReason_WriteError(t *testing.T) {
	s := model.ModifySummary{Status: "failed"}
	reason := MakeFailureReason(s, nil, nil, fmt.Errorf("write fail"), nil)
	assert.Contains(t, reason, "write fail")
	cat := MakeFailureCategory(s, nil, nil, fmt.Errorf("write fail"), nil)
	assert.Equal(t, "write", cat)
}

func TestMakeFailureReason_StatusFailed_NoErrors(t *testing.T) {
	s := model.ModifySummary{Status: "failed"}
	reason := MakeFailureReason(s, nil, nil, nil, nil)
	assert.Equal(t, "modify failed", reason)
	cat := MakeFailureCategory(s, nil, nil, nil, nil)
	assert.Equal(t, "modify", cat)
}

func TestMakeFailureReason_StatusFailed_WithSummaryError(t *testing.T) {
	s := model.ModifySummary{Status: "failed", Errors: []string{"section too large"}}
	reason := MakeFailureReason(s, nil, nil, nil, nil)
	assert.Equal(t, "section too large", reason)
}

// --- ParseVerifierPatch edge cases ---

func TestParseVerifierPatch_EmptyInput(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.json")
	require.NoError(t, os.WriteFile(tmp, []byte("   "), 0644))
	_, _, err := ParseVerifierPatch(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestParseVerifierPatch_ExtraJSON(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "extra.json")
	data := `{"dexes":[]} {"extra":true}`
	require.NoError(t, os.WriteFile(tmp, []byte(data), 0644))
	_, _, err := ParseVerifierPatch(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extra json")
}

func TestParseVerifierPatch_BadMode(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "badmode.json")
	data := `{"mode":"delete","dexes":[]}`
	require.NoError(t, os.WriteFile(tmp, []byte(data), 0644))
	_, _, err := ParseVerifierPatch(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported patch mode")
}

func TestParseVerifierPatch_UnknownField(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "unknown.json")
	data := `{"dexes":[], "bogus_field": 123}`
	require.NoError(t, os.WriteFile(tmp, []byte(data), 0644))
	_, _, err := ParseVerifierPatch(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid verifier patch json")
}

func TestParseVerifierPatch_FileNotFound(t *testing.T) {
	_, _, err := ParseVerifierPatch("/nonexistent/path/patch.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read verifier patch")
}

// --- ValidateVerifierPatchIndices edge cases ---

func TestValidateVerifierPatchIndices_NegativeDexIndex(t *testing.T) {
	err := ValidateVerifierPatchIndices(model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{DexIndex: -1}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid dex_index")
}

func TestValidateVerifierPatchIndices_DuplicateDexIndex(t *testing.T) {
	err := ValidateVerifierPatchIndices(model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{DexIndex: 0}, {DexIndex: 0}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate patch dex_index")
}

func TestValidateVerifierPatchIndices_NegativeClassIndex(t *testing.T) {
	err := ValidateVerifierPatchIndices(model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{DexIndex: 0, Classes: []model.VerifierPatchClass{{ClassIndex: -1}}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid class_index")
}

func TestValidateVerifierPatchIndices_DuplicateClassIndex(t *testing.T) {
	err := ValidateVerifierPatchIndices(model.VerifierPatchSpec{
		Dexes: []model.VerifierPatchDex{{DexIndex: 0, Classes: []model.VerifierPatchClass{
			{ClassIndex: 0}, {ClassIndex: 0},
		}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate class_index")
}

// --- BuildVerifierSectionReplacement edge cases ---

func TestBuildReplacement_NoDexOrChecksum(t *testing.T) {
	_, _, err := BuildVerifierSectionReplacement(nil, nil, model.VerifierPatchSpec{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot infer dex count")
}

func TestBuildReplacement_PatchDexExceedsCount(t *testing.T) {
	_, _, err := BuildVerifierSectionReplacement(
		[]model.DexReport{{ClassDefs: 3}},
		[]uint32{0xCAFE},
		model.VerifierPatchSpec{Dexes: []model.VerifierPatchDex{{DexIndex: 5}}},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds dex count")
}

func TestBuildReplacement_DuplicatePatchDex(t *testing.T) {
	_, _, err := BuildVerifierSectionReplacement(
		[]model.DexReport{{ClassDefs: 3}},
		[]uint32{0xCAFE},
		model.VerifierPatchSpec{Dexes: []model.VerifierPatchDex{{DexIndex: 0}, {DexIndex: 0}}},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestBuildReplacement_ChecksumOnlyNoDex(t *testing.T) {
	// No dex reports but has checksums → infers dex count from checksums
	payload, _, err := BuildVerifierSectionReplacement(
		nil,
		[]uint32{0xCAFE},
		model.VerifierPatchSpec{},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
}

// --- DefaultBuilder.BuildMerge ---

func TestDefaultBuilder_BuildMerge_NoDex(t *testing.T) {
	b := DefaultBuilder{}
	_, _, err := b.BuildMerge(nil, nil, model.VdexSection{}, nil, model.VerifierPatchSpec{})
	require.Error(t, err)
}

// --- WriteOutputFileAtomic edge cases ---

func TestWriteOutputFileAtomic_InvalidDir(t *testing.T) {
	err := WriteOutputFileAtomic("/nonexistent/dir/output.vdex", []byte("data"))
	require.Error(t, err)
}

// --- AppendModifyLog edge cases ---

func TestAppendModifyLog_InvalidPath(t *testing.T) {
	err := AppendModifyLog("/nonexistent/dir/log.jsonl", model.ModifySummary{}, nil, nil, "", "")
	require.Error(t, err)
}

func TestAppendModifyLog_WithDiffs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	s := model.ModifySummary{
		Status:          "ok",
		ModifiedClasses: 2,
		DexDiffs: []model.ModifyDexDiff{
			{DexIndex: 0, ModifiedClasses: 2, ChangedClassIdxs: []int{0, 1}},
			{DexIndex: 1, ModifiedClasses: 0},
		},
	}
	err := AppendModifyLog(path, s, map[string]string{"mode": "replace"}, []string{"warn1"}, "", "")
	require.NoError(t, err)

	data, _ := os.ReadFile(path)
	var entry model.ModifyLogEntry
	require.NoError(t, json.Unmarshal(data, &entry))
	assert.Equal(t, []int{0}, entry.ModifiedDexes)
	assert.Equal(t, 2, entry.ModifiedClassCount)
	assert.NotEmpty(t, entry.TopSamples)
}


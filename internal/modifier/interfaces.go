package modifier

import "github.com/0xc0de1ab/vdexcli/internal/model"

// VerifierBuilder constructs verifier-deps section payloads.
type VerifierBuilder interface {
	BuildReplacement(dexes []model.DexReport, checksums []uint32, patch model.VerifierPatchSpec) ([]byte, []string, error)
	BuildMerge(dexes []model.DexReport, checksums []uint32, section model.VdexSection, raw []byte, patch model.VerifierPatchSpec) ([]byte, []string, error)
}

// VerifierComparator compares original and patched verifier sections.
type VerifierComparator interface {
	Compare(raw []byte, section model.VdexSection, dexes []model.DexReport, checksums []uint32, patchedPayload []byte) (model.VerifierSectionDiff, []model.ModifyDexDiff, []string, error)
}

// PatchLoader parses and validates a verifier patch from a file path or stdin.
type PatchLoader interface {
	Load(path string) (model.VerifierPatchSpec, []string, error)
	Validate(patch model.VerifierPatchSpec) error
}

// FailureClassifier determines failure reason and category from modify results.
type FailureClassifier interface {
	Reason(summary model.ModifySummary, parseErr, compareErr, writeErr error, strictMatched []string) string
	Category(summary model.ModifySummary, parseErr, compareErr, writeErr error, strictMatched []string) string
}

// OutputWriter handles atomic file writes and log appending.
type OutputWriter interface {
	WriteAtomic(path string, data []byte) error
	AppendLog(path string, summary model.ModifySummary, cliArgs map[string]string, strictMatched []string, failureReason string, failureCategory string) error
}

// --- Default implementations wrapping the package-level functions ---

// DefaultBuilder is the standard VerifierBuilder implementation.
type DefaultBuilder struct{}

func (DefaultBuilder) BuildReplacement(dexes []model.DexReport, checksums []uint32, patch model.VerifierPatchSpec) ([]byte, []string, error) {
	return BuildVerifierSectionReplacement(dexes, checksums, patch)
}

func (DefaultBuilder) BuildMerge(dexes []model.DexReport, checksums []uint32, section model.VdexSection, raw []byte, patch model.VerifierPatchSpec) ([]byte, []string, error) {
	return BuildVerifierSectionMerge(dexes, checksums, section, raw, patch)
}

// DefaultComparator is the standard VerifierComparator implementation.
type DefaultComparator struct{}

func (DefaultComparator) Compare(raw []byte, section model.VdexSection, dexes []model.DexReport, checksums []uint32, patchedPayload []byte) (model.VerifierSectionDiff, []model.ModifyDexDiff, []string, error) {
	return CompareVerifierSectionDiff(raw, section, dexes, checksums, patchedPayload)
}

// DefaultPatchLoader is the standard PatchLoader implementation.
type DefaultPatchLoader struct{}

func (DefaultPatchLoader) Load(path string) (model.VerifierPatchSpec, []string, error) {
	return ParseVerifierPatch(path)
}

func (DefaultPatchLoader) Validate(patch model.VerifierPatchSpec) error {
	return ValidateVerifierPatchIndices(patch)
}

// DefaultFailureClassifier is the standard FailureClassifier implementation.
type DefaultFailureClassifier struct{}

func (DefaultFailureClassifier) Reason(summary model.ModifySummary, parseErr, compareErr, writeErr error, strictMatched []string) string {
	return MakeFailureReason(summary, parseErr, compareErr, writeErr, strictMatched)
}

func (DefaultFailureClassifier) Category(summary model.ModifySummary, parseErr, compareErr, writeErr error, strictMatched []string) string {
	return MakeFailureCategory(summary, parseErr, compareErr, writeErr, strictMatched)
}

// DefaultOutputWriter is the standard OutputWriter implementation.
type DefaultOutputWriter struct{}

func (DefaultOutputWriter) WriteAtomic(path string, data []byte) error {
	return WriteOutputFileAtomic(path, data)
}

func (DefaultOutputWriter) AppendLog(path string, summary model.ModifySummary, cliArgs map[string]string, strictMatched []string, failureReason string, failureCategory string) error {
	return AppendModifyLog(path, summary, cliArgs, strictMatched, failureReason, failureCategory)
}

// Compile-time interface compliance checks.
var (
	_ VerifierBuilder    = DefaultBuilder{}
	_ VerifierComparator = DefaultComparator{}
	_ PatchLoader        = DefaultPatchLoader{}
	_ FailureClassifier  = DefaultFailureClassifier{}
	_ OutputWriter       = DefaultOutputWriter{}
)

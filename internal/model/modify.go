package model

type VerifierPatchPair struct {
	Dest uint32 `json:"dest"`
	Src  uint32 `json:"src"`
}

type VerifierPatchClass struct {
	ClassIndex int                 `json:"class_index"`
	Verified   *bool               `json:"verified,omitempty"`
	Pairs      []VerifierPatchPair `json:"pairs,omitempty"`
}

type VerifierPatchDex struct {
	DexIndex     int                  `json:"dex_index"`
	ExtraStrings []string             `json:"extra_strings"`
	Classes      []VerifierPatchClass `json:"classes"`
}

type VerifierPatchSpec struct {
	Mode  string             `json:"mode"`
	Dexes []VerifierPatchDex `json:"dexes"`
}

type ModifySummary struct {
	SchemaVersion         string              `json:"schema_version"`
	InputFile             string              `json:"input_file"`
	OutputFile            string              `json:"output_file"`
	Mode                  string              `json:"mode"`
	DryRun                bool                `json:"dry_run"`
	Status                string              `json:"status"`
	PatchDexes            int                 `json:"patch_dexes"`
	PatchClasses          int                 `json:"patch_classes"`
	PatchExtraStrings     int                 `json:"patch_extra_strings"`
	ExpectedDexes         int                 `json:"expected_dexes"`
	VerifierSectionOld    uint32              `json:"verifier_section_old_size"`
	VerifierSectionNew    int                 `json:"verifier_section_new_size"`
	TotalClasses          int                 `json:"total_classes"`
	ModifiedClasses       int                 `json:"modified_classes"`
	UnmodifiedClasses     int                 `json:"unmodified_classes"`
	DexDiffs              []ModifyDexDiff     `json:"dex_diffs,omitempty"`
	ClassChangePercent    float64             `json:"class_change_percent"`
	WarningsByCategory    map[string][]string `json:"warnings_by_category,omitempty"`
	Warnings              []string            `json:"warnings"`
	Errors                []string            `json:"errors"`
	FailureCategory       string              `json:"failure_category,omitempty"`
	FailureCategoryCounts map[string]int      `json:"failure_category_counts,omitempty"`
}

type ModifyDexDiff struct {
	DexIndex          int   `json:"dex_index"`
	TotalClasses      int   `json:"total_classes"`
	ModifiedClasses   int   `json:"modified_classes"`
	UnmodifiedClasses int   `json:"unmodified_classes"`
	ChangedClassIdxs  []int `json:"changed_class_indices,omitempty"`
}

type VerifierSectionDiff struct {
	TotalClasses      int
	ModifiedClasses   int
	UnmodifiedClasses int
}

type VerifierSectionClass struct {
	Verified bool
	Pairs    []VerifierPatchPair
}

type VerifierSectionDex struct {
	ClassCount  int
	Classes     []VerifierSectionClass
	ExtraString []string
}

type ModifyLogEntry struct {
	Timestamp             string            `json:"timestamp"`
	Cmd                   []string          `json:"command"`
	Summary               ModifySummary     `json:"summary"`
	Args                  map[string]string `json:"args"`
	ModifiedDexes         []int             `json:"modified_dexes,omitempty"`
	TopSamples            []string          `json:"top_modified_class_samples,omitempty"`
	ModifiedClassCount    int               `json:"modified_class_count,omitempty"`
	StrictMatched         []string          `json:"strict_matched_warnings,omitempty"`
	FailureReason         string            `json:"failure_reason,omitempty"`
	FailureCategory       string            `json:"failure_category,omitempty"`
	FailureCategoryCounts map[string]int    `json:"failure_category_counts,omitempty"`
}

package model

// VdexDiff holds the structural differences between two VDEX files.
type VdexDiff struct {
	FileA string `json:"file_a"`
	FileB string `json:"file_b"`
	SizeA int    `json:"size_a"`
	SizeB int    `json:"size_b"`

	HeaderChanged  bool                `json:"header_changed"`
	HeaderDiff     *HeaderDiff         `json:"header_diff,omitempty"`
	SectionDiffs   []SectionDiff       `json:"section_diffs,omitempty"`
	ChecksumDiff   *ChecksumDiff       `json:"checksum_diff,omitempty"`
	DexDiffs       []DexFileDiff       `json:"dex_diffs,omitempty"`
	VerifierDiff   *VerifierDiffInfo   `json:"verifier_diff,omitempty"`
	TypeLookupDiff *TypeLookupDiffInfo `json:"type_lookup_diff,omitempty"`

	Summary DiffSummary `json:"summary"`
}

type HeaderDiff struct {
	MagicA   string `json:"magic_a,omitempty"`
	MagicB   string `json:"magic_b,omitempty"`
	VersionA string `json:"version_a,omitempty"`
	VersionB string `json:"version_b,omitempty"`
}

type SectionDiff struct {
	Kind      uint32 `json:"kind"`
	Name      string `json:"name"`
	OffsetA   uint32 `json:"offset_a"`
	OffsetB   uint32 `json:"offset_b"`
	SizeA     uint32 `json:"size_a"`
	SizeB     uint32 `json:"size_b"`
	SizeDelta int    `json:"size_delta"`
}

type ChecksumDiff struct {
	CountA   int   `json:"count_a"`
	CountB   int   `json:"count_b"`
	Changed  []int `json:"changed_indices,omitempty"`
	AddedB   int   `json:"added_in_b"`
	RemovedA int   `json:"removed_from_a"`
}

type DexFileDiff struct {
	Index      int    `json:"index"`
	Status     string `json:"status"` // "unchanged", "modified", "added", "removed"
	ChecksumA  uint32 `json:"checksum_a,omitempty"`
	ChecksumB  uint32 `json:"checksum_b,omitempty"`
	ClassDefsA uint32 `json:"class_defs_a,omitempty"`
	ClassDefsB uint32 `json:"class_defs_b,omitempty"`
	SignatureA string `json:"signature_a,omitempty"`
	SignatureB string `json:"signature_b,omitempty"`
}

type VerifierDiffInfo struct {
	DexCount     int               `json:"dex_count"`
	DexDiffs     []VerifierDexDiff `json:"dex_diffs,omitempty"`
	TotalChanged int               `json:"total_classes_changed"`
}

type VerifierDexDiff struct {
	DexIndex      int `json:"dex_index"`
	VerifiedA     int `json:"verified_a"`
	VerifiedB     int `json:"verified_b"`
	UnverifiedA   int `json:"unverified_a"`
	UnverifiedB   int `json:"unverified_b"`
	PairsA        int `json:"pairs_a"`
	PairsB        int `json:"pairs_b"`
	ExtraStringsA int `json:"extra_strings_a"`
	ExtraStringsB int `json:"extra_strings_b"`
	VerifiedDelta int `json:"verified_delta"`
	PairsDelta    int `json:"pairs_delta"`
}

type TypeLookupDiffInfo struct {
	DexCount int                 `json:"dex_count"`
	DexDiffs []TypeLookupDexDiff `json:"dex_diffs,omitempty"`
}

type TypeLookupDexDiff struct {
	DexIndex     int `json:"dex_index"`
	BucketsA     int `json:"buckets_a"`
	BucketsB     int `json:"buckets_b"`
	EntriesA     int `json:"entries_a"`
	EntriesB     int `json:"entries_b"`
	EntriesDelta int `json:"entries_delta"`
}

type DiffSummary struct {
	Identical         bool `json:"identical"`
	SectionsChanged   int  `json:"sections_changed"`
	ChecksumsChanged  int  `json:"checksums_changed"`
	DexFilesChanged   int  `json:"dex_files_changed"`
	VerifierChanged   int  `json:"verifier_classes_changed"`
	TypeLookupChanged int  `json:"type_lookup_entries_changed"`
}

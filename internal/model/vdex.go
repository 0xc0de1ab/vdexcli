package model

type VdexSection struct {
	Kind    uint32 `json:"kind"`
	Offset  uint32 `json:"offset"`
	Size    uint32 `json:"size"`
	Name    string `json:"name"`
	Meaning string `json:"meaning"`
}

type VdexHeader struct {
	Magic       string `json:"magic"`
	Version     string `json:"version"`
	NumSections uint32 `json:"number_of_sections"`
}

type DexReport struct {
	Index        int      `json:"index"`
	Offset       uint32   `json:"offset"`
	Size         uint32   `json:"size"`
	Checksum     uint32   `json:"checksum"`
	Magic        string   `json:"magic"`
	Version      string   `json:"version"`
	ChecksumId   uint32   `json:"checksum_field"`
	Signature    string   `json:"signature"`
	FileSize     uint32   `json:"file_size"`
	HeaderSize   uint32   `json:"header_size"`
	Endian       string   `json:"endian"`
	LinkSize     uint32   `json:"link_size"`
	LinkOffset   uint32   `json:"link_offset"`
	MapOffset    uint32   `json:"map_offset"`
	StringIds    uint32   `json:"string_ids_size"`
	StringIdsOff uint32   `json:"string_ids_off"`
	TypeIds      uint32   `json:"type_ids_size"`
	TypeIdsOff   uint32   `json:"type_ids_off"`
	ProtoIds     uint32   `json:"proto_ids_size"`
	ProtoIdsOff  uint32   `json:"proto_ids_off"`
	FieldIds     uint32   `json:"field_ids_size"`
	FieldIdsOff  uint32   `json:"field_ids_off"`
	MethodIds    uint32   `json:"method_ids_size"`
	MethodIdsOff uint32   `json:"method_ids_off"`
	ClassDefs    uint32   `json:"class_defs_size"`
	ClassDefsOff uint32   `json:"class_defs_off"`
	DataSize     uint32   `json:"data_size"`
	DataOffset   uint32   `json:"data_offset"`
	Classes      []string `json:"class_def_preview,omitempty"`
}

type DexContext struct {
	Rep                DexReport
	Strings            []string
	StringOffsetToName map[uint32]string
}

type VerifierPair struct {
	ClassDefIndex uint32 `json:"class_def_index"`
	DestID        uint32 `json:"destination_id"`
	Dest          string `json:"destination"`
	SrcID         uint32 `json:"source_id"`
	Src           string `json:"source"`
}

type VerifierDexReport struct {
	DexIndex           int            `json:"dex_index"`
	VerifiedClasses    int            `json:"verified_classes"`
	UnverifiedClasses  int            `json:"unverified_classes"`
	AssignabilityPairs int            `json:"assignability_pairs"`
	ExtraStringCount   int            `json:"extra_string_count"`
	FirstPairs         []VerifierPair `json:"first_pairs"`
}

type VerifierReport struct {
	Offset uint32              `json:"offset"`
	Size   uint32              `json:"size"`
	Dexes  []VerifierDexReport `json:"dexes"`
}

type TypeLookupSample struct {
	Bucket       uint32 `json:"bucket"`
	ClassDef     uint32 `json:"class_def_index"`
	StringOffset uint32 `json:"string_offset"`
	NextDelta    uint32 `json:"next_delta"`
	HashBits     uint32 `json:"hash_bits"`
	Descriptor   string `json:"descriptor"`
}

type TypeLookupDexReport struct {
	DexIndex        int                `json:"dex_index"`
	RawSize         uint32             `json:"raw_size"`
	MaskBits        uint32             `json:"mask_bits"`
	BucketCount     int                `json:"bucket_count"`
	EntryCount      int                `json:"entry_count"`
	NonEmptyBuckets int                `json:"non_empty_buckets"`
	MaxChainLen     int                `json:"max_chain_len"`
	AvgChainLen     float64            `json:"avg_chain_len"`
	Samples         []TypeLookupSample `json:"sample_entries"`
	Warnings        []string           `json:"warnings"`
}

type TypeLookupReport struct {
	Offset uint32                `json:"offset"`
	Size   uint32                `json:"size"`
	Dexes  []TypeLookupDexReport `json:"dexes"`
}

type ByteCoverageRange struct {
	Offset int    `json:"offset"`
	Size   int    `json:"size"`
	Label  string `json:"label"`
}

type ByteCoverageReport struct {
	FileSize        int                 `json:"file_size"`
	ParsedBytes     int                 `json:"parsed_bytes"`
	UnparsedBytes   int                 `json:"unparsed_bytes"`
	CoveragePercent float64             `json:"coverage_percent"`
	Ranges          []ByteCoverageRange `json:"ranges"`
	Gaps            []ByteCoverageRange `json:"gaps,omitempty"`
}

type VdexReport struct {
	SchemaVersion      string              `json:"schema_version"`
	Meanings           *ParserMeanings     `json:"meanings,omitempty"`
	File               string              `json:"file"`
	Size               int                 `json:"size"`
	Header             VdexHeader          `json:"header"`
	Sections           []VdexSection       `json:"sections"`
	Checksums          []uint32            `json:"checksums"`
	Dexes              []DexReport         `json:"dex_files"`
	Verifier           *VerifierReport     `json:"verifier_deps,omitempty"`
	TypeLookup         *TypeLookupReport   `json:"type_lookup,omitempty"`
	Coverage           *ByteCoverageReport `json:"byte_coverage,omitempty"`
	Diagnostics        []ParseDiagnostic   `json:"diagnostics,omitempty"`
	Warnings           []string            `json:"warnings"`
	WarningsByCategory map[string][]string `json:"warnings_by_category,omitempty"`
	Errors             []string            `json:"errors"`
}

// AddDiag appends a structured diagnostic and populates the legacy
// Warnings/Errors string slices for backward compatibility.
func (r *VdexReport) AddDiag(d ParseDiagnostic) {
	r.Diagnostics = append(r.Diagnostics, d)
	if d.Severity == SeverityError {
		r.Errors = append(r.Errors, d.Message)
	} else {
		r.Warnings = append(r.Warnings, d.Message)
	}
}

// AddDiags appends multiple diagnostics.
func (r *VdexReport) AddDiags(ds []ParseDiagnostic) {
	for _, d := range ds {
		r.AddDiag(d)
	}
}

type ExtractSummary struct {
	SchemaVersion      string              `json:"schema_version"`
	File               string              `json:"file"`
	Size               int                 `json:"size"`
	ExtractDir         string              `json:"extract_dir"`
	NameTemplate       string              `json:"name_template"`
	Extracted          int                 `json:"extracted"`
	Failed             int                 `json:"failed"`
	Warnings           []string            `json:"warnings"`
	WarningsByCategory map[string][]string `json:"warnings_by_category,omitempty"`
	Errors             []string            `json:"errors"`
}

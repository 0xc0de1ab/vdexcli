package model

// ParserMeanings holds human-readable descriptions for every parsed field.
type ParserMeanings struct {
	VdexFile struct {
		Magic              string `json:"magic"`
		Version            string `json:"version"`
		Sections           string `json:"sections"`
		Checksums          string `json:"checksums"`
		DexFiles           string `json:"dex_files"`
		Verifier           string `json:"verifier_deps"`
		TypeLookup         string `json:"type_lookup"`
		Warnings           string `json:"warnings"`
		WarningsByCategory string `json:"warnings_by_category"`
		Errors             string `json:"errors"`
		SchemaVer          string `json:"schema_version"`
	} `json:"vdex_file"`
	SectionKind map[string]string `json:"section_kind"`
	DexHeader   struct {
		Magic        string `json:"magic"`
		Version      string `json:"version"`
		Checksum     string `json:"checksum_field"`
		Signature    string `json:"signature"`
		FileSize     string `json:"file_size"`
		HeaderSize   string `json:"header_size"`
		Endian       string `json:"endian"`
		StringIds    string `json:"string_ids_size"`
		StringIdsOff string `json:"string_ids_off"`
		TypeIds      string `json:"type_ids_size"`
		TypeIdsOff   string `json:"type_ids_off"`
		ProtoIds     string `json:"proto_ids_size"`
		ProtoIdsOff  string `json:"proto_ids_off"`
		FieldIds     string `json:"field_ids_size"`
		FieldIdsOff  string `json:"field_ids_off"`
		MethodIds    string `json:"method_ids_size"`
		MethodIdsOff string `json:"method_ids_off"`
		ClassDefs    string `json:"class_defs_size"`
		ClassDefsOff string `json:"class_defs_off"`
		DataSize     string `json:"data_size"`
		DataOffset   string `json:"data_offset"`
		ClassPreview string `json:"class_def_preview"`
	} `json:"dex_header"`
	VerifierDeps struct {
		Offset            string `json:"offset"`
		Size              string `json:"size"`
		VerifiedClasses   string `json:"verified_classes"`
		UnverifiedClasses string `json:"unverified_classes"`
		AssignabilityPair string `json:"assignability_pairs"`
		ExtraStringCount  string `json:"extra_string_count"`
		FirstPairs        string `json:"first_pairs"`
	} `json:"verifier_deps"`
	TypeLookup struct {
		Offset          string `json:"offset"`
		Size            string `json:"size"`
		RawSize         string `json:"raw_size"`
		BucketCount     string `json:"bucket_count"`
		EntryCount      string `json:"entry_count"`
		NonEmptyBuckets string `json:"non_empty_buckets"`
		MaxChainLen     string `json:"max_chain_len"`
		AvgChainLen     string `json:"avg_chain_len"`
		SampleEntries   string `json:"sample_entries"`
	} `json:"type_lookup"`
}

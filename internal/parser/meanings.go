package parser

import "github.com/0xc0de1ab/vdexcli/internal/model"

// NewParserMeanings returns a ParserMeanings instance populated with
// human-readable descriptions for every field the parser emits.
func NewParserMeanings() *model.ParserMeanings {
	return &model.ParserMeanings{
		VdexFile: struct {
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
		}{
			Magic:              "Vdex header magic (must be 'vdex')",
			Version:            "Vdex format version, currently '027' expected",
			Sections:           "Section table entries for checksum, dex, verifier_deps, type_lookup",
			Checksums:          "Concatenated checksum array, one entry per embedded dex",
			DexFiles:           "Parsed DEX payload metadata and preview classes",
			Verifier:           "Verifier dependency section summary per dex",
			TypeLookup:         "Type lookup table section summary per dex",
			Warnings:           "Non-fatal parse anomalies collected during analysis",
			WarningsByCategory: "Warnings grouped by parser-defined categories",
			Errors:             "Fatal parse errors",
			SchemaVer:          "CLI output schema version",
		},
		SectionKind: map[string]string{
			"0":  "kChecksumSection",
			"1":  "kDexFileSection",
			"2":  "kVerifierDepsSection",
			"3":  "kTypeLookupTableSection",
			"8":  "kDebugInfoSection (ART variants)",
			"9":  "kProfilingInfoSection (ART variants)",
			"10": "kClassInfoSection (ART variants)",
		},
		DexHeader: struct {
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
		}{
			Magic:        "DEX magic header 'dex\\n'",
			Version:      "DEX format version",
			Checksum:     "adler-style checksum from DEX header (checksum_field)",
			Signature:    "SHA-1 signature of the DEX file (20 bytes at offset 0x0C)",
			FileSize:     "Total DEX file size in bytes",
			HeaderSize:   "Size of dex header",
			Endian:       "Byte order indicated by endian_tag",
			StringIds:    "Number of string_ids entries",
			StringIdsOff: "Offset of string_ids table in DEX",
			TypeIds:      "Number of type_ids entries",
			TypeIdsOff:   "Offset of type_ids table in DEX",
			ProtoIds:     "Number of proto_ids entries",
			ProtoIdsOff:  "Offset of proto_ids table in DEX",
			FieldIds:     "Number of field_ids entries",
			FieldIdsOff:  "Offset of field_ids table in DEX",
			MethodIds:    "Number of method_ids entries",
			MethodIdsOff: "Offset of method_ids table in DEX",
			ClassDefs:    "Number of class_defs entries",
			ClassDefsOff: "Offset of class_defs table in DEX",
			DataSize:     "Size of data section",
			DataOffset:   "Offset of data section",
			ClassPreview: "Top class_def descriptors preview (for human inspection)",
		},
		VerifierDeps: struct {
			Offset            string `json:"offset"`
			Size              string `json:"size"`
			VerifiedClasses   string `json:"verified_classes"`
			UnverifiedClasses string `json:"unverified_classes"`
			AssignabilityPair string `json:"assignability_pairs"`
			ExtraStringCount  string `json:"extra_string_count"`
			FirstPairs        string `json:"first_pairs"`
		}{
			Offset:            "Offset of per-dex verifier section blob",
			Size:              "Size of per-dex verifier section blob",
			VerifiedClasses:   "Number of classes verified by verifier",
			UnverifiedClasses: "Number of classes with 'not verified' marker",
			AssignabilityPair: "Pairs linking class definitions and source type ids",
			ExtraStringCount:  "Number of extra strings for verifier IDs resolution",
			FirstPairs:        "Preview of assignability pair entries",
		},
		TypeLookup: struct {
			Offset          string `json:"offset"`
			Size            string `json:"size"`
			RawSize         string `json:"raw_size"`
			BucketCount     string `json:"bucket_count"`
			EntryCount      string `json:"entry_count"`
			NonEmptyBuckets string `json:"non_empty_buckets"`
			MaxChainLen     string `json:"max_chain_len"`
			AvgChainLen     string `json:"avg_chain_len"`
			SampleEntries   string `json:"sample_entries"`
		}{
			Offset:          "Offset for this dex type_lookup block",
			Size:            "Size for this dex type_lookup block",
			RawSize:         "Raw payload size",
			BucketCount:     "Number of buckets in table",
			EntryCount:      "How many entries were parsed",
			NonEmptyBuckets: "Buckets containing at least one descriptor entry",
			MaxChainLen:     "Maximum chain traverse length while decoding linked slots",
			AvgChainLen:     "Average chain length for visited chains",
			SampleEntries:   "Descriptor samples for quick inspection",
		},
	}
}

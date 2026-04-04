package model

import "fmt"

// Severity classifies a parse finding as fatal or informational.
type Severity int

const (
	SeverityError   Severity = iota // Parsing cannot continue reliably.
	SeverityWarning                 // Parsing continues; data may be incomplete.
)

// Category groups related diagnostics for filtering (--strict-warn).
type Category string

const (
	CatHeader     Category = "header"
	CatSection    Category = "section"
	CatDex        Category = "dex"
	CatVerifier   Category = "verifier"
	CatTypeLookup Category = "type_lookup"
	CatChecksum   Category = "checksum"
)

// ParseDiagnostic is a structured finding emitted during VDEX/DEX parsing.
type ParseDiagnostic struct {
	Severity Severity
	Category Category
	Code     DiagCode
	Message  string
	Hint     string // Actionable suggestion for the user.
}

func (d ParseDiagnostic) Error() string {
	if d.Hint != "" {
		return fmt.Sprintf("[%s] %s (hint: %s)", d.Code, d.Message, d.Hint)
	}
	return fmt.Sprintf("[%s] %s", d.Code, d.Message)
}

// ForJSON returns a structured representation for JSON output.
func (d ParseDiagnostic) ForJSON() map[string]string {
	m := map[string]string{
		"code":     string(d.Code),
		"severity": d.SeverityString(),
		"category": string(d.Category),
		"message":  d.Message,
	}
	if d.Hint != "" {
		m["hint"] = d.Hint
	}
	return m
}

// SeverityString returns "error" or "warning".
func (d ParseDiagnostic) SeverityString() string {
	if d.Severity == SeverityError {
		return "error"
	}
	return "warning"
}

// DiagCode identifies the specific type of diagnostic for programmatic handling.
type DiagCode string

const (
	// --- header errors ---
	ErrFileTooSmall        DiagCode = "ERR_FILE_TOO_SMALL"
	ErrInvalidMagic        DiagCode = "ERR_INVALID_MAGIC"
	ErrSectionTableTrunc   DiagCode = "ERR_SECTION_TABLE_TRUNCATED"
	ErrChecksumExceedsFile DiagCode = "ERR_CHECKSUM_EXCEEDS_FILE"

	// --- header warnings ---
	WarnVersionMismatch DiagCode = "WARN_VERSION_MISMATCH"

	// --- section warnings ---
	WarnSectionExceedsFile DiagCode = "WARN_SECTION_EXCEEDS_FILE"
	WarnSectionBeyondFile  DiagCode = "WARN_SECTION_BEYOND_FILE"
	WarnSectionZeroSize    DiagCode = "WARN_SECTION_ZERO_SIZE"
	WarnSectionOverlap     DiagCode = "WARN_SECTION_OVERLAP"
	WarnSectionDuplicate   DiagCode = "WARN_SECTION_DUPLICATE"

	// --- checksum warnings ---
	WarnChecksumAlignment DiagCode = "WARN_CHECKSUM_NOT_ALIGNED"
	WarnNoChecksumSection DiagCode = "WARN_NO_CHECKSUM_SECTION"

	// --- dex errors/warnings ---
	ErrDexTooShort         DiagCode = "ERR_DEX_TOO_SHORT"
	ErrDexInvalidMagic     DiagCode = "ERR_DEX_INVALID_MAGIC"
	ErrDexInvalidFileSize  DiagCode = "ERR_DEX_INVALID_FILE_SIZE"
	WarnDexSectionRange    DiagCode = "WARN_DEX_SECTION_RANGE"
	WarnDexTruncated       DiagCode = "WARN_DEX_TRUNCATED"
	WarnDexFileSizeClamped DiagCode = "WARN_DEX_FILESIZE_CLAMPED"
	ErrDexStringsRange     DiagCode = "ERR_DEX_STRINGS_RANGE"
	ErrDexTypeIdsRange     DiagCode = "ERR_DEX_TYPE_IDS_RANGE"
	ErrDexClassDefsRange   DiagCode = "ERR_DEX_CLASS_DEFS_RANGE"

	// --- verifier warnings ---
	WarnVerifierInferredCount   DiagCode = "WARN_VERIFIER_INFERRED_COUNT"
	WarnVerifierSectionRange    DiagCode = "WARN_VERIFIER_SECTION_RANGE"
	WarnVerifierIndexTruncated  DiagCode = "WARN_VERIFIER_INDEX_TRUNCATED"
	WarnVerifierBlockOutside    DiagCode = "WARN_VERIFIER_BLOCK_OUTSIDE"
	WarnVerifierBlockTruncated  DiagCode = "WARN_VERIFIER_BLOCK_TRUNCATED"
	WarnVerifierMalformedChain  DiagCode = "WARN_VERIFIER_MALFORMED_CHAIN"
	WarnVerifierMalformedBounds DiagCode = "WARN_VERIFIER_MALFORMED_BOUNDS"
	WarnVerifierInvalidLEB128   DiagCode = "WARN_VERIFIER_INVALID_LEB128"
	WarnVerifierExtrasTruncated DiagCode = "WARN_VERIFIER_EXTRAS_TRUNCATED"
	WarnVerifierExtraInvalid    DiagCode = "WARN_VERIFIER_EXTRA_INVALID"

	// --- type lookup warnings ---
	WarnTypeLookupSectionRange DiagCode = "WARN_TYPELOOKUP_SECTION_RANGE"
	WarnTypeLookupTruncated    DiagCode = "WARN_TYPELOOKUP_TRUNCATED"
	WarnTypeLookupDexExceeds   DiagCode = "WARN_TYPELOOKUP_DEX_EXCEEDS"
)

// Diagnostic constructors — each returns a fully populated ParseDiagnostic.
// Using constructors ensures consistent formatting and correct severity/category.

func DiagFileTooSmall(fileSize int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatHeader, ErrFileTooSmall,
		fmt.Sprintf("file too small for VDEX header: %d bytes (need >= 12)", fileSize),
		"verify the file is a complete VDEX and not truncated during copy"}
}

func DiagInvalidMagic(got string) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatHeader, ErrInvalidMagic,
		fmt.Sprintf("invalid VDEX magic: got %q, expected \"vdex\"", got),
		"this file is not a VDEX; check if it is an OAT, DEX, or unrelated file"}
}

func DiagVersionMismatch(expected, got string) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatHeader, WarnVersionMismatch,
		fmt.Sprintf("VDEX version mismatch: got %q, expected %q", got, expected),
		fmt.Sprintf("vdexcli supports v%s (Android 12+); this file may parse partially or incorrectly", expected)}
}

func DiagSectionTableTruncated(need, have int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatSection, ErrSectionTableTrunc,
		fmt.Sprintf("file too small for section header table: need %d bytes, have %d", need, have),
		"the file appears truncated; re-extract from the device or build output"}
}

func DiagChecksumExceedsFile() ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatChecksum, ErrChecksumExceedsFile,
		"checksum section exceeds file boundary",
		"re-extract the file from device; use `vdexcli parse --format sections` to inspect raw section headers"}
}

func DiagChecksumAlignment() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatChecksum, WarnChecksumAlignment,
		"checksum section size is not a multiple of 4",
		"last checksum entry may be incomplete; dex count derived from truncated section — verify with `--format sections`"}
}

func DiagNoChecksumSection() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatChecksum, WarnNoChecksumSection,
		"no checksum section found; dex count inferred from dex section",
		"this is normal for some DM-format VDEX files"}
}

func DiagSectionExceedsFile(kind uint32, offset, size uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionExceedsFile,
		fmt.Sprintf("section %s exceeds file: off=%#x size=%#x", sectionLabel(kind), offset, size),
		"re-extract the file from the device or build output; this section will be skipped"}
}

func DiagSectionBeyondFile(kind uint32, offset uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionBeyondFile,
		fmt.Sprintf("section %s starts beyond file: off=%#x", sectionLabel(kind), offset),
		"section header table may be corrupted; re-extract from device or verify with a hex editor"}
}

func DiagSectionZeroSize(kind uint32) ParseDiagnostic {
	name := SectionName[kind]
	if name == "" {
		name = fmt.Sprintf("kind %d", kind)
	}
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionZeroSize,
		fmt.Sprintf("section %s has zero size", name),
		"this section is empty; normal for DM-format VDEX (no embedded DEX)"}
}

func DiagSectionOverlap(kindA, kindB uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionOverlap,
		fmt.Sprintf("section %s overlaps section %s", sectionLabel(kindA), sectionLabel(kindB)),
		"section header table is corrupted; re-extract from device — overlapping data will produce incorrect results"}
}

func DiagSectionDuplicate(kind uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionDuplicate,
		fmt.Sprintf("duplicate section kind %d (only first occurrence used)", kind),
		"non-standard VDEX; the second section of the same kind is ignored"}
}

// sectionLabel returns a human-readable section name for diagnostic messages.
func sectionLabel(kind uint32) string {
	if n, ok := SectionName[kind]; ok {
		return n
	}
	return fmt.Sprintf("kind(%d)", kind)
}

// --- dex constructors ---

func DiagDexTooShort(index int, available int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatDex, ErrDexTooShort,
		fmt.Sprintf("dex[%d]: header too short (%d bytes available, need 112)", index, available),
		"the DEX section may be truncated; re-extract the VDEX from device"}
}

func DiagDexInvalidMagic(index int, got string) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatDex, ErrDexInvalidMagic,
		fmt.Sprintf("dex[%d]: invalid magic %q", index, got),
		"embedded data is not a valid DEX file; the VDEX may be corrupted"}
}

func DiagDexInvalidFileSize(index int, declared, available uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatDex, ErrDexInvalidFileSize,
		fmt.Sprintf("dex[%d]: declared file_size %d exceeds available %d", index, declared, available),
		"DEX header file_size is inconsistent with the section; file may be partially overwritten"}
}

func DiagDexSectionRange() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatDex, WarnDexSectionRange,
		"kDexFileSection offset/size out of file range",
		"DEX section will be skipped; other sections may still parse correctly"}
}

func DiagDexTruncated(index int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatDex, WarnDexTruncated,
		fmt.Sprintf("dex[%d]: section ends before next dex boundary", index),
		"remaining DEX files in this section cannot be parsed"}
}

func DiagDexFileSizeClamped(index int, declared, available uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatDex, WarnDexFileSizeClamped,
		fmt.Sprintf("dex[%d]: file_size %d clamped to available %d", index, declared, available),
		"DEX header file_size exceeds section bounds; parsing continues with clamped size"}
}

func DiagDexStringsRange(index int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatDex, ErrDexStringsRange,
		fmt.Sprintf("dex[%d]: string_ids offset/size out of dex range", index),
		"string table cannot be read; class names and verifier strings will be unavailable"}
}

func DiagDexTypeIdsRange(index int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatDex, ErrDexTypeIdsRange,
		fmt.Sprintf("dex[%d]: type_ids offset/size out of dex range", index),
		"type table cannot be read; class descriptor resolution will fail"}
}

func DiagDexClassDefsRange(index int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatDex, ErrDexClassDefsRange,
		fmt.Sprintf("dex[%d]: class_defs offset/size out of dex range", index),
		"class definitions cannot be read; class preview will be empty"}
}

// --- verifier constructors ---

func DiagVerifierSectionRange() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierSectionRange,
		"verifier-deps section offset/size out of file range",
		"verifier section will be skipped; use `--format sections` to check raw offsets"}
}

func DiagVerifierIndexTruncated(dexIdx int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierIndexTruncated,
		fmt.Sprintf("verifier section index table truncated at dex %d", dexIdx),
		"remaining dex verifier data cannot be parsed; file may be truncated"}
}

func DiagVerifierBlockOutside(dexIdx int, offset int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierBlockOutside,
		fmt.Sprintf("verifier block %d offset %#x outside section", dexIdx, offset),
		"this dex verifier block will be skipped; section header may be corrupted"}
}

func DiagVerifierBlockTruncated(dexIdx int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierBlockTruncated,
		fmt.Sprintf("dex %d verifier block truncated", dexIdx),
		"class offset table extends beyond section; class counts may be wrong"}
}

func DiagVerifierMalformedChain(dexIdx, classIdx int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierMalformedChain,
		fmt.Sprintf("dex %d class %d malformed class offset chain", dexIdx, classIdx),
		"cannot find next verified class boundary; remaining classes in this dex skipped"}
}

func DiagVerifierMalformedBounds(dexIdx, classIdx int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierMalformedBounds,
		fmt.Sprintf("dex %d class %d malformed set bounds", dexIdx, classIdx),
		"assignability set range is invalid; this class's pairs will be missing"}
}

func DiagVerifierInvalidLEB128(dexIdx, classIdx int, field string) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierInvalidLEB128,
		fmt.Sprintf("dex %d class %d invalid %s leb128", dexIdx, classIdx, field),
		"LEB128 decoding failed; remaining pairs for this class are skipped"}
}

func DiagVerifierExtrasTruncated(dexIdx int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierExtrasTruncated,
		fmt.Sprintf("dex %d verifier extra strings table truncated", dexIdx),
		"extra string offsets extend beyond section; string resolution will fall back to IDs"}
}

func DiagVerifierExtraInvalid(dexIdx, strIdx int, offset int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatVerifier, WarnVerifierExtraInvalid,
		fmt.Sprintf("dex %d extra string %d offset %#x invalid", dexIdx, strIdx, offset),
		"string offset points outside section; this string shown as placeholder"}
}

// --- type lookup constructors ---

func DiagTypeLookupSectionRange() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatTypeLookup, WarnTypeLookupSectionRange,
		"type-lookup section offset/size out of file range",
		"type-lookup section will be skipped; use `--format sections` to check raw offsets"}
}

func DiagTypeLookupTruncated(dexIdx int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatTypeLookup, WarnTypeLookupTruncated,
		fmt.Sprintf("type-lookup section truncated before dex %d", dexIdx),
		"remaining dex type-lookup tables cannot be parsed"}
}

func DiagTypeLookupDexExceeds(dexIdx int, size int) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatTypeLookup, WarnTypeLookupDexExceeds,
		fmt.Sprintf("type-lookup dex %d size %d exceeds section", dexIdx, size),
		"this dex's type-lookup table extends beyond section bounds; parsing stops here"}
}

// UnknownSectionName formats a name for an unrecognized section kind.
func UnknownSectionName(kind uint32) string {
	return fmt.Sprintf("unknown(%d)", kind)
}

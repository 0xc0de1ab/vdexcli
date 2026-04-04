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
		"this VDEX may be from a different Android version; parsing continues but results may be incomplete"}
}

func DiagSectionTableTruncated(need, have int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatSection, ErrSectionTableTrunc,
		fmt.Sprintf("file too small for section header table: need %d bytes, have %d", need, have),
		"the file appears truncated; re-extract from the device or build output"}
}

func DiagChecksumExceedsFile() ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatChecksum, ErrChecksumExceedsFile,
		"checksum section exceeds file boundary",
		"file may be truncated or the section header table is corrupted"}
}

func DiagChecksumAlignment() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatChecksum, WarnChecksumAlignment,
		"checksum section size is not a multiple of 4",
		"non-standard section size; the last checksum entry may be incomplete"}
}

func DiagNoChecksumSection() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatChecksum, WarnNoChecksumSection,
		"no checksum section found; dex count inferred from dex section",
		"this is normal for some DM-format VDEX files"}
}

func DiagSectionExceedsFile(kind uint32, offset, size uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionExceedsFile,
		fmt.Sprintf("section kind %d exceeds file: off=%#x size=%#x", kind, offset, size),
		"section data extends past end of file; file may be truncated"}
}

func DiagSectionBeyondFile(kind uint32, offset uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionBeyondFile,
		fmt.Sprintf("section kind %d starts beyond file: off=%#x", kind, offset),
		"section offset points outside the file; header table may be corrupted"}
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
		fmt.Sprintf("section kind %d overlaps section kind %d", kindA, kindB),
		"overlapping sections indicate a corrupted section header table"}
}

func DiagSectionDuplicate(kind uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionDuplicate,
		fmt.Sprintf("duplicate section kind %d (only first occurrence used)", kind),
		"non-standard VDEX; the second section of the same kind is ignored"}
}

// UnknownSectionName formats a name for an unrecognized section kind.
func UnknownSectionName(kind uint32) string {
	return fmt.Sprintf("unknown(%d)", kind)
}

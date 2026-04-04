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
}

func (d ParseDiagnostic) Error() string { return d.Message }

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
		fmt.Sprintf("file too small for VDEX header: %d bytes (need >= 12)", fileSize)}
}

func DiagInvalidMagic(got string) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatHeader, ErrInvalidMagic,
		fmt.Sprintf("invalid VDEX magic: got %q, expected \"vdex\"", got)}
}

func DiagVersionMismatch(expected, got string) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatHeader, WarnVersionMismatch,
		fmt.Sprintf("VDEX version mismatch: got %q, expected %q", got, expected)}
}

func DiagSectionTableTruncated(need, have int) ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatSection, ErrSectionTableTrunc,
		fmt.Sprintf("file too small for section header table: need %d bytes, have %d", need, have)}
}

func DiagChecksumExceedsFile() ParseDiagnostic {
	return ParseDiagnostic{SeverityError, CatChecksum, ErrChecksumExceedsFile,
		"checksum section exceeds file boundary"}
}

func DiagChecksumAlignment() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatChecksum, WarnChecksumAlignment,
		"checksum section size is not a multiple of 4"}
}

func DiagNoChecksumSection() ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatChecksum, WarnNoChecksumSection,
		"no checksum section found; dex count inferred from dex section"}
}

func DiagSectionExceedsFile(kind uint32, offset, size uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionExceedsFile,
		fmt.Sprintf("section kind %d exceeds file: off=%#x size=%#x", kind, offset, size)}
}

func DiagSectionBeyondFile(kind uint32, offset uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionBeyondFile,
		fmt.Sprintf("section kind %d starts beyond file: off=%#x", kind, offset)}
}

func DiagSectionZeroSize(kind uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionZeroSize,
		fmt.Sprintf("section kind %d has zero size", kind)}
}

func DiagSectionOverlap(kindA, kindB uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionOverlap,
		fmt.Sprintf("section kind %d overlaps section kind %d", kindA, kindB)}
}

func DiagSectionDuplicate(kind uint32) ParseDiagnostic {
	return ParseDiagnostic{SeverityWarning, CatSection, WarnSectionDuplicate,
		fmt.Sprintf("duplicate section kind %d (only first occurrence used)", kind)}
}

// UnknownSectionName formats a name for an unrecognized section kind.
func UnknownSectionName(kind uint32) string {
	return fmt.Sprintf("unknown(%d)", kind)
}

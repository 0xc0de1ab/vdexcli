// Package model defines shared types, constants, and diagnostics used across
// all vdexcli packages. It has no internal dependencies.
package model

// CLIVersion is set at build time via -ldflags. Falls back to the default below.
var CLIVersion = "0.4.0"

const (
	VdexCurrentVersion  = "027"
	NotVerifiedMarker   = uint32(0xFFFFFFFF)
	VdexSchemaVersion   = "1.0.0"
	DefaultNameTemplate = "{base}_{index}_{checksum}.dex"

	SectionChecksum     = 0
	SectionDex          = 1
	SectionVerifierDeps = 2
	SectionTypeLookup   = 3

	MaxClassPreview       = 20
	MaxVerifierPairs      = 20
	MaxTypeLookupSamples  = 24
	MaxTypeLookupClasses  = 0xFFFF
	MaxModifyClassSamples = 8
)

var SectionName = map[uint32]string{
	SectionChecksum:     "kChecksumSection",
	SectionDex:          "kDexFileSection",
	SectionVerifierDeps: "kVerifierDepsSection",
	SectionTypeLookup:   "kTypeLookupTableSection",
}

var SectionMeaning = map[uint32]string{
	SectionChecksum:     "DEX file location checksum list (one uint32 per input dex)",
	SectionDex:          "Concatenated DEX file payload",
	SectionVerifierDeps: "Verifier dependency section",
	SectionTypeLookup:   "Class descriptor lookup table section",
}

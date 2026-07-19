package vdex

import "github.com/0xc0de1ab/vdexcli/internal/model"

// The following type aliases re-export internal model types under a stable
// public surface. Because they use Go type alias syntax (= model.X) callers
// do not need any conversion between the public and internal packages.
//
// Type stability: these types reflect the current internal/model layout.
// Fields will not be removed in minor releases, but new fields may be added.

// Field is a single annotated byte range within a VDEX file.
// Every byte in the file is covered by exactly one Field (including gaps and padding).
type Field = model.PrimitiveField

// FieldType is the primitive encoding of a field (e.g. "uint32_le", "uleb128").
type FieldType = model.PrimitiveType

// FieldMap is the complete annotated view of a VDEX file produced by Explain*.
// Fields are ordered by offset. TotalBytes reflects the file size; UnmappedGaps
// lists any byte ranges that could not be attributed to a known structure.
type FieldMap = model.PrimitiveMap

// ByteRange marks an unexplained [Start, End) byte range within the file.
type ByteRange = model.ByteRange

// Version returns the vdexcli engine version embedded at build time.
func Version() string {
	return model.CLIVersion
}

// Report is the high-level parsed VDEX report produced by Parse*.
// It contains the VDEX header, sections, checksums, DEX metadata,
// verifier dependency statistics, and byte-level coverage analysis.
type Report = model.VdexReport

// Diagnostic is a single parser diagnostic (error or warning).
type Diagnostic = model.ParseDiagnostic

// Primitive type constants for use in field type comparisons.
const (
	TypeMagic    = model.TypeMagic
	TypeUint8    = model.TypeUint8
	TypeUint16LE = model.TypeUint16LE
	TypeUint32LE = model.TypeUint32LE
	TypeUint64LE = model.TypeUint64LE
	TypeUleb128  = model.TypeUleb128
	TypeLeb128   = model.TypeLeb128
	TypeCString  = model.TypeCString
	TypeBytes    = model.TypeBytes
	TypePadding  = model.TypePadding
)

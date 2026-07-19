package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ByteArray marshals as a JSON number array so browser consumers receive the
// same byte-oriented representation exposed by the Go API. UnmarshalJSON also
// accepts the legacy base64 string representation.
type ByteArray []byte

func (b ByteArray) MarshalJSON() ([]byte, error) {
	values := make([]int, len(b))
	for i, value := range b {
		values[i] = int(value)
	}
	return json.Marshal(values)
}

func (b *ByteArray) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var encoded string
		if err := json.Unmarshal(data, &encoded); err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode legacy byte array: %w", err)
		}
		*b = decoded
		return nil
	}
	var values []int
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	out := make([]byte, len(values))
	for i, value := range values {
		if value < 0 || value > 255 {
			return fmt.Errorf("byte value at index %d is out of range: %d", i, value)
		}
		out[i] = byte(value)
	}
	*b = out
	return nil
}

type PrimitiveType string

const (
	TypeMagic    PrimitiveType = "magic"     // Magic number (e.g. 'vdex', 'dex\n')
	TypeChar     PrimitiveType = "char"      // Single character — reserved for future use; no ReadChar method yet
	TypeUint8    PrimitiveType = "uint8"     // 1-byte integer
	TypeUint16LE PrimitiveType = "uint16_le" // 2-byte little-endian integer
	TypeUint32LE PrimitiveType = "uint32_le" // 4-byte little-endian integer
	TypeUint64LE PrimitiveType = "uint64_le" // 8-byte little-endian integer
	TypeLeb128   PrimitiveType = "leb128"    // Variable-length signed LEB128 integer — reserved for future use; no ReadLeb128 method yet
	TypeUleb128  PrimitiveType = "uleb128"   // Variable-length unsigned LEB128 integer
	TypeString   PrimitiveType = "string"    // String data (MUTF-8) — reserved for future use; no ReadString method yet
	TypeCString  PrimitiveType = "cstring"   // Null-terminated C-style string
	TypeBytes    PrimitiveType = "bytes"     // Raw byte block (SHA1, signature, etc.)
	TypePadding  PrimitiveType = "padding"   // Alignment padding zero bytes
)

type PrimitiveField struct {
	Offset      uint32        `json:"offset"`       // Start byte offset in the file
	Size        uint32        `json:"size"`         // Physical size in bytes
	Type        PrimitiveType `json:"type"`         // Primitive data type
	RawBytes    ByteArray     `json:"raw_bytes"`    // Raw physical bytes (for hex dump)
	ParsedValue interface{}   `json:"parsed_value"` // Parsed/converted actual Go value
	LogicalPath string        `json:"logical_path"` // Logical structure path (e.g., "vdex.header.version")
	Summary     string        `json:"summary"`      // Short summary description
	Description string        `json:"description"`  // Detailed description
}

type PrimitiveMap struct {
	Fields       []*PrimitiveField `json:"fields"`
	TotalBytes   uint32            `json:"total_bytes"`
	UnmappedGaps []ByteRange       `json:"unmapped_gaps"` // Undescribed gap ranges
}

// ByteRange marks a [Start, End) byte range within the file.
// NOTE: This is distinct from ByteCoverageRange (defined in vdex.go) which uses
// {Offset, Size} form and is used for coverage accounting in the legacy parser.
type ByteRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

// FieldAtOffset returns the PrimitiveField that covers the given byte offset,
// or nil if no field covers it.
func (pm *PrimitiveMap) FieldAtOffset(offset uint32) *PrimitiveField {
	if pm == nil {
		return nil
	}
	for _, f := range pm.Fields {
		if offset >= f.Offset && offset < f.Offset+f.Size {
			return f
		}
	}
	return nil
}

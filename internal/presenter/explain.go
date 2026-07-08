package presenter

import (
	"fmt"
	"io"
	"strings"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// WriteExplain writes the PrimitiveMap to w, optionally filtering by offset.
func WriteExplain(w io.Writer, pm *model.PrimitiveMap, format string, offsetFilter *uint32) error {
	format = strings.ToLower(format)

	// 1. If offset filter is provided, find the specific field
	if offsetFilter != nil {
		field := FindFieldAtOffset(pm, *offsetFilter)
		if field == nil {
			if format == "json" {
				_, err := io.WriteString(w, "{}\n")
				return err
			}
			_, err := fmt.Fprintf(w, "No field found containing offset 0x%x (%d)\n", *offsetFilter, *offsetFilter)
			return err
		}

		if format == "json" {
			return WriteJSON(w, field)
		}

		// Text format for single field: print a detailed view
		return printDetailedField(w, field)
	}

	// 2. Full map output
	if format == "json" {
		return WriteJSON(w, pm)
	}

	// Default: Text format table
	return printExplainTable(w, pm)
}

// FindFieldAtOffset locates the PrimitiveField that covers the given offset.
func FindFieldAtOffset(pm *model.PrimitiveMap, offset uint32) *model.PrimitiveField {
	for _, f := range pm.Fields {
		if offset >= f.Offset && offset < f.Offset+f.Size {
			return f
		}
	}
	return nil
}

func printDetailedField(w io.Writer, f *model.PrimitiveField) error {
	var err error
	_, err = fmt.Fprintf(w, "%s\n", c(bold, fmt.Sprintf("Field Details at Offset 0x%08x:", f.Offset)))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, strings.Repeat("-", 60))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%-14s %s\n", "Logical Path:", c(bold, f.LogicalPath))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%-14s 0x%08x (%d)\n", "Offset:", f.Offset, f.Offset)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%-14s %d bytes\n", "Size:", f.Size)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%-14s %s\n", "Type:", c(colorForType(f.Type), string(f.Type)))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%-14s %s\n", "Raw Bytes:", hexDumpRaw(f.RawBytes))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%-14s %s\n", "Value:", formatValue(f))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%-14s %s\n", "Summary:", f.Summary)
	if err != nil {
		return err
	}
	if f.Description != "" {
		_, err = fmt.Fprintf(w, "%-14s %s\n", "Description:", f.Description)
		if err != nil {
			return err
		}
	}
	return nil
}

func printExplainTable(w io.Writer, pm *model.PrimitiveMap) error {
	// Print Header
	_, err := fmt.Fprintf(w, "%-12s%-25s%-15s%s\n", "[Offset]", "[Hex Dump]", "[Primitive]", "[Field Path / Explanation]")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, strings.Repeat("-", 99))
	if err != nil {
		return err
	}

	for _, f := range pm.Fields {
		offsetStr := c(dim, fmt.Sprintf("0x%08x", f.Offset))
		hexDump := hexDumpPreview(f.RawBytes)
		primType := string(f.Type)
		valStr := formatValue(f)

		// For Offset, it is colored. Its uncolored length is 10. We print colored offset and 2 spaces.
		offsetPart := fmt.Sprintf("%s  ", offsetStr)
		
		// For Hex Dump, we pad the uncolored string to 23 chars, then add 2 spaces.
		hexPart := fmt.Sprintf("%-23s  ", hexDump)
		
		// For Primitive, we pad the uncolored type string to 13 chars, then color it, then add 2 spaces.
		primPart := fmt.Sprintf("%s  ", c(colorForType(f.Type), fmt.Sprintf("%-13s", primType)))

		// Path is padded to 27 chars, then print value
		_, err = fmt.Fprintf(w, "%s%s%s%-27s -> %s\n", offsetPart, hexPart, primPart, f.LogicalPath, valStr)
		if err != nil {
			return err
		}
	}
	return nil
}

func colorForType(t model.PrimitiveType) string {
	switch t {
	case model.TypeMagic:
		return boldCyn
	case model.TypeCString, model.TypeString:
		return green
	case model.TypeUint8, model.TypeUint16LE, model.TypeUint32LE, model.TypeUint64LE:
		return cyan
	case model.TypeLeb128, model.TypeUleb128:
		return yellow
	case model.TypePadding:
		return dim
	case model.TypeBytes:
		return white
	default:
		return white
	}
}

func hexDumpPreview(bytes []byte) string {
	if len(bytes) == 0 {
		return ""
	}
	if len(bytes) <= 8 {
		var parts []string
		for _, b := range bytes {
			parts = append(parts, fmt.Sprintf("%02x", b))
		}
		return strings.Join(parts, " ")
	}
	// For longer, print first 7 bytes + "..."
	var parts []string
	for i := 0; i < 7; i++ {
		parts = append(parts, fmt.Sprintf("%02x", bytes[i]))
	}
	return strings.Join(parts, " ") + " ..."
}

func hexDumpRaw(bytes []byte) string {
	var parts []string
	for _, b := range bytes {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, " ")
}

func formatValue(f *model.PrimitiveField) string {
	if f == nil {
		return ""
	}

	// 1. Special cases based on LogicalPath
	if f.LogicalPath == "vdex.header.magic" {
		if val, ok := f.ParsedValue.(string); ok {
			if val == "vdex" {
				return fmt.Sprintf("%q (Valid)", val)
			}
			return fmt.Sprintf("%q (Invalid)", val)
		}
	}
	if f.LogicalPath == "vdex.header.version" {
		var ver string
		if bytesVal, ok := f.ParsedValue.([]byte); ok {
			ver = string(trimNullsCopy(bytesVal))
		} else if strVal, ok := f.ParsedValue.(string); ok {
			ver = string(trimNullsCopy([]byte(strVal)))
		}
		if ver != "" {
			switch ver {
			case "006":
				return fmt.Sprintf("%q (Android 8.0/8.1)", ver)
			case "019":
				return fmt.Sprintf("%q (Android 9/10)", ver)
			case "021":
				return fmt.Sprintf("%q (Android 11)", ver)
			case "027":
				return fmt.Sprintf("%q (Android 12+)", ver)
			default:
				return fmt.Sprintf("%q", ver)
			}
		}
	}
	if f.LogicalPath == "vdex.header.sections" {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("%d sections", val)
		}
	}
	if strings.HasSuffix(f.LogicalPath, ".kind") {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("%d (%s)", val, sectionKindName(uint32(val)))
		}
	}
	if strings.HasSuffix(f.LogicalPath, ".offset") {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("0x%x (Start offset)", val)
		}
	}
	if strings.HasSuffix(f.LogicalPath, ".size") {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("%d bytes (Section size)", val)
		}
	}
	if strings.HasPrefix(f.LogicalPath, "vdex.checksums[") {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("0x%08x", val)
		}
	}
	if strings.HasSuffix(f.LogicalPath, ".file_size") {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("%d bytes (File size)", val)
		}
	}
	if strings.HasSuffix(f.LogicalPath, ".class_defs_size") {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("%d classes", val)
		}
	}
	if strings.Contains(f.LogicalPath, ".class_offsets[") {
		if val, ok := convertToUint64(f.ParsedValue); ok {
			if uint32(val) == 0xFFFFFFFF {
				return "0xffffffff (Not verified)"
			}
			return fmt.Sprintf("0x%x", val)
		}
	}
	if strings.Contains(f.LogicalPath, ".extra_strings[") {
		if val, ok := f.ParsedValue.(string); ok {
			return fmt.Sprintf("%q", val)
		}
	}
	if f.LogicalPath == "vdex.gap" {
		return f.Summary
	}

	// 2. Generic formatting based on Type
	switch f.Type {
	case model.TypeMagic:
		if val, ok := f.ParsedValue.(string); ok {
			return fmt.Sprintf("%q", val)
		}
	case model.TypeCString:
		if val, ok := f.ParsedValue.(string); ok {
			return fmt.Sprintf("%q", val)
		}
	case model.TypeString:
		if val, ok := f.ParsedValue.(string); ok {
			return fmt.Sprintf("%q", val)
		}
	case model.TypeUint8, model.TypeUint16LE, model.TypeUint32LE, model.TypeUint64LE, model.TypeLeb128, model.TypeUleb128:
		if val, ok := convertToUint64(f.ParsedValue); ok {
			return fmt.Sprintf("%d", val)
		}
	case model.TypePadding:
		return f.Summary
	case model.TypeBytes:
		if bytesVal, ok := f.ParsedValue.([]byte); ok {
			if isPrintable(bytesVal) {
				return fmt.Sprintf("%q", string(bytesVal))
			}
			if f.Summary != "" {
				return f.Summary
			}
			return fmt.Sprintf("%d bytes", len(bytesVal))
		}
	}

	// Fallback
	if f.ParsedValue != nil {
		return fmt.Sprintf("%v", f.ParsedValue)
	}
	return f.Summary
}

func sectionKindName(kind uint32) string {
	switch kind {
	case 0:
		return "kChecksumSection"
	case 1:
		return "kDexSection"
	case 2:
		return "kVerifierDepsSection"
	case 3:
		return "kTypeLookupTableSection"
	default:
		return "kUnknownSection"
	}
}

func convertToUint64(val any) (uint64, bool) {
	switch v := val.(type) {
	case uint8:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int8:
		return uint64(v), true
	case int16:
		return uint64(v), true
	case int32:
		return uint64(v), true
	case int64:
		return uint64(v), true
	case int:
		return uint64(v), true
	}
	return 0, false
}

func isPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func trimNullsCopy(b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			return b[:i+1]
		}
	}
	return b[:0]
}

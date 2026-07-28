package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

const maxExplainSections = 64

// accessFlagsDescription returns a human-readable description of DEX class access_flags.
// See https://source.android.com/docs/core/runtime/dex-format#access-flags
func accessFlagsDescription(flags uint32) string {
	const (
		accPublic               = 0x0001
		accPrivate              = 0x0002
		accProtected            = 0x0004
		accStatic               = 0x0008
		accFinal                = 0x0010
		accSynchronized         = 0x0020 // for methods
		accVolatile             = 0x0040 // for fields
		accBridge               = 0x0040 // for methods
		accTransient            = 0x0080 // for fields
		accVarargs              = 0x0080 // for methods
		accNative               = 0x0100
		accInterface            = 0x0200
		accAbstract             = 0x0400
		accStrict               = 0x0800
		accSynthetic            = 0x1000
		accAnnotation           = 0x2000
		accEnum                 = 0x4000
		accConstructor          = 0x10000
		accDeclaredSynchronized = 0x20000
	)
	type flag struct {
		bit  uint32
		name string
	}
	knownFlags := []flag{
		{accPublic, "PUBLIC"}, {accPrivate, "PRIVATE"}, {accProtected, "PROTECTED"},
		{accStatic, "STATIC"}, {accFinal, "FINAL"}, {accSynchronized, "SYNCHRONIZED"},
		{accVolatile, "VOLATILE/BRIDGE"}, {accTransient, "TRANSIENT/VARARGS"},
		{accNative, "NATIVE"}, {accInterface, "INTERFACE"}, {accAbstract, "ABSTRACT"},
		{accStrict, "STRICT"}, {accSynthetic, "SYNTHETIC"}, {accAnnotation, "ANNOTATION"},
		{accEnum, "ENUM"}, {accConstructor, "CONSTRUCTOR"},
		{accDeclaredSynchronized, "DECLARED_SYNCHRONIZED"},
	}
	var parts []string
	for _, f := range knownFlags {
		if flags&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	unknown := flags
	for _, f := range knownFlags {
		unknown &^= f.bit
	}
	desc := fmt.Sprintf("access_flags=0x%04x", flags)
	if len(parts) > 0 {
		desc += " [" + strings.Join(parts, "|") + "]"
	}
	if unknown != 0 {
		desc += fmt.Sprintf(" (unknown_bits=0x%x)", unknown)
	}
	return desc
}

type AnnotatedReader struct {
	data   []byte
	offset uint32
	fields []*model.PrimitiveField
}

func (r *AnnotatedReader) canRead(size uint32) bool {
	return uint64(r.offset)+uint64(size) <= uint64(len(r.data))
}

func NewAnnotatedReader(data []byte) *AnnotatedReader {
	return &AnnotatedReader{data: data, offset: 0}
}

func (r *AnnotatedReader) SetOffset(off uint32) {
	r.offset = off
}

func (r *AnnotatedReader) Offset() uint32 {
	return r.offset
}

func (r *AnnotatedReader) Len() uint32 {
	return uint32(len(r.data))
}

func (r *AnnotatedReader) ReadMagic(size int, path string, summary string, desc string) string {
	if size <= 0 || uint64(size) > uint64(^uint32(0)) || !r.canRead(uint32(size)) {
		return ""
	}
	end := r.offset + uint32(size)
	val := string(r.data[r.offset:end])
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        uint32(size),
		Type:        model.TypeMagic,
		RawBytes:    r.data[r.offset:end],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += uint32(size)
	return val
}

func (r *AnnotatedReader) ReadUint8(path string, summary string, desc string) uint8 {
	if !r.canRead(1) {
		return 0
	}
	val := r.data[r.offset]
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        1,
		Type:        model.TypeUint8,
		RawBytes:    r.data[r.offset : r.offset+1],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += 1
	return val
}

func (r *AnnotatedReader) ReadUint16LE(path string, summary string, desc string) uint16 {
	if !r.canRead(2) {
		return 0
	}
	val := binary.LittleEndian.Uint16(r.data[r.offset : r.offset+2])
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        2,
		Type:        model.TypeUint16LE,
		RawBytes:    r.data[r.offset : r.offset+2],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += 2
	return val
}

func (r *AnnotatedReader) ReadUint32LE(path string, summary string, desc string) uint32 {
	if !r.canRead(4) {
		return 0
	}
	val := binary.LittleEndian.Uint32(r.data[r.offset : r.offset+4])
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        4,
		Type:        model.TypeUint32LE,
		RawBytes:    r.data[r.offset : r.offset+4],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += 4
	return val
}

func (r *AnnotatedReader) ReadUint64LE(path string, summary string, desc string) uint64 {
	if !r.canRead(8) {
		return 0
	}
	val := binary.LittleEndian.Uint64(r.data[r.offset : r.offset+8])
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        8,
		Type:        model.TypeUint64LE,
		RawBytes:    r.data[r.offset : r.offset+8],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += 8
	return val
}

func (r *AnnotatedReader) ReadUleb128(path string, summary string, desc string) (uint32, int) {
	if !r.canRead(1) {
		return 0, 0
	}
	val, bytesRead, err := binutil.ReadULEB128(r.data, int(r.offset))
	if err != nil {
		// Do NOT advance r.offset on error; caller must check bytesRead==0 and break.
		return 0, 0
	}
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        uint32(bytesRead),
		Type:        model.TypeUleb128,
		RawBytes:    r.data[r.offset : r.offset+uint32(bytesRead)],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += uint32(bytesRead)
	return val, bytesRead
}

// ReadCStringBounded reads a null-terminated C string but restricts its search
// to maxOffset, preventing it from crossing section boundaries (BUG-H2 fix).
func (r *AnnotatedReader) ReadCStringBounded(maxOffset uint32, path string, summary string, desc string) string {
	if r.offset >= uint32(len(r.data)) {
		return ""
	}
	// Clamp maxOffset to the actual data length.
	if maxOffset > uint32(len(r.data)) {
		maxOffset = uint32(len(r.data))
	}
	if r.offset >= maxOffset {
		return ""
	}
	// Search only within [r.offset, maxOffset) — never crosses section boundary.
	nullIdx := bytes.IndexByte(r.data[r.offset:maxOffset], 0)
	var size uint32
	var val string
	if nullIdx < 0 {
		size = maxOffset - r.offset
		val = string(r.data[r.offset:maxOffset])
	} else {
		size = uint32(nullIdx) + 1
		val = string(r.data[r.offset : r.offset+uint32(nullIdx)])
	}
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        size,
		Type:        model.TypeCString,
		RawBytes:    r.data[r.offset : r.offset+size],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += size
	return val
}

func (r *AnnotatedReader) ReadBytes(size int, path string, summary string, desc string) []byte {
	if size <= 0 {
		return nil
	}
	if uint64(r.offset) >= uint64(len(r.data)) {
		return nil
	}
	remaining := len(r.data) - int(r.offset)
	if size > remaining {
		size = remaining
	}
	end := r.offset + uint32(size)
	val := r.data[r.offset:end]
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        uint32(size),
		Type:        model.TypeBytes,
		RawBytes:    val,
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += uint32(size)
	return val
}

func (r *AnnotatedReader) Align4(path string) {
	aligned := (uint64(r.offset) + 3) &^ uint64(3)
	if aligned > uint64(len(r.data)) || aligned > uint64(^uint32(0)) {
		return
	}
	newOffset := uint32(aligned)
	padSize := newOffset - r.offset
	if padSize > 0 && newOffset <= uint32(len(r.data)) {
		r.fields = append(r.fields, &model.PrimitiveField{
			Offset:      r.offset,
			Size:        padSize,
			Type:        model.TypePadding,
			RawBytes:    r.data[r.offset:newOffset],
			ParsedValue: nil,
			LogicalPath: path,
			Summary:     "4-byte alignment padding",
			Description: "Zero-padding to align subsequent structures on a 4-byte boundary.",
		})
		r.offset = newOffset
	}
}

type sectionInfo struct {
	kind   uint32
	offset uint32
	size   uint32
}

func validateExplainSections(fileSize int, headerEnd uint64, sections []sectionInfo) error {
	nonEmpty := make([]sectionInfo, 0, len(sections))
	seenKinds := make(map[uint32]struct{}, len(sections))
	for _, section := range sections {
		if _, exists := seenKinds[section.kind]; exists {
			return fmt.Errorf("duplicate VDEX section kind %d", section.kind)
		}
		seenKinds[section.kind] = struct{}{}
		if section.size == 0 {
			continue
		}
		end := uint64(section.offset) + uint64(section.size)
		if uint64(section.offset) < headerEnd {
			return fmt.Errorf("VDEX section kind %d overlaps the header/table", section.kind)
		}
		if end > uint64(fileSize) {
			return fmt.Errorf(
				"VDEX section kind %d exceeds file bounds: offset=%#x size=%#x",
				section.kind, section.offset, section.size,
			)
		}
		nonEmpty = append(nonEmpty, section)
	}

	sort.Slice(nonEmpty, func(i, j int) bool {
		if nonEmpty[i].offset == nonEmpty[j].offset {
			return nonEmpty[i].size < nonEmpty[j].size
		}
		return nonEmpty[i].offset < nonEmpty[j].offset
	})
	for i := 1; i < len(nonEmpty); i++ {
		previous := nonEmpty[i-1]
		current := nonEmpty[i]
		if uint64(current.offset) < uint64(previous.offset)+uint64(previous.size) {
			return fmt.Errorf(
				"VDEX section kind %d overlaps section kind %d",
				current.kind, previous.kind,
			)
		}
	}
	return nil
}

func validateExplainDexTable(name string, offset, count, itemSize, dexSize uint32) error {
	if count == 0 {
		return nil
	}
	if count > maxExplainCollectionItems {
		return fmt.Errorf("DEX %s count %d exceeds explain limit %d", name, count, maxExplainCollectionItems)
	}
	if offset == 0 {
		return fmt.Errorf("DEX %s has non-zero count %d with zero offset", name, count)
	}
	end := uint64(offset) + uint64(count)*uint64(itemSize)
	if end > uint64(dexSize) {
		return fmt.Errorf(
			"DEX %s table exceeds file bounds: offset=%#x count=%d item_size=%d file_size=%#x",
			name, offset, count, itemSize, dexSize,
		)
	}
	return nil
}

func validDexVersion(raw string) bool {
	if len(raw) != 4 || raw[3] != 0 {
		return false
	}
	switch raw[:3] {
	case "035", "037", "038", "039", "040", "041":
		return true
	default:
		return false
	}
}

// ExplainVdexBytes parses raw VDEX bytes and returns a byte-level annotated field map.
// Every byte in data is accounted for in the returned PrimitiveMap.
// This is the primary entry point and is compatible with all build targets including WASM.
func ExplainVdexBytes(data []byte) (*model.PrimitiveMap, error) {
	raw := data
	if uint64(len(raw)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("file exceeds the VDEX uint32 offset limit")
	}

	if len(raw) < 12 {
		return nil, fmt.Errorf("file too small for VDEX header (%d bytes, need 12)", len(raw))
	}

	r := NewAnnotatedReader(raw)

	// 1. VdexHeader
	magic := r.ReadMagic(4, "vdex.header.magic", "VDEX magic signature", "Identifies the file as a VDEX file.")
	if magic != "vdex" {
		return nil, fmt.Errorf("invalid VDEX magic signature: %q", magic)
	}

	// BUG-M1 fix: version field should be TypeMagic, not TypeBytes.
	versionMagic := r.ReadMagic(4, "vdex.header.version", "VDEX version number", "The version of the VDEX format.")
	versionStr := string(trimNulls([]byte(versionMagic)))

	// I-02 fix: Legacy VDEX (v021-026) has a different 28-byte header layout where
	// offset[8:12] is dexSectionVersion, NOT numSections. Reading it as numSections
	// would produce millions of garbage sections. Reject legacy files explicitly.
	if IsLegacyVersion(versionStr) {
		return nil, fmt.Errorf(
			"ExplainVdex: legacy VDEX v%s is not supported by byte-level explain; use 'vdexcli parse' for legacy format",
			versionStr,
		)
	}
	if versionStr != model.VdexCurrentVersion {
		return nil, fmt.Errorf(
			"ExplainVdex: unsupported VDEX version %q (supported: %s)",
			versionStr, model.VdexCurrentVersion,
		)
	}

	numSections := r.ReadUint32LE("vdex.header.sections", "Number of sections", "Total number of sections defined in the section table.")
	if numSections > maxExplainSections {
		return nil, fmt.Errorf("VDEX section count %d exceeds explain limit %d", numSections, maxExplainSections)
	}

	// 2. Section Headers Table
	// BUG-H3 fix: use uint64 arithmetic to prevent uint32 overflow when numSections is large.
	headerEnd64 := uint64(12) + uint64(numSections)*12
	if headerEnd64 > uint64(len(raw)) {
		return nil, fmt.Errorf("file too small for section table (%d bytes, need %d)", len(raw), headerEnd64)
	}

	sectionMap := make(map[uint32]sectionInfo)
	sections := make([]sectionInfo, 0, numSections)
	for i := uint32(0); i < numSections; i++ {
		kind := r.ReadUint32LE(fmt.Sprintf("vdex.sections[%d].kind", i), "Section kind", fmt.Sprintf("The identifier of the section type for section %d.", i))
		offset := r.ReadUint32LE(fmt.Sprintf("vdex.sections[%d].offset", i), "Section offset", fmt.Sprintf("File offset where section %d starts.", i))
		size := r.ReadUint32LE(fmt.Sprintf("vdex.sections[%d].size", i), "Section size", fmt.Sprintf("The size in bytes of section %d.", i))

		section := sectionInfo{kind: kind, offset: offset, size: size}
		sections = append(sections, section)
		if _, exists := sectionMap[kind]; !exists {
			sectionMap[kind] = section
		}
	}
	if err := validateExplainSections(len(raw), headerEnd64, sections); err != nil {
		return nil, err
	}
	// 3. Checksums Section (kind 0)
	var checksumsCount int
	var checksumValues []uint32
	if cs, ok := sectionMap[0]; ok && cs.size > 0 && validByteRange(len(raw), cs.offset, cs.size) {
		r.SetOffset(cs.offset)
		count := cs.size / 4
		if count > maxExplainCollectionItems {
			return nil, fmt.Errorf("VDEX checksum count %d exceeds explain limit %d", count, maxExplainCollectionItems)
		}
		checksumsCount = int(count)
		for i := uint32(0); i < count; i++ {
			checksum := r.ReadUint32LE(
				fmt.Sprintf("vdex.checksums[%d]", i),
				fmt.Sprintf("DEX[%d] checksum", i),
				fmt.Sprintf("The location checksum for the DEX file at index %d.", i),
			)
			checksumValues = append(checksumValues, checksum)
		}
		// BUG-M4 fix: emit TypePadding for remainder bytes when size % 4 != 0.
		remainder := cs.size % 4
		if remainder != 0 {
			r.fields = append(r.fields, &model.PrimitiveField{
				Offset:      r.offset,
				Size:        remainder,
				Type:        model.TypePadding,
				RawBytes:    raw[r.offset : r.offset+remainder],
				ParsedValue: nil,
				LogicalPath: "vdex.checksums.padding",
				Summary:     "Checksum section trailing padding",
				Description: fmt.Sprintf("Trailing %d byte(s) of checksum section not aligned to 4 bytes.", remainder),
			})
			r.offset += remainder
		}
	}

	// 4. DEX Section (kind 1)
	var dexDefs []uint32
	dexPreviews := make([]model.DexPreview, len(checksumValues))
	for index := range checksumValues {
		checksum := checksumValues[index]
		dexPreviews[index] = model.DexPreview{Index: index, LocationChecksum: &checksum}
	}
	if ds, ok := sectionMap[1]; ok && ds.size > 0 && validByteRange(len(raw), ds.offset, ds.size) {
		sectionEnd := uint64(ds.offset) + uint64(ds.size)
		cursor := ds.offset
		dexIdx := 0
		expectedDexCount := checksumsCount

		for (expectedDexCount == 0 && uint64(cursor) < sectionEnd) || (expectedDexCount > 0 && dexIdx < expectedDexCount) {
			r.SetOffset(cursor)
			r.Align4(fmt.Sprintf("vdex.dexes.align[%d]", dexIdx))
			cursor = r.Offset()

			if uint64(cursor)+112 > sectionEnd {
				break
			}

			dexStart := cursor

			// BUG-M3 fix: parse DEX magic (4B) and version (4B) as separate TypeMagic fields.
			dexMagicStr := r.ReadMagic(4, fmt.Sprintf("vdex.dex[%d].header.magic", dexIdx), "DEX magic signature", "Identifies the file as a DEX file (must be 'dex\\n').")
			dexVersion := r.ReadMagic(4, fmt.Sprintf("vdex.dex[%d].header.version", dexIdx), "DEX version", "DEX format version (e.g. '035\\x00').")
			if !bytes.HasPrefix([]byte(dexMagicStr), []byte("dex\n")) {
				return nil, fmt.Errorf("dex[%d] at %#x has invalid magic %q", dexIdx, dexStart, dexMagicStr)
			}
			if !validDexVersion(dexVersion) {
				return nil, fmt.Errorf("dex[%d] at %#x has invalid version %q", dexIdx, dexStart, dexVersion)
			}

			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.checksum", dexIdx), "DEX checksum", "Adler32 checksum of the DEX file.")
			_ = r.ReadBytes(20, fmt.Sprintf("vdex.dex[%d].header.signature", dexIdx), "DEX SHA-1 signature", "SHA-1 signature of the DEX file (20 bytes).")
			fileSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.file_size", dexIdx), "DEX file size", "Declared size of the DEX file in bytes.")
			headerSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.header_size", dexIdx), "DEX header size", "Size of the DEX header in bytes (typically 112).")
			endianTag := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.endian_tag", dexIdx), "DEX endian tag", "Endianness tag (0x12345678 = little-endian).")
			linkSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.link_size", dexIdx), "DEX link size", "Size of the link section in bytes (0 if unused).")
			linkOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.link_off", dexIdx), "DEX link offset", "File offset of the link section (0 if unused).")
			mapOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.map_off", dexIdx), "DEX map offset", "File offset of the map_list item.")
			stringIdsSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.string_ids_size", dexIdx), "DEX string IDs count", "Number of elements in the string identifiers list.")
			stringIdsOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.string_ids_off", dexIdx), "DEX string IDs offset", "Offset from start of the file to the string identifiers list.")
			typeIdsSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.type_ids_size", dexIdx), "DEX type IDs count", "Number of elements in the type identifiers list.")
			typeIdsOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.type_ids_off", dexIdx), "DEX type IDs offset", "Offset from start of the file to the type identifiers list.")
			protoIdsSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.proto_ids_size", dexIdx), "DEX proto IDs count", "Number of elements in the method prototype identifiers list.")
			protoIdsOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.proto_ids_off", dexIdx), "DEX proto IDs offset", "Offset from start of the file to the proto identifiers list.")
			fieldIdsSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.field_ids_size", dexIdx), "DEX field IDs count", "Number of elements in the field identifiers list.")
			fieldIdsOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.field_ids_off", dexIdx), "DEX field IDs offset", "Offset from start of the file to the field identifiers list.")
			methodIdsSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.method_ids_size", dexIdx), "DEX method IDs count", "Number of elements in the method identifiers list.")
			methodIdsOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.method_ids_off", dexIdx), "DEX method IDs offset", "Offset from start of the file to the method identifiers list.")
			classDefsSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.class_defs_size", dexIdx), "DEX class defs count", "Number of elements in the class definitions list.")
			classDefsOff := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.class_defs_off", dexIdx), "DEX class defs offset", "Offset from start of the file to the class definitions list.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.data_size", dexIdx), "DEX data size", "Size of the data section in bytes.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.data_off", dexIdx), "DEX data offset", "Offset from start of the file to the data section.")

			if fileSize < 112 {
				return nil, fmt.Errorf("dex[%d] at %#x has invalid file_size %#x", dexIdx, dexStart, fileSize)
			}
			available := sectionEnd - uint64(dexStart)
			if uint64(fileSize) > available {
				return nil, fmt.Errorf(
					"dex[%d] at %#x declares file_size %#x with only %#x bytes available",
					dexIdx, dexStart, fileSize, available,
				)
			}
			effectiveSize := fileSize
			dexDefs = append(dexDefs, classDefsSize)

			if headerSize != 112 {
				return nil, fmt.Errorf("dex[%d] at %#x has unsupported header_size %#x", dexIdx, dexStart, headerSize)
			}
			if endianTag != 0x12345678 {
				return nil, fmt.Errorf("dex[%d] at %#x has unsupported endian tag %#x", dexIdx, dexStart, endianTag)
			}
			for _, table := range []struct {
				name                string
				offset, count, size uint32
			}{
				{"string_ids", stringIdsOff, stringIdsSize, 4},
				{"type_ids", typeIdsOff, typeIdsSize, 4},
				{"proto_ids", protoIdsOff, protoIdsSize, 12},
				{"field_ids", fieldIdsOff, fieldIdsSize, 8},
				{"method_ids", methodIdsOff, methodIdsSize, 8},
				{"class_defs", classDefsOff, classDefsSize, 32},
			} {
				if err := validateExplainDexTable(table.name, table.offset, table.count, table.size, effectiveSize); err != nil {
					return nil, fmt.Errorf("dex[%d] at %#x: %w", dexIdx, dexStart, err)
				}
			}
			if linkSize > 0 {
				if linkOff == 0 || uint64(linkOff)+uint64(linkSize) > uint64(effectiveSize) {
					return nil, fmt.Errorf(
						"dex[%d] at %#x has invalid link range offset=%#x size=%#x",
						dexIdx, dexStart, linkOff, linkSize,
					)
				}
			}
			if mapOff > 0 && uint64(mapOff)+4 > uint64(effectiveSize) {
				return nil, fmt.Errorf("dex[%d] at %#x has invalid map_off %#x", dexIdx, dexStart, mapOff)
			}

			// Delegate DEX payload annotation and semantic preview extraction to
			// explain_dex.go so the byte map and interpreter use the same bounds.
			params := dexPayloadParams{
				raw:           raw,
				r:             r,
				dexIdx:        dexIdx,
				dexStart:      dexStart,
				effectiveSize: effectiveSize,
				headerSize:    headerSize,
				stringIdsOff:  stringIdsOff,
				stringIdsSize: stringIdsSize,
				typeIdsOff:    typeIdsOff,
				typeIdsSize:   typeIdsSize,
				protoIdsOff:   protoIdsOff,
				protoIdsSize:  protoIdsSize,
				fieldIdsOff:   fieldIdsOff,
				fieldIdsSize:  fieldIdsSize,
				methodIdsOff:  methodIdsOff,
				methodIdsSize: methodIdsSize,
				classDefsOff:  classDefsOff,
				classDefsSize: classDefsSize,
				linkOff:       linkOff,
				linkSize:      linkSize,
				mapOff:        mapOff,
			}
			preview := buildDexPreview(params)
			if dexIdx < len(checksumValues) {
				checksum := checksumValues[dexIdx]
				preview.LocationChecksum = &checksum
			}
			if dexIdx < len(dexPreviews) {
				dexPreviews[dexIdx] = preview
			} else {
				dexPreviews = append(dexPreviews, preview)
			}
			annotateDexPayload(params)

			nextCursor := uint64(dexStart) + uint64(effectiveSize)
			if nextCursor <= uint64(cursor) || nextCursor > sectionEnd {
				break
			}
			cursor = uint32(nextCursor)
			dexIdx++
		}
	}

	// 5. VerifierDeps Section (kind 2)
	if vs, ok := sectionMap[2]; ok && vs.size > 0 && validByteRange(len(raw), vs.offset, vs.size) {
		sectionStart := int(vs.offset)
		sectionEnd := sectionStart + int(vs.size)
		r.SetOffset(vs.offset)

		expectedDexCount := checksumsCount
		if expectedDexCount == 0 {
			expectedDexCount = len(dexDefs)
		}
		if expectedDexCount > maxExplainCollectionItems {
			return nil, fmt.Errorf(
				"verifier DEX count %d exceeds explain limit %d",
				expectedDexCount, maxExplainCollectionItems,
			)
		}
		indexBytes := uint64(expectedDexCount) * 4
		if indexBytes > uint64(vs.size) {
			return nil, fmt.Errorf(
				"verifier DEX offset table needs %d bytes, section has %d",
				indexBytes, vs.size,
			)
		}

		var dexBlockOffsets []uint32
		for i := 0; i < expectedDexCount; i++ {
			off := r.ReadUint32LE(
				fmt.Sprintf("vdex.verifier.dex_offsets[%d]", i),
				"Verifier DEX offset",
				fmt.Sprintf("Section-absolute offset to the verifier dependency block for DEX %d.", i),
			)
			dexBlockOffsets = append(dexBlockOffsets, off)
		}
		for i, relative := range dexBlockOffsets {
			if uint64(relative) < indexBytes || relative >= vs.size {
				return nil, fmt.Errorf(
					"verifier dex[%d] block offset %#x is outside payload range [%#x,%#x)",
					i, relative, indexBytes, vs.size,
				)
			}
			if relative%4 != 0 {
				return nil, fmt.Errorf("verifier dex[%d] block offset %#x is not 4-byte aligned", i, relative)
			}
			if i > 0 && relative <= dexBlockOffsets[i-1] {
				return nil, fmt.Errorf("verifier DEX block offsets are not strictly increasing at dex %d", i)
			}
		}

		for i, relative := range dexBlockOffsets {
			blockOff := sectionStart + int(relative)
			blockEnd := sectionEnd
			if i+1 < len(dexBlockOffsets) {
				blockEnd = sectionStart + int(dexBlockOffsets[i+1])
			}

			var numClass int
			if i < len(dexDefs) {
				if dexDefs[i] > maxExplainCollectionItems {
					return nil, fmt.Errorf(
						"verifier dex[%d] class count %d exceeds explain limit %d",
						i, dexDefs[i], maxExplainCollectionItems,
					)
				}
				numClass = int(dexDefs[i])
			}

			if numClass == 0 {
				numClass = inferClassCount(raw, sectionStart, blockOff, blockEnd)
			}
			if numClass > maxExplainCollectionItems {
				return nil, fmt.Errorf(
					"verifier dex[%d] inferred class count %d exceeds explain limit %d",
					i, numClass, maxExplainCollectionItems,
				)
			}
			classTableBytes := uint64(numClass+1) * 4
			if uint64(blockOff)+classTableBytes > uint64(blockEnd) {
				return nil, fmt.Errorf("verifier dex[%d] class offset table exceeds its block", i)
			}

			r.SetOffset(uint32(blockOff))

			var classOffsets []uint32
			for c := 0; c <= numClass; c++ {
				off := r.ReadUint32LE(
					fmt.Sprintf("vdex.verifier.dex[%d].class_offsets[%d]", i, c),
					"Class verifier offset",
					fmt.Sprintf("Section-absolute offset to assignability pairs for class %d.", c),
				)
				classOffsets = append(classOffsets, off)
			}

			maxSetEnd := blockOff + 4*(numClass+1)
			nextValid := 1
			for classIdx := 0; classIdx < numClass; classIdx++ {
				o := classOffsets[classIdx]
				if o == model.NotVerifiedMarker {
					continue
				}

				for nextValid <= classIdx || (nextValid <= numClass && classOffsets[nextValid] == model.NotVerifiedMarker) {
					nextValid++
				}
				if nextValid > numClass {
					break
				}

				setStart := sectionStart + int(o)
				setEnd := sectionStart + int(classOffsets[nextValid])
				if setStart < blockOff+4*(numClass+1) || setEnd > blockEnd || setEnd < setStart {
					return nil, fmt.Errorf(
						"verifier dex[%d] class[%d] has malformed set bounds [%#x,%#x)",
						i, classIdx, setStart, setEnd,
					)
				}

				if setStart > maxSetEnd {
					maxSetEnd = setStart
				}

				r.SetOffset(uint32(setStart))
				pairIdx := 0
				for r.Offset() < uint32(setEnd) {
					if _, _, err := binutil.ReadULEB128(raw[:setEnd], int(r.Offset())); err != nil {
						return nil, fmt.Errorf(
							"verifier dex[%d] class[%d] pair[%d] destination exceeds set bounds",
							i, classIdx, pairIdx,
						)
					}
					_, destN := r.ReadUleb128(
						fmt.Sprintf("vdex.verifier.dex[%d].class[%d].pair[%d].dest", i, classIdx, pairIdx),
						"Destination type index",
						"The destination type index for assignability verification.",
					)
					if destN == 0 || r.Offset() >= uint32(setEnd) {
						return nil, fmt.Errorf(
							"verifier dex[%d] class[%d] pair[%d] is missing a bounded source",
							i, classIdx, pairIdx,
						)
					}
					if _, _, err := binutil.ReadULEB128(raw[:setEnd], int(r.Offset())); err != nil {
						return nil, fmt.Errorf(
							"verifier dex[%d] class[%d] pair[%d] source exceeds set bounds",
							i, classIdx, pairIdx,
						)
					}
					_, srcN := r.ReadUleb128(
						fmt.Sprintf("vdex.verifier.dex[%d].class[%d].pair[%d].src", i, classIdx, pairIdx),
						"Source type index",
						"The source type index for assignability verification.",
					)
					if srcN == 0 || r.Offset() > uint32(setEnd) {
						return nil, fmt.Errorf(
							"verifier dex[%d] class[%d] pair[%d] source exceeds set bounds",
							i, classIdx, pairIdx,
						)
					}
					pairIdx++
				}

				if setEnd > maxSetEnd {
					maxSetEnd = setEnd
				}
			}

			r.SetOffset(uint32(maxSetEnd))
			r.Align4(fmt.Sprintf("vdex.verifier.dex[%d].align", i))

			cursor := int(r.Offset())
			if cursor > blockEnd {
				return nil, fmt.Errorf("verifier dex[%d] pair data exceeds its block", i)
			}
			if cursor+4 <= blockEnd {
				numStrings := r.ReadUint32LE(
					fmt.Sprintf("vdex.verifier.dex[%d].num_extra_strings", i),
					"Extra strings count",
					"Number of extra strings in the verifier deps block.",
				)
				if numStrings > maxExplainCollectionItems {
					return nil, fmt.Errorf(
						"verifier dex[%d] extra string count %d exceeds explain limit %d",
						i, numStrings, maxExplainCollectionItems,
					)
				}
				if uint64(r.Offset())+uint64(numStrings)*4 > uint64(blockEnd) {
					return nil, fmt.Errorf("verifier dex[%d] extra string offset table exceeds its block", i)
				}

				var extraStringOffsets []uint32
				for s := uint32(0); s < numStrings; s++ {
					off := r.ReadUint32LE(
						fmt.Sprintf("vdex.verifier.dex[%d].extra_string_offsets[%d]", i, s),
						"Extra string offset",
						"Section-absolute offset to the extra string.",
					)
					extraStringOffsets = append(extraStringOffsets, off)
				}

				seenExtraOffsets := make(map[uint32]struct{}, len(extraStringOffsets))
				for s, rel := range extraStringOffsets {
					abs := sectionStart + int(rel)
					if abs < blockOff || abs >= blockEnd {
						return nil, fmt.Errorf(
							"verifier dex[%d] extra string[%d] offset %#x is outside its block",
							i, s, rel,
						)
					}
					if _, duplicate := seenExtraOffsets[rel]; duplicate {
						continue
					}
					seenExtraOffsets[rel] = struct{}{}
					r.SetOffset(uint32(abs))
					r.ReadCStringBounded(
						uint32(blockEnd),
						fmt.Sprintf("vdex.verifier.dex[%d].extra_strings[%d]", i, s),
						"Extra string",
						"Extra string used by verifier dependencies.",
					)
				}
			}
		}
	}

	// 6. TypeLookupTable Section (kind 3)
	if ts, ok := sectionMap[3]; ok && ts.size > 0 && validByteRange(len(raw), ts.offset, ts.size) {
		sectionStart := int(ts.offset)
		sectionEnd := sectionStart + int(ts.size)
		r.SetOffset(ts.offset)

		expectedDexCount := checksumsCount
		if expectedDexCount == 0 {
			expectedDexCount = len(dexDefs)
		}

		for i := 0; i < expectedDexCount; i++ {
			if r.Offset()+4 > uint32(sectionEnd) {
				break
			}

			tableStart := r.Offset()
			size := r.ReadUint32LE(
				fmt.Sprintf("vdex.typelookup.dex[%d].size", i),
				"Table size",
				"Size of the type lookup table in bytes.",
			)

			// BUG-H4 fix: use uint64 arithmetic to prevent overflow when size is very large.
			if uint64(r.Offset())+uint64(size) > uint64(sectionEnd) {
				remaining := uint32(sectionEnd) - r.Offset()
				if remaining > 0 {
					r.ReadBytes(int(remaining), fmt.Sprintf("vdex.typelookup.dex[%d].truncated_payload", i), "Truncated table payload", "Truncated lookup table entries.")
				}
				break
			}

			count := size / 8
			if count > maxExplainCollectionItems {
				return nil, fmt.Errorf(
					"type-lookup dex[%d] entry count %d exceeds explain limit %d",
					i, count, maxExplainCollectionItems,
				)
			}

			// I-04 fix: Compute maskBits from class_defs_size of the corresponding DEX.
			// maskBits determines the bit-field layout of packed_data:
			//   bits[0        : maskBits)       = next_pos_delta (chain delta)
			//   bits[maskBits : 2*maskBits)     = class_def_idx
			//   bits[2*maskBits : 32)           = hash_bits (upper bits of class name hash)
			var classDefs uint32
			if i < len(dexDefs) {
				classDefs = dexDefs[i]
			}
			var maskBits uint32
			if classDefs > 0 {
				capped := classDefs
				if capped > 65536 {
					capped = 65536
				}
				maskBits = binutil.MinimumBitsToStore(capped - 1)
				if maskBits > 30 {
					maskBits = 30
				}
			}
			mask := (uint32(1) << maskBits) - 1

			for b := uint32(0); b < count; b++ {
				r.ReadUint32LE(
					fmt.Sprintf("vdex.typelookup.dex[%d].entry[%d].string_offset", i, b),
					"String offset",
					"Offset of the class descriptor string in the DEX string_data section.",
				)
				// Read packed_data raw value first, then build a rich description.
				packed := r.ReadUint32LE(
					fmt.Sprintf("vdex.typelookup.dex[%d].entry[%d].packed_data", i, b),
					"Packed data (bit fields: hash_bits | class_def_idx | next_pos_delta)",
					"", // description filled below
				)
				// Overwrite the description of the field we just emitted with
				// the decoded bit-field values.
				if len(r.fields) > 0 {
					lastField := r.fields[len(r.fields)-1]
					var nextDelta, classDefIdx, hashBits uint32
					if maskBits == 0 {
						hashBits = packed
					} else {
						nextDelta = packed & mask
						classDefIdx = (packed >> maskBits) & mask
						hashBits = packed >> (2 * maskBits)
					}
					lastField.Description = fmt.Sprintf(
						"Packed bit fields (maskBits=%d): "+
							"hash_bits=0x%x (bits[%d:32], upper hash of class descriptor), "+
							"class_def_idx=%d (bits[%d:%d], index into class_defs table), "+
							"next_pos_delta=%d (bits[0:%d], bucket-chain delta; 0=end of chain).",
						maskBits,
						hashBits, 2*maskBits,
						classDefIdx, maskBits, 2*maskBits,
						nextDelta, maskBits,
					)
				}
			}

			expectedEnd := tableStart + 4 + size
			if r.Offset() < expectedEnd {
				r.ReadBytes(
					int(expectedEnd-r.Offset()),
					fmt.Sprintf("vdex.typelookup.dex[%d].padding", i),
					"Table alignment padding",
					"Trailing alignment bytes for the type lookup table.",
				)
			}
		}
	}

	// 7. Parse any unknown sections
	for _, s := range sectionMap {
		if s.size == 0 {
			continue
		}
		if s.kind != 0 && s.kind != 1 && s.kind != 2 && s.kind != 3 {
			if validByteRange(len(raw), s.offset, s.size) {
				r.SetOffset(s.offset)
				r.ReadBytes(int(s.size), fmt.Sprintf("vdex.section_%d", s.kind), fmt.Sprintf("Section kind %d data", s.kind), "Raw unparsed section data.")
			}
		}
	}

	// Sweep and fill unmapped gaps to ensure 0 gaps and match total file length.
	sort.Slice(r.fields, func(i, j int) bool {
		if r.fields[i].Offset == r.fields[j].Offset {
			return r.fields[i].Size < r.fields[j].Size
		}
		return r.fields[i].Offset < r.fields[j].Offset
	})

	var finalFields []*model.PrimitiveField
	unmappedGaps := make([]model.ByteRange, 0)
	var cursor uint32 = 0
	fileSize := uint32(len(raw))

	for _, f := range r.fields {
		// BUG-H1 fix: skip overlapping fields (f.Offset < cursor means this field
		// starts inside an already-covered range, which would double-cover bytes).
		if f.Offset < cursor {
			continue
		}
		if f.Offset > cursor {
			gapBytes := raw[cursor:f.Offset]
			gapSize := f.Offset - cursor

			// Classify the gap:
			// - Known alignment padding: all-zero bytes, ≤3 bytes (4-byte align)
			//   → emit TypePadding field only; do NOT add to UnmappedGaps.
			// - Larger or non-zero gaps → truly unmapped; add to UnmappedGaps.
			isAlignPad := gapSize <= 3 && allZero(gapBytes)
			if !isAlignPad {
				unmappedGaps = append(unmappedGaps, model.ByteRange{Start: cursor, End: f.Offset})
			}

			desc := fmt.Sprintf("Alignment padding of %d bytes.", gapSize)
			if !isAlignPad {
				desc = fmt.Sprintf("Unmapped gap of %d bytes (non-zero or oversized).", gapSize)
			}
			finalFields = append(finalFields, &model.PrimitiveField{
				Offset:      cursor,
				Size:        gapSize,
				Type:        model.TypePadding,
				RawBytes:    gapBytes,
				ParsedValue: nil,
				LogicalPath: "vdex.padding",
				Summary:     "Alignment Padding",
				Description: desc,
			})
		}
		finalFields = append(finalFields, f)
		if f.Offset+f.Size > cursor {
			cursor = f.Offset + f.Size
		}
	}

	if cursor < fileSize {
		gapBytes := raw[cursor:fileSize]
		gapSize := fileSize - cursor
		isAlignPad := gapSize <= 3 && allZero(gapBytes)
		if !isAlignPad {
			unmappedGaps = append(unmappedGaps, model.ByteRange{Start: cursor, End: fileSize})
		}
		desc := fmt.Sprintf("Trailing alignment padding of %d bytes.", gapSize)
		if !isAlignPad {
			desc = fmt.Sprintf("Unmapped trailing gap of %d bytes.", gapSize)
		}
		finalFields = append(finalFields, &model.PrimitiveField{
			Offset:      cursor,
			Size:        gapSize,
			Type:        model.TypePadding,
			RawBytes:    gapBytes,
			ParsedValue: nil,
			LogicalPath: "vdex.padding",
			Summary:     "Trailing Padding",
			Description: desc,
		})
	}

	// BUG-N3: Removed the redundant second sort.Slice. After the BUG-H1 overlap fix
	// the sweep loop guarantees finalFields are already in strict ascending order.
	// BUG-N2: Removed the empty "if versionStr != '027'" dead-code block.
	_ = versionStr // suppress "declared but not used" if compiler complains

	return &model.PrimitiveMap{
		Fields:       finalFields,
		TotalBytes:   fileSize,
		UnmappedGaps: unmappedGaps,
		DexPreviews:  dexPreviews,
	}, nil
}

// allZero reports whether every byte in b is 0x00.
// Used by the gap-fill sweep to distinguish known alignment padding (all zeros)
// from genuine unmapped regions that may contain non-zero data.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

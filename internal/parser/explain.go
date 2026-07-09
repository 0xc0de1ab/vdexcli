package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

type AnnotatedReader struct {
	data   []byte
	offset uint32
	fields []*model.PrimitiveField
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
	if r.offset+uint32(size) > uint32(len(r.data)) {
		return ""
	}
	val := string(r.data[r.offset : r.offset+uint32(size)])
	r.fields = append(r.fields, &model.PrimitiveField{
		Offset:      r.offset,
		Size:        uint32(size),
		Type:        model.TypeMagic,
		RawBytes:    r.data[r.offset : r.offset+uint32(size)],
		ParsedValue: val,
		LogicalPath: path,
		Summary:     summary,
		Description: desc,
	})
	r.offset += uint32(size)
	return val
}

func (r *AnnotatedReader) ReadUint8(path string, summary string, desc string) uint8 {
	if r.offset+1 > uint32(len(r.data)) {
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
	if r.offset+2 > uint32(len(r.data)) {
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
	if r.offset+4 > uint32(len(r.data)) {
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
	if r.offset+8 > uint32(len(r.data)) {
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
	if r.offset+uint32(size) > uint32(len(r.data)) {
		size = len(r.data) - int(r.offset)
	}
	val := r.data[r.offset : r.offset+uint32(size)]
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
	newOffset := uint32(binutil.Align4(int(r.offset)))
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

func ExplainVdex(path string) (*model.PrimitiveMap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
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

	numSections := r.ReadUint32LE("vdex.header.sections", "Number of sections", "Total number of sections defined in the section table.")

	// 2. Section Headers Table
	// BUG-H3 fix: use uint64 arithmetic to prevent uint32 overflow when numSections is large.
	headerEnd64 := uint64(12) + uint64(numSections)*12
	if headerEnd64 > uint64(len(raw)) {
		return nil, fmt.Errorf("file too small for section table (%d bytes, need %d)", len(raw), headerEnd64)
	}

	sectionMap := make(map[uint32]sectionInfo)
	for i := uint32(0); i < numSections; i++ {
		kind := r.ReadUint32LE(fmt.Sprintf("vdex.sections[%d].kind", i), "Section kind", fmt.Sprintf("The identifier of the section type for section %d.", i))
		offset := r.ReadUint32LE(fmt.Sprintf("vdex.sections[%d].offset", i), "Section offset", fmt.Sprintf("File offset where section %d starts.", i))
		size := r.ReadUint32LE(fmt.Sprintf("vdex.sections[%d].size", i), "Section size", fmt.Sprintf("The size in bytes of section %d.", i))

		// BUG-M6 fix: keep first occurrence; reference parser (ParseVdex) also uses the first.
		if _, exists := sectionMap[kind]; !exists {
			sectionMap[kind] = sectionInfo{kind: kind, offset: offset, size: size}
		}
	}

	// 3. Checksums Section (kind 0)
	var checksumsCount int
	if cs, ok := sectionMap[0]; ok && cs.size > 0 && cs.offset+cs.size <= uint32(len(raw)) {
		r.SetOffset(cs.offset)
		count := cs.size / 4
		checksumsCount = int(count)
		for i := uint32(0); i < count; i++ {
			r.ReadUint32LE(
				fmt.Sprintf("vdex.checksums[%d]", i),
				fmt.Sprintf("DEX[%d] checksum", i),
				fmt.Sprintf("The location checksum for the DEX file at index %d.", i),
			)
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
	if ds, ok := sectionMap[1]; ok && ds.size > 0 && ds.offset+ds.size <= uint32(len(raw)) {
		cursor := ds.offset
		dexIdx := 0
		expectedDexCount := checksumsCount

		for (expectedDexCount == 0 && cursor < ds.offset+ds.size) || (expectedDexCount > 0 && dexIdx < expectedDexCount) {
			r.SetOffset(cursor)
			r.Align4(fmt.Sprintf("vdex.dexes.align[%d]", dexIdx))
			cursor = r.Offset()

			if cursor+112 > ds.offset+ds.size {
				break
			}

			dexStart := cursor

			// BUG-M3 fix: parse DEX magic (4B) and version (4B) as separate TypeMagic fields.
			dexMagicStr := r.ReadMagic(4, fmt.Sprintf("vdex.dex[%d].header.magic", dexIdx), "DEX magic signature", "Identifies the file as a DEX file (must be 'dex\\n').")
			_ = r.ReadMagic(4, fmt.Sprintf("vdex.dex[%d].header.version", dexIdx), "DEX version", "DEX format version (e.g. '035\\x00').")
			if !bytes.HasPrefix([]byte(dexMagicStr), []byte("dex\n")) {
				break
			}

			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.checksum", dexIdx), "DEX checksum", "Adler32 checksum of the DEX file.")
			_ = r.ReadBytes(20, fmt.Sprintf("vdex.dex[%d].header.signature", dexIdx), "DEX signature", "SHA-1 signature of the DEX file.")
			fileSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.file_size", dexIdx), "DEX file size", "Declared size of the DEX file in bytes.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.header_size", dexIdx), "DEX header size", "Size of the DEX header in bytes (typically 112).")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.endian_tag", dexIdx), "DEX endian tag", "Endianness tag (typically 0x12345678).")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.link_size", dexIdx), "DEX link size", "Size of the link section in bytes.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.link_off", dexIdx), "DEX link offset", "File offset of the link section.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.map_off", dexIdx), "DEX map offset", "File offset of the map list.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.string_ids_size", dexIdx), "DEX string IDs size", "Number of string identifiers in the string IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.string_ids_off", dexIdx), "DEX string IDs offset", "File offset of the string IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.type_ids_size", dexIdx), "DEX type IDs size", "Number of type identifiers in the type IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.type_ids_off", dexIdx), "DEX type IDs offset", "File offset of the type IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.proto_ids_size", dexIdx), "DEX proto IDs size", "Number of prototype identifiers in the prototype IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.proto_ids_off", dexIdx), "DEX proto IDs offset", "File offset of the prototype IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.field_ids_size", dexIdx), "DEX field IDs size", "Number of field identifiers in the field IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.field_ids_off", dexIdx), "DEX field IDs offset", "File offset of the field IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.method_ids_size", dexIdx), "DEX method IDs size", "Number of method identifiers in the method IDs table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.method_ids_off", dexIdx), "DEX method IDs offset", "File offset of the method IDs table.")
			classDefsSize := r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.class_defs_size", dexIdx), "DEX class defs size", "Number of class definitions in the class definitions table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.class_defs_off", dexIdx), "DEX class defs offset", "File offset of the class definitions table.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.data_size", dexIdx), "DEX data size", "Size of the data section in bytes.")
			_ = r.ReadUint32LE(fmt.Sprintf("vdex.dex[%d].header.data_off", dexIdx), "DEX data offset", "File offset of the data section.")

			dexDefs = append(dexDefs, classDefsSize)

			effectiveSize := fileSize
			if dexStart+effectiveSize > ds.offset+ds.size {
				effectiveSize = ds.offset+ds.size - dexStart
			}

			payloadSize := int(effectiveSize) - 112
			if payloadSize > 0 {
				r.ReadBytes(payloadSize, fmt.Sprintf("vdex.dex[%d].payload", dexIdx), "DEX payload", "The remaining tables and data of the DEX file.")
			}

			cursor = dexStart + effectiveSize
			dexIdx++
		}
	}

	// 5. VerifierDeps Section (kind 2)
	if vs, ok := sectionMap[2]; ok && vs.size > 0 && vs.offset+vs.size <= uint32(len(raw)) {
		sectionStart := int(vs.offset)
		sectionEnd := sectionStart + int(vs.size)
		r.SetOffset(vs.offset)

		expectedDexCount := len(dexDefs)
		if expectedDexCount == 0 {
			expectedDexCount = checksumsCount
		}

		var dexBlockOffsets []uint32
		for i := 0; i < expectedDexCount; i++ {
			if r.Offset()+4 > uint32(sectionEnd) {
				break
			}
			off := r.ReadUint32LE(
				fmt.Sprintf("vdex.verifier.dex_offsets[%d]", i),
				"Verifier DEX offset",
				fmt.Sprintf("Section-absolute offset to the verifier dependency block for DEX %d.", i),
			)
			dexBlockOffsets = append(dexBlockOffsets, off)
		}

		for i, relative := range dexBlockOffsets {
			blockOff := sectionStart + int(relative)
			if blockOff < sectionStart || blockOff >= sectionEnd {
				continue
			}

			var numClass int
			if i < len(dexDefs) {
				numClass = int(dexDefs[i])
			}

			if numClass == 0 {
				numClass = inferClassCount(raw, sectionStart, blockOff, sectionEnd)
			}

			r.SetOffset(uint32(blockOff))

			var classOffsets []uint32
			for c := 0; c <= numClass; c++ {
				if r.Offset()+4 > uint32(sectionEnd) {
					break
				}
				off := r.ReadUint32LE(
					fmt.Sprintf("vdex.verifier.dex[%d].class_offsets[%d]", i, c),
					"Class verifier offset",
					fmt.Sprintf("Section-absolute offset to assignability pairs for class %d.", c),
				)
				classOffsets = append(classOffsets, off)
			}

			if len(classOffsets) < numClass+1 {
				continue
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
				if setStart < blockOff || setEnd > sectionEnd || setEnd < setStart {
					continue
				}

				if setStart > maxSetEnd {
					maxSetEnd = setStart
				}

				r.SetOffset(uint32(setStart))
				pairIdx := 0
				for r.Offset() < uint32(setEnd) {
					// BUG-C1 fix: break on malformed LEB128 (n==0 means offset won't
					// advance, which causes an infinite loop on malformed input).
					_, destN := r.ReadUleb128(
						fmt.Sprintf("vdex.verifier.dex[%d].class[%d].pair[%d].dest", i, classIdx, pairIdx),
						"Destination type index",
						"The destination type index for assignability verification.",
					)
					if destN == 0 {
						break // malformed LEB128 — stop to avoid infinite loop
					}
					_, srcN := r.ReadUleb128(
						fmt.Sprintf("vdex.verifier.dex[%d].class[%d].pair[%d].src", i, classIdx, pairIdx),
						"Source type index",
						"The source type index for assignability verification.",
					)
					if srcN == 0 {
						break // malformed LEB128 — stop to avoid infinite loop
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
			if cursor+4 <= sectionEnd {
				numStrings := r.ReadUint32LE(
					fmt.Sprintf("vdex.verifier.dex[%d].num_extra_strings", i),
					"Extra strings count",
					"Number of extra strings in the verifier deps block.",
				)

				var extraStringOffsets []uint32
				for s := 0; s < int(numStrings); s++ {
					if r.Offset()+4 > uint32(sectionEnd) {
						break
					}
					off := r.ReadUint32LE(
						fmt.Sprintf("vdex.verifier.dex[%d].extra_string_offsets[%d]", i, s),
						"Extra string offset",
						"Section-absolute offset to the extra string.",
					)
					extraStringOffsets = append(extraStringOffsets, off)
				}

				for s, rel := range extraStringOffsets {
					abs := sectionStart + int(rel)
					if abs >= blockOff && abs < sectionEnd {
						r.SetOffset(uint32(abs))
						// BUG-H2 fix: use ReadCStringBounded with sectionEnd to prevent
						// crossing into the next section when the string is unterminated.
						r.ReadCStringBounded(
							uint32(sectionEnd),
							fmt.Sprintf("vdex.verifier.dex[%d].extra_strings[%d]", i, s),
							"Extra string",
							"Extra string used by verifier dependencies.",
						)
					}
				}
			}
		}
	}

	// 6. TypeLookupTable Section (kind 3)
	if ts, ok := sectionMap[3]; ok && ts.size > 0 && ts.offset+ts.size <= uint32(len(raw)) {
		sectionStart := int(ts.offset)
		sectionEnd := sectionStart + int(ts.size)
		r.SetOffset(ts.offset)

		expectedDexCount := len(dexDefs)
		if expectedDexCount == 0 {
			expectedDexCount = checksumsCount
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
			for b := uint32(0); b < count; b++ {
				r.ReadUint32LE(
					fmt.Sprintf("vdex.typelookup.dex[%d].entry[%d].string_offset", i, b),
					"String offset",
					"Offset of the class descriptor string in the DEX file.",
				)
				r.ReadUint32LE(
					fmt.Sprintf("vdex.typelookup.dex[%d].entry[%d].packed_data", i, b),
					"Packed data",
					"Packed class definition index and next chain delta.",
				)
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
			if s.offset+s.size <= uint32(len(raw)) {
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
	var unmappedGaps []model.ByteRange
	var cursor uint32 = 0
	fileSize := uint32(len(raw))

	for _, f := range r.fields {
		// BUG-H1 fix: skip overlapping fields (f.Offset < cursor means this field
		// starts inside an already-covered range, which would double-cover bytes).
		if f.Offset < cursor {
			continue
		}
		if f.Offset > cursor {
			gapSize := f.Offset - cursor
			gapRange := model.ByteRange{Start: cursor, End: f.Offset}
			unmappedGaps = append(unmappedGaps, gapRange)

			finalFields = append(finalFields, &model.PrimitiveField{
				Offset:      cursor,
				Size:        gapSize,
				Type:        model.TypePadding,
				RawBytes:    raw[cursor:f.Offset],
				ParsedValue: nil,
				LogicalPath: "vdex.gap",
				Summary:     "Gap / Padding",
				Description: fmt.Sprintf("Unmapped gap or padding of %d bytes.", gapSize),
			})
		}
		finalFields = append(finalFields, f)
		if f.Offset+f.Size > cursor {
			cursor = f.Offset + f.Size
		}
	}

	if cursor < fileSize {
		gapSize := fileSize - cursor
		gapRange := model.ByteRange{Start: cursor, End: fileSize}
		unmappedGaps = append(unmappedGaps, gapRange)

		finalFields = append(finalFields, &model.PrimitiveField{
			Offset:      cursor,
			Size:        gapSize,
			Type:        model.TypePadding,
			RawBytes:    raw[cursor:fileSize],
			ParsedValue: nil,
			LogicalPath: "vdex.gap",
			Summary:     "Gap / Padding",
			Description: fmt.Sprintf("Unmapped gap or padding of %d bytes at the end of the file.", gapSize),
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
	}, nil
}

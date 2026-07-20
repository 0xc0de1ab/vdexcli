package parser

// explain_dex.go — DEX file section annotation helpers for ExplainVdex.
//
// This file contains the sub-functions extracted from the monolithic
// ExplainVdex() function to handle the annotation of DEX file payload
// (section tables, data items, etc.).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

const (
	dexPreviewClassLimit      = 3
	dexPreviewDescriptorLimit = 4096
	dexPreviewPackageLimit    = 3
	dexPreviewSampleLimit     = 512
)

// dexSectionInfo describes a known DEX payload section (offset relative to
// DEX file start, size, logical path name, and a human-readable description).
type dexSectionInfo struct {
	off  uint32 // offset relative to start of this DEX file
	size uint32
	name string // logical path for PrimitiveField
	desc string // human-readable description
}

// dexPayloadParams holds all parameters needed to annotate one DEX file's
// internal payload sections.
type dexPayloadParams struct {
	raw           []byte
	r             *AnnotatedReader
	dexIdx        int
	dexStart      uint32 // absolute file offset where this DEX begins
	effectiveSize uint32 // byte length of this DEX (may be < declared file_size if truncated)
	headerSize    uint32 // from header_size field; usually 112
	stringIdsOff  uint32
	stringIdsSize uint32
	typeIdsOff    uint32
	typeIdsSize   uint32
	protoIdsOff   uint32
	protoIdsSize  uint32
	fieldIdsOff   uint32
	fieldIdsSize  uint32
	methodIdsOff  uint32
	methodIdsSize uint32
	classDefsOff  uint32
	classDefsSize uint32
	linkOff       uint32
	linkSize      uint32
	mapOff        uint32
}

func buildDexPreview(p dexPayloadParams) model.DexPreview {
	preview := model.DexPreview{Index: p.dexIdx, Embedded: true, ClassCount: p.classDefsSize}
	if p.classDefsSize == 0 || !dexTableInRange(p, p.classDefsOff, p.classDefsSize, 32) ||
		!dexTableInRange(p, p.typeIdsOff, p.typeIdsSize, 4) ||
		!dexTableInRange(p, p.stringIdsOff, p.stringIdsSize, 4) {
		return preview
	}

	type descriptorPreview struct {
		descriptor  string
		packageName string
		packageOK   bool
		valid       bool
	}
	packageCounts := make(map[string]uint32)
	descriptorCache := make(map[uint32]descriptorPreview)
	classExamples := make(map[string]struct{})
	sampleCount := min(p.classDefsSize, uint32(dexPreviewSampleLimit))
	preview.SampledClassDefs = sampleCount
	for sampleIdx := uint32(0); sampleIdx < sampleCount; sampleIdx++ {
		classDefIdx := sampleIdx
		if sampleCount > 1 && p.classDefsSize > sampleCount {
			classDefIdx = uint32(uint64(sampleIdx) * uint64(p.classDefsSize-1) / uint64(sampleCount-1))
		}
		classDefAt := uint64(p.dexStart) + uint64(p.classDefsOff) + uint64(classDefIdx)*32
		classIdx := binary.LittleEndian.Uint32(p.raw[int(classDefAt) : int(classDefAt)+4])
		resolved, cached := descriptorCache[classIdx]
		if !cached {
			resolved.descriptor, resolved.valid = resolveDexClassDescriptor(p, classIdx)
			if resolved.valid {
				resolved.packageName, resolved.packageOK = dexPackageName(resolved.descriptor)
			}
			descriptorCache[classIdx] = resolved
		}
		if !resolved.valid {
			continue
		}
		preview.ResolvedClassDescriptors++
		if len(preview.ClassDescriptors) < dexPreviewClassLimit {
			if _, seen := classExamples[resolved.descriptor]; !seen {
				classExamples[resolved.descriptor] = struct{}{}
				preview.ClassDescriptors = append(preview.ClassDescriptors, resolved.descriptor)
			}
		}
		if resolved.packageOK {
			packageCounts[resolved.packageName]++
		}
	}

	type packageCount struct {
		name  string
		count uint32
	}
	packages := make([]packageCount, 0, len(packageCounts))
	for name, count := range packageCounts {
		packages = append(packages, packageCount{name: name, count: count})
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].count != packages[j].count {
			return packages[i].count > packages[j].count
		}
		return packages[i].name < packages[j].name
	})
	preview.PackageCount = len(packages)
	for _, pkg := range packages[:min(len(packages), dexPreviewPackageLimit)] {
		preview.TopPackages = append(preview.TopPackages, model.DexPackagePreview{
			Name:       pkg.name,
			ClassCount: pkg.count,
		})
	}
	return preview
}

func dexTableInRange(p dexPayloadParams, offset uint32, count uint32, itemSize uint32) bool {
	if offset == 0 || count == 0 {
		return false
	}
	tableEnd := uint64(offset) + uint64(count)*uint64(itemSize)
	absEnd := uint64(p.dexStart) + tableEnd
	return tableEnd <= uint64(p.effectiveSize) && absEnd <= uint64(len(p.raw))
}

func resolveDexClassDescriptor(p dexPayloadParams, classIdx uint32) (string, bool) {
	if classIdx >= p.typeIdsSize {
		return "", false
	}
	typeAt := uint64(p.dexStart) + uint64(p.typeIdsOff) + uint64(classIdx)*4
	stringIdx := binary.LittleEndian.Uint32(p.raw[int(typeAt) : int(typeAt)+4])
	if stringIdx >= p.stringIdsSize {
		return "", false
	}
	stringIDAt := uint64(p.dexStart) + uint64(p.stringIdsOff) + uint64(stringIdx)*4
	stringOffset := binary.LittleEndian.Uint32(p.raw[int(stringIDAt) : int(stringIDAt)+4])
	stringAt := uint64(p.dexStart) + uint64(stringOffset)
	dexEnd := uint64(p.dexStart) + uint64(p.effectiveSize)
	if stringAt >= dexEnd || stringAt >= uint64(len(p.raw)) {
		return "", false
	}

	_, lengthSize, err := binutil.ReadULEB128(p.raw, int(stringAt))
	if err != nil {
		return "", false
	}
	valueAt := stringAt + uint64(lengthSize)
	if valueAt >= dexEnd || valueAt >= uint64(len(p.raw)) {
		return "", false
	}
	limit := min(dexEnd, uint64(len(p.raw)), valueAt+dexPreviewDescriptorLimit)
	nullAt := bytes.IndexByte(p.raw[int(valueAt):int(limit)], 0)
	if nullAt < 0 {
		return "", false
	}
	descriptor := string(p.raw[int(valueAt) : int(valueAt)+nullAt])
	if !strings.HasPrefix(descriptor, "L") || !strings.HasSuffix(descriptor, ";") {
		return "", false
	}
	return descriptor, true
}

func dexPackageName(descriptor string) (string, bool) {
	className := strings.TrimSuffix(strings.TrimPrefix(descriptor, "L"), ";")
	separator := strings.LastIndexByte(className, '/')
	if separator <= 0 {
		return "", false
	}
	return strings.ReplaceAll(className[:separator], "/", "."), true
}

// annotateMapList reads and decomposes a DEX map_list entry-by-entry into
// (type[2] + unused[2] + count[4] + offset[4]) fields.
func annotateMapList(r *AnnotatedReader, raw []byte, secName string, secOff, secSize, dexEnd uint32) {
	if secOff+secSize > dexEnd {
		return
	}
	r.SetOffset(secOff)
	mapCount := r.ReadUint32LE(secName+".size", "Map list count",
		"Number of map_item entries in this map_list.")

	mapTypeName := map[uint16]string{
		0x0000: "TYPE_HEADER_ITEM", 0x0001: "TYPE_STRING_ID_ITEM",
		0x0002: "TYPE_TYPE_ID_ITEM", 0x0003: "TYPE_PROTO_ID_ITEM",
		0x0004: "TYPE_FIELD_ID_ITEM", 0x0005: "TYPE_METHOD_ID_ITEM",
		0x0006: "TYPE_CLASS_DEF_ITEM", 0x0007: "TYPE_CALL_SITE_ID_ITEM",
		0x0008: "TYPE_METHOD_HANDLE_ITEM", 0x1000: "TYPE_MAP_LIST",
		0x1001: "TYPE_TYPE_LIST", 0x1002: "TYPE_ANNOTATION_SET_REF_LIST",
		0x1003: "TYPE_ANNOTATION_SET_ITEM", 0x2000: "TYPE_CLASS_DATA_ITEM",
		0x2001: "TYPE_CODE_ITEM", 0x2002: "TYPE_STRING_DATA_ITEM",
		0x2003: "TYPE_DEBUG_INFO_ITEM", 0x2004: "TYPE_ANNOTATION_ITEM",
		0x2005: "TYPE_ENCODED_ARRAY_ITEM", 0x2006: "TYPE_ANNOTATIONS_DIRECTORY_ITEM",
		0xF000: "TYPE_HIDDENAPI_CLASS_DATA_ITEM",
	}
	for j := uint32(0); j < mapCount; j++ {
		if r.Offset()+12 > dexEnd {
			break
		}
		prefix := fmt.Sprintf("%s.item[%d]", secName, j)
		typeVal := r.ReadUint16LE(prefix+".type", "Map item type",
			"Section type code identifying what kind of data is at the given offset.")
		_ = r.ReadUint16LE(prefix+".unused", "Map item padding",
			"Unused padding field (always 0).")
		itemCount := r.ReadUint32LE(prefix+".count", "Map item count",
			"Number of items of this section type.")
		itemOff := r.ReadUint32LE(prefix+".offset", "Map item offset",
			fmt.Sprintf("File offset where these %d items begin.", itemCount))

		typStr, ok := mapTypeName[typeVal]
		if !ok {
			typStr = fmt.Sprintf("0x%04x", typeVal)
		}
		// Enrich the type field description
		if len(r.fields) >= 4 {
			typeField := r.fields[len(r.fields)-4]
			typeField.Description = fmt.Sprintf(
				"Section type: %s (0x%04x). Count=%d, Offset=0x%x.",
				typStr, typeVal, itemCount, itemOff)
		}
		_ = raw // raw available if needed for further analysis
	}
}

// annotateStringIds reads string_ids table and resolves inline string values.
func annotateStringIds(r *AnnotatedReader, raw []byte, secName string, secSize, dexStart, dexEnd, stringIdsSize uint32) {
	count := secSize / 4
	for j := uint32(0); j < count; j++ {
		strDataOff := r.ReadUint32LE(
			fmt.Sprintf("%s[%d]", secName, j),
			fmt.Sprintf("string_ids[%d]: offset to string_data_item", j),
			"") // Description filled below

		// Resolve the string_data_item inline for display
		var resolvedStr string
		sdAbs := int(dexStart) + int(strDataOff)
		if sdAbs >= 0 && sdAbs < len(raw) && sdAbs < int(dexEnd) {
			_, ulebLen, err := binutil.ReadULEB128(raw, sdAbs)
			strStart := sdAbs + ulebLen
			limit := min(len(raw), int(dexEnd))
			if err == nil && strStart < limit {
				if n := bytes.IndexByte(raw[strStart:limit], 0); n >= 0 {
					resolvedStr = string(raw[strStart : strStart+n])
				}
			}
		}

		desc := fmt.Sprintf(
			"File offset (0x%x) to the ULEB128-length-prefixed MUTF-8 string for string identifier %d.",
			strDataOff, j)
		if resolvedStr != "" {
			desc = fmt.Sprintf("%q — %s", resolvedStr, desc)
		}
		if len(r.fields) > 0 {
			r.fields[len(r.fields)-1].Description = desc
		}
	}
	_ = stringIdsSize
}

// annotateClassDefs reads class_defs table with access_flags bit decomposition.
func annotateClassDefs(r *AnnotatedReader, secName string, secSize uint32) {
	count := secSize / 32
	for j := uint32(0); j < count; j++ {
		prefix := fmt.Sprintf("%s[%d]", secName, j)
		r.ReadUint32LE(prefix+".class_idx", "ClassDef class_idx",
			fmt.Sprintf("Index into type_ids for class definition %d.", j))

		accessFlags := r.ReadUint32LE(prefix+".access_flags", "ClassDef access_flags",
			"") // Description filled below with bit decomposition
		if len(r.fields) > 0 {
			r.fields[len(r.fields)-1].Description = accessFlagsDescription(accessFlags)
		}

		r.ReadUint32LE(prefix+".superclass_idx", "ClassDef superclass_idx",
			"Index into type_ids for the superclass (0xFFFFFFFF if none / java.lang.Object).")
		r.ReadUint32LE(prefix+".interfaces_off", "ClassDef interfaces_off",
			"Offset to implemented interfaces type_list (0 if none).")
		r.ReadUint32LE(prefix+".source_file_idx", "ClassDef source_file_idx",
			"Index into string_ids for the source file name (0xFFFFFFFF if unknown).")
		r.ReadUint32LE(prefix+".annotations_off", "ClassDef annotations_off",
			"Offset to the annotations_directory_item (0 if none).")
		r.ReadUint32LE(prefix+".class_data_off", "ClassDef class_data_off",
			"Offset to the class_data_item (0 if no fields/methods).")
		r.ReadUint32LE(prefix+".static_values_off", "ClassDef static_values_off",
			"Offset to the encoded_array_item for static field initializers (0 if none).")
	}
}

// annotateStringDataItems decomposes string_data_items in the data section.
// It collects string_data offsets from string_ids, sorts them, and
// iterates over them emitting ULEB128 + chars + null as annotated blobs.
// Gaps between known string_data_items are emitted as data_gap blobs.
func annotateStringDataItems(
	r *AnnotatedReader,
	raw []byte,
	dexIdx int,
	dexStart, dexEnd, payloadCursor, effectiveSize uint32,
	stringIdsOff, stringIdsSize uint32,
) {
	// Collect string_data offsets from the string_ids table
	var stringDataOffsets []uint32
	if stringIdsOff > 0 && stringIdsSize > 0 {
		for si := uint32(0); si < stringIdsSize; si++ {
			soOff := int(dexStart) + int(stringIdsOff) + int(si*4)
			if soOff+4 <= len(raw) {
				strDataOff := binary.LittleEndian.Uint32(raw[soOff : soOff+4])
				if strDataOff >= payloadCursor && strDataOff < effectiveSize {
					stringDataOffsets = append(stringDataOffsets, strDataOff)
				}
			}
		}
		sort.Slice(stringDataOffsets, func(i, j int) bool {
			return stringDataOffsets[i] < stringDataOffsets[j]
		})
	}

	if len(stringDataOffsets) == 0 {
		// No string data resolvable → emit whole remainder as a single blob
		remAbs := dexStart + payloadCursor
		remSize := effectiveSize - payloadCursor
		if remAbs+remSize > dexEnd {
			remSize = dexEnd - remAbs
		}
		if remSize > 0 {
			r.SetOffset(remAbs)
			r.ReadBytes(int(remSize),
				fmt.Sprintf("vdex.dex[%d].data", dexIdx),
				fmt.Sprintf("DEX data section (%d bytes)", remSize),
				"Data section containing string_data_items, code_items, annotation data, and other variable-length structures.")
		}
		return
	}

	dataCursor := payloadCursor
	for si, strOff := range stringDataOffsets {
		if strOff < dataCursor {
			continue
		}
		// Emit gap before this string_data_item
		if strOff > dataCursor {
			gapSz := strOff - dataCursor
			gapAbs := dexStart + dataCursor
			if gapAbs+gapSz <= dexEnd {
				r.SetOffset(gapAbs)
				r.ReadBytes(int(gapSz),
					fmt.Sprintf("vdex.dex[%d].data_gap_%04x", dexIdx, dataCursor),
					fmt.Sprintf("Data gap at DEX offset 0x%x", dataCursor),
					"Non-string data (code_items, type_lists, annotations, etc.)")
			}
			dataCursor = strOff
		}

		// Decompose string_data_item: ULEB128 utf16_size + MUTF-8 bytes + null
		sdAbs := int(dexStart) + int(strOff)
		if sdAbs >= len(raw) {
			break
		}
		uleb, ulebLen, err := binutil.ReadULEB128(raw, sdAbs)
		if err != nil || sdAbs+ulebLen > len(raw) {
			break
		}
		strStart := sdAbs + ulebLen
		limit := min(len(raw), int(dexEnd))
		if strStart >= limit {
			break
		}
		nullAt := bytes.IndexByte(raw[strStart:limit], 0)
		if nullAt < 0 {
			break
		}
		strLen := nullAt
		itemSize := ulebLen + strLen + 1
		strVal := string(raw[strStart : strStart+strLen])
		r.SetOffset(uint32(sdAbs))
		r.ReadBytes(itemSize,
			fmt.Sprintf("vdex.dex[%d].string_data[%d]", dexIdx, si),
			fmt.Sprintf("string_data_item[%d]: %q", si, strVal),
			fmt.Sprintf(
				"MUTF-8 encoded string data: utf16_size=%d (ULEB128, %d byte(s)), "+
					"chars=%q, null_terminator. Pointed to by string_ids[%d].",
				uleb, ulebLen, strVal, si))
		dataCursor = strOff + uint32(itemSize)
	}

	// Emit remaining bytes after last string_data_item
	if dataCursor < effectiveSize {
		finalSz := effectiveSize - dataCursor
		finalAbs := dexStart + dataCursor
		if finalAbs < dexEnd && finalSz > 0 {
			if finalAbs+finalSz > dexEnd {
				finalSz = dexEnd - finalAbs
			}
			r.SetOffset(finalAbs)
			r.ReadBytes(int(finalSz),
				fmt.Sprintf("vdex.dex[%d].data_remaining", dexIdx),
				fmt.Sprintf("DEX data remainder (%d bytes)", finalSz),
				"Remaining data: code_items, type_lists, annotation data, class_data_items, etc.")
		}
	}
}

// annotateDexPayload processes all known DEX payload sections (after the 112B header)
// and emits annotated PrimitiveFields for each one, filling gaps with blob entries.
func annotateDexPayload(p dexPayloadParams) {
	r := p.r
	raw := p.raw
	dexIdx := p.dexIdx
	dexStart := p.dexStart
	effectiveSize := p.effectiveSize
	dexEnd := dexStart + effectiveSize

	// Clamp header_size to 112 if it is absent or invalid
	if p.headerSize < 112 || p.headerSize > effectiveSize {
		p.headerSize = 112
	}
	headerSize := p.headerSize

	// -------------------------------------------------------------------------
	// 1. Collect known sections (offset relative to DEX file start, not file).
	// -------------------------------------------------------------------------
	var knownSections []dexSectionInfo

	addSec := func(off, size uint32, name, desc string) {
		if off == 0 || size == 0 {
			return
		}
		if off+size > effectiveSize {
			if off >= effectiveSize {
				return
			}
			size = effectiveSize - off
		}
		knownSections = append(knownSections, dexSectionInfo{off: off, size: size, name: name, desc: desc})
	}

	addSec(p.stringIdsOff, p.stringIdsSize*4,
		fmt.Sprintf("vdex.dex[%d].string_ids", dexIdx),
		fmt.Sprintf("String IDs table: %d entries × 4B. Each is a file offset to a string_data_item.", p.stringIdsSize))
	addSec(p.typeIdsOff, p.typeIdsSize*4,
		fmt.Sprintf("vdex.dex[%d].type_ids", dexIdx),
		fmt.Sprintf("Type IDs table: %d entries × 4B. Each is an index into the string IDs list.", p.typeIdsSize))
	addSec(p.protoIdsOff, p.protoIdsSize*12,
		fmt.Sprintf("vdex.dex[%d].proto_ids", dexIdx),
		fmt.Sprintf("Proto IDs table: %d entries × 12B (shorty_idx[4]+return_type_idx[4]+parameters_off[4]).", p.protoIdsSize))
	addSec(p.fieldIdsOff, p.fieldIdsSize*8,
		fmt.Sprintf("vdex.dex[%d].field_ids", dexIdx),
		fmt.Sprintf("Field IDs table: %d entries × 8B (class_idx[2]+type_idx[2]+name_idx[4]).", p.fieldIdsSize))
	addSec(p.methodIdsOff, p.methodIdsSize*8,
		fmt.Sprintf("vdex.dex[%d].method_ids", dexIdx),
		fmt.Sprintf("Method IDs table: %d entries × 8B (class_idx[2]+proto_idx[2]+name_idx[4]).", p.methodIdsSize))
	addSec(p.classDefsOff, p.classDefsSize*32,
		fmt.Sprintf("vdex.dex[%d].class_defs", dexIdx),
		fmt.Sprintf("Class Defs table: %d entries × 32B per class definition.", p.classDefsSize))
	if p.linkSize > 0 && p.linkOff > 0 {
		addSec(p.linkOff, p.linkSize,
			fmt.Sprintf("vdex.dex[%d].link_section", dexIdx),
			"Link section data (statically linked libraries, unused in most DEX files).")
	}
	if p.mapOff > 0 && p.mapOff < effectiveSize {
		mapOffAbs := int(dexStart) + int(p.mapOff)
		if mapOffAbs+4 <= int(dexEnd) && mapOffAbs+4 <= len(raw) {
			mapCount := binary.LittleEndian.Uint32(raw[mapOffAbs : mapOffAbs+4])
			mapSize := 4 + mapCount*12
			if p.mapOff+mapSize > effectiveSize {
				mapSize = effectiveSize - p.mapOff
			}
			addSec(p.mapOff, mapSize,
				fmt.Sprintf("vdex.dex[%d].map_list", dexIdx),
				fmt.Sprintf("Map list: %d entries. Lists all section types in this DEX file.", mapCount))
		}
	}

	// Sort and deduplicate by offset
	sort.Slice(knownSections, func(i, j int) bool {
		return knownSections[i].off < knownSections[j].off
	})
	var dedup []dexSectionInfo
	var lastEnd uint32
	for _, sec := range knownSections {
		if sec.off < lastEnd {
			continue
		}
		dedup = append(dedup, sec)
		if sec.off+sec.size > lastEnd {
			lastEnd = sec.off + sec.size
		}
	}

	// -------------------------------------------------------------------------
	// 2. Walk sections in order, filling gaps, annotating each table.
	// -------------------------------------------------------------------------
	payloadCursor := headerSize
	for _, sec := range dedup {
		if sec.off < payloadCursor {
			continue
		}
		// Gap before this section
		if sec.off > payloadCursor {
			gapSize := sec.off - payloadCursor
			gapAbs := dexStart + payloadCursor
			if gapAbs+gapSize <= dexEnd {
				r.SetOffset(gapAbs)
				r.ReadBytes(int(gapSize),
					fmt.Sprintf("vdex.dex[%d].gap_%04x", dexIdx, payloadCursor),
					fmt.Sprintf("Gap at DEX offset 0x%x", payloadCursor),
					fmt.Sprintf("Unstructured gap of %d bytes between DEX sections. May be padding or unknown data.", gapSize))
			}
			payloadCursor = sec.off
		}

		absOff := dexStart + sec.off
		if absOff+sec.size > dexEnd {
			sec.size = dexEnd - absOff
		}
		if sec.size == 0 {
			continue
		}
		r.SetOffset(absOff)

		switch {
		case strings.HasSuffix(sec.name, ".string_ids"):
			annotateStringIds(r, raw, sec.name, sec.size, dexStart, dexEnd, p.stringIdsSize)
		case strings.HasSuffix(sec.name, ".type_ids"):
			count := sec.size / 4
			for j := uint32(0); j < count; j++ {
				r.ReadUint32LE(
					fmt.Sprintf("%s[%d]", sec.name, j),
					fmt.Sprintf("type_ids[%d]: string_id index", j),
					fmt.Sprintf("Index into the string_ids list for the descriptor string of type identifier %d.", j))
			}
		case strings.HasSuffix(sec.name, ".proto_ids"):
			count := sec.size / 12
			for j := uint32(0); j < count; j++ {
				prefix := fmt.Sprintf("%s[%d]", sec.name, j)
				r.ReadUint32LE(prefix+".shorty_idx", "Proto shorty_idx",
					fmt.Sprintf("Index into string_ids for the shorty descriptor of prototype %d.", j))
				r.ReadUint32LE(prefix+".return_type_idx", "Proto return_type_idx",
					fmt.Sprintf("Index into type_ids for the return type of prototype %d.", j))
				r.ReadUint32LE(prefix+".parameters_off", "Proto parameters_off",
					fmt.Sprintf("Offset to type_list for parameter types of prototype %d (0 if none).", j))
			}
		case strings.HasSuffix(sec.name, ".field_ids"):
			count := sec.size / 8
			for j := uint32(0); j < count; j++ {
				prefix := fmt.Sprintf("%s[%d]", sec.name, j)
				r.ReadUint16LE(prefix+".class_idx", "Field class_idx",
					fmt.Sprintf("Index into type_ids for the definer class of field %d.", j))
				r.ReadUint16LE(prefix+".type_idx", "Field type_idx",
					fmt.Sprintf("Index into type_ids for the type of field %d.", j))
				r.ReadUint32LE(prefix+".name_idx", "Field name_idx",
					fmt.Sprintf("Index into string_ids for the name of field %d.", j))
			}
		case strings.HasSuffix(sec.name, ".method_ids"):
			count := sec.size / 8
			for j := uint32(0); j < count; j++ {
				prefix := fmt.Sprintf("%s[%d]", sec.name, j)
				r.ReadUint16LE(prefix+".class_idx", "Method class_idx",
					fmt.Sprintf("Index into type_ids for the definer class of method %d.", j))
				r.ReadUint16LE(prefix+".proto_idx", "Method proto_idx",
					fmt.Sprintf("Index into proto_ids for the prototype of method %d.", j))
				r.ReadUint32LE(prefix+".name_idx", "Method name_idx",
					fmt.Sprintf("Index into string_ids for the name of method %d.", j))
			}
		case strings.HasSuffix(sec.name, ".class_defs"):
			annotateClassDefs(r, sec.name, sec.size)
		case strings.HasSuffix(sec.name, ".map_list"):
			annotateMapList(r, raw, sec.name, absOff, sec.size, dexEnd)
		default:
			r.ReadBytes(int(sec.size), sec.name,
				fmt.Sprintf("%s (%d bytes)", sec.name, sec.size),
				sec.desc)
		}
		payloadCursor = sec.off + sec.size
	}

	// -------------------------------------------------------------------------
	// 3. Handle remaining bytes (data section): string_data_items + rest.
	// -------------------------------------------------------------------------
	if payloadCursor < effectiveSize {
		annotateStringDataItems(
			r, raw, dexIdx,
			dexStart, dexEnd, payloadCursor, effectiveSize,
			p.stringIdsOff, p.stringIdsSize,
		)
	}
}

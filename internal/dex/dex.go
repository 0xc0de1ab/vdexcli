// Package dex parses individual Android DEX files.
//
// This package is independent of the VDEX container format.
// It receives raw DEX bytes and produces a model.DexContext
// containing header fields, string table, and class descriptors.
package dex

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"hash/adler32"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func supportedDexVersion(version []byte) bool {
	if len(version) != 4 || version[3] != 0 {
		return false
	}
	switch string(version[:3]) {
	case "035", "037", "038", "039", "040", "041":
		return true
	default:
		return false
	}
}

// Parse reads a single DEX file from raw bytes starting at the given
// fileOffset within the VDEX file. It returns the parsed context, the
// number of bytes consumed, and any error.
func Parse(raw []byte, fileOffset int) (*model.DexContext, int, error) {
	return parseAt(raw, 0, fileOffset)
}

func parseAt(container []byte, headerOffset int, fileOffset int) (*model.DexContext, int, error) {
	if headerOffset < 0 || headerOffset > len(container) || len(container)-headerOffset < 0x70 {
		available := len(container) - headerOffset
		if available < 0 {
			available = 0
		}
		return nil, 0, fmt.Errorf("dex@%#x: data shorter than header (%d bytes, need 112)", fileOffset, available)
	}
	raw := container[headerOffset:]
	if !bytes.Equal(raw[0:4], []byte("dex\n")) {
		return nil, 0, fmt.Errorf("dex@%#x: invalid magic %q", fileOffset, string(raw[0:4]))
	}
	if !supportedDexVersion(raw[4:8]) {
		return nil, 0, fmt.Errorf("dex@%#x: unsupported version %q", fileOffset, string(raw[4:8]))
	}

	endianTag := binutil.ReadU32(raw, 0x28)
	switch endianTag {
	case 0x12345678:
	case 0x78563412:
		return nil, 0, fmt.Errorf("dex@%#x: reverse-endian DEX is not supported", fileOffset)
	default:
		return nil, 0, fmt.Errorf("dex@%#x: invalid endian_tag %#x", fileOffset, endianTag)
	}

	fileSize := binutil.ReadU32(raw, 0x20)
	declaredFileSize := fileSize
	if fileSize < 0x70 {
		return nil, 0, fmt.Errorf("dex@%#x: invalid file_size %d", fileOffset, fileSize)
	}
	version := string(raw[4:7])
	headerSize := binutil.ReadU32(raw, 0x24)
	expectedHeaderSize := uint32(0x70)
	if version == "041" {
		expectedHeaderSize = 0x78
	}
	if headerSize != expectedHeaderSize {
		return nil, 0, fmt.Errorf("dex@%#x: invalid header_size %#x (expected %#x)", fileOffset, headerSize, expectedHeaderSize)
	}
	if fileSize < expectedHeaderSize {
		return nil, 0, fmt.Errorf("dex@%#x: invalid file_size %d smaller than header %d", fileOffset, fileSize, expectedHeaderSize)
	}

	containerSize := fileSize
	declaredHeaderOffset := uint32(0)
	var offsetData []byte
	if version == "041" {
		if len(raw) < int(expectedHeaderSize) {
			return nil, 0, fmt.Errorf("dex@%#x: data shorter than v041 header (%d bytes, need %d)", fileOffset, len(raw), expectedHeaderSize)
		}
		containerSize = binutil.ReadU32(raw, 0x70)
		declaredHeaderOffset = binutil.ReadU32(raw, 0x74)
		if containerSize != uint32(len(container)) {
			return nil, 0, fmt.Errorf(
				"dex@%#x: container_size %#x does not match available container bytes %#x",
				fileOffset,
				containerSize,
				len(container),
			)
		}
		if declaredHeaderOffset != uint32(headerOffset) {
			return nil, 0, fmt.Errorf(
				"dex@%#x: header_offset %#x does not match container position %#x",
				fileOffset,
				declaredHeaderOffset,
				headerOffset,
			)
		}
		if declaredHeaderOffset >= containerSize || uint64(fileSize) > uint64(containerSize)-uint64(declaredHeaderOffset) {
			return nil, 0, fmt.Errorf(
				"dex@%#x: file_size %#x exceeds container remainder %#x",
				fileOffset,
				fileSize,
				uint64(containerSize)-uint64(declaredHeaderOffset),
			)
		}
		if declaredHeaderOffset%4 != 0 {
			return nil, 0, fmt.Errorf("dex@%#x: header_offset %#x is not 4-byte aligned", fileOffset, declaredHeaderOffset)
		}
		offsetData = container[:containerSize]
	} else {
		if headerOffset != 0 {
			return nil, 0, fmt.Errorf(
				"dex@%#x: non-container DEX v%s found at container offset %#x",
				fileOffset,
				version,
				headerOffset,
			)
		}
		if uint64(fileSize) > uint64(len(raw)) {
			fileSize = uint32(len(raw))
			containerSize = fileSize
		}
		offsetData = raw[:fileSize]
	}

	sig := fmt.Sprintf("%x", raw[0x0C:0x20])
	integrityEnd := int(fileSize)
	checksumValid := false
	signatureValid := false
	if integrityEnd <= len(raw) {
		computedSignature := sha1.Sum(raw[0x20:integrityEnd])
		signatureValid = bytes.Equal(raw[0x0C:0x20], computedSignature[:])
		checksumValid = binutil.ReadU32(raw, 0x08) == adler32.Checksum(raw[0x0C:integrityEnd])
	}

	stringIdsOff := binutil.ReadU32(raw, 0x3C)
	typeIdsOff := binutil.ReadU32(raw, 0x44)
	protoIdsOff := binutil.ReadU32(raw, 0x4C)
	fieldIdsOff := binutil.ReadU32(raw, 0x54)
	methodIdsOff := binutil.ReadU32(raw, 0x5C)
	classDefsOff := binutil.ReadU32(raw, 0x64)

	ctx := &model.DexContext{
		Rep: model.DexReport{
			Offset:         uint32(fileOffset),
			Size:           fileSize,
			Magic:          string(raw[0:4]),
			Version:        string(bytes.TrimRight(raw[4:8], "\x00")),
			ChecksumId:     binutil.ReadU32(raw, 0x08),
			ChecksumValid:  checksumValid,
			Signature:      sig,
			SignatureValid: signatureValid,
			FileSize:       fileSize,
			HeaderSize:     headerSize,
			ContainerSize:  containerSize,
			HeaderOffset:   declaredHeaderOffset,
			Endian:         "little-endian",
			LinkSize:       binutil.ReadU32(raw, 0x2C),
			LinkOffset:     binutil.ReadU32(raw, 0x30),
			MapOffset:      binutil.ReadU32(raw, 0x34),
			StringIds:      binutil.ReadU32(raw, 0x38),
			StringIdsOff:   stringIdsOff,
			TypeIds:        binutil.ReadU32(raw, 0x40),
			TypeIdsOff:     typeIdsOff,
			ProtoIds:       binutil.ReadU32(raw, 0x48),
			ProtoIdsOff:    protoIdsOff,
			FieldIds:       binutil.ReadU32(raw, 0x50),
			FieldIdsOff:    fieldIdsOff,
			MethodIds:      binutil.ReadU32(raw, 0x58),
			MethodIdsOff:   methodIdsOff,
			ClassDefs:      binutil.ReadU32(raw, 0x60),
			ClassDefsOff:   classDefsOff,
			DataSize:       binutil.ReadU32(raw, 0x68),
			DataOffset:     binutil.ReadU32(raw, 0x6C),
		},
		StringOffsetToName: map[uint32]string{},
	}
	if ctx.Rep.TypeIds > model.MaxTypeLookupClasses {
		return ctx, int(fileSize), fmt.Errorf(
			"dex@%#x: type_ids count %d exceeds format limit %d",
			fileOffset,
			ctx.Rep.TypeIds,
			model.MaxTypeLookupClasses,
		)
	}
	if ctx.Rep.ProtoIds > model.MaxTypeLookupClasses {
		return ctx, int(fileSize), fmt.Errorf(
			"dex@%#x: proto_ids count %d exceeds format limit %d",
			fileOffset,
			ctx.Rep.ProtoIds,
			model.MaxTypeLookupClasses,
		)
	}
	if ctx.Rep.FieldIds > model.MaxTypeLookupClasses || ctx.Rep.MethodIds > model.MaxTypeLookupClasses {
		return ctx, int(fileSize), fmt.Errorf(
			"dex@%#x: field_ids/method_ids counts %d/%d exceed format limit %d",
			fileOffset,
			ctx.Rep.FieldIds,
			ctx.Rep.MethodIds,
			model.MaxTypeLookupClasses,
		)
	}
	if ctx.Rep.ClassDefs > ctx.Rep.TypeIds {
		return ctx, int(fileSize), fmt.Errorf(
			"dex@%#x: class_defs count %d exceeds type_ids count %d",
			fileOffset,
			ctx.Rep.ClassDefs,
			ctx.Rep.TypeIds,
		)
	}

	minDataOffset := uint64(headerSize)
	if version == "041" {
		minDataOffset += uint64(declaredHeaderOffset)
	}
	for _, table := range []struct {
		name          string
		offset, count uint32
		itemSize      uint32
	}{
		{"string_ids", stringIdsOff, ctx.Rep.StringIds, 4},
		{"type_ids", typeIdsOff, ctx.Rep.TypeIds, 4},
		{"proto_ids", protoIdsOff, ctx.Rep.ProtoIds, 12},
		{"field_ids", fieldIdsOff, ctx.Rep.FieldIds, 8},
		{"method_ids", methodIdsOff, ctx.Rep.MethodIds, 8},
		{"class_defs", classDefsOff, ctx.Rep.ClassDefs, 32},
	} {
		if err := validateDataRange(table.name, table.offset, table.count, table.itemSize, 4, minDataOffset, uint64(len(offsetData))); err != nil {
			return ctx, int(fileSize), fmt.Errorf("dex@%#x: %w", fileOffset, err)
		}
	}
	if err := validateFixedTableRanges(declaredHeaderOffset, headerSize, ctx.Rep); err != nil {
		return ctx, int(fileSize), fmt.Errorf("dex@%#x: %w", fileOffset, err)
	}
	if err := validateDataRange("link", ctx.Rep.LinkOffset, ctx.Rep.LinkSize, 1, 1, minDataOffset, uint64(len(offsetData))); err != nil {
		return ctx, int(fileSize), fmt.Errorf("dex@%#x: %w", fileOffset, err)
	}
	if ctx.Rep.MapOffset != 0 {
		if err := validateDataRange("map", ctx.Rep.MapOffset, 1, 4, 4, minDataOffset, uint64(len(offsetData))); err != nil {
			return ctx, int(fileSize), fmt.Errorf("dex@%#x: %w", fileOffset, err)
		}
		if err := validateMapList(offsetData, ctx.Rep.MapOffset, declaredHeaderOffset, ctx.Rep); err != nil {
			return ctx, int(fileSize), fmt.Errorf("dex@%#x: %w", fileOffset, err)
		}
	}
	if version != "041" {
		if err := validateDataRange("data", ctx.Rep.DataOffset, ctx.Rep.DataSize, 1, 1, minDataOffset, uint64(len(offsetData))); err != nil {
			return ctx, int(fileSize), fmt.Errorf("dex@%#x: %w", fileOffset, err)
		}
	}

	if err := validateIDReferences(offsetData, ctx.Rep); err != nil {
		return ctx, int(fileSize), fmt.Errorf("dex@%#x: %w", fileOffset, err)
	}

	strs, offsetMap, serr := ParseStrings(offsetData, ctx.Rep.StringIds, stringIdsOff)
	ctx.Strings = strs
	ctx.StringOffsetToName = offsetMap
	if serr != nil {
		return ctx, int(fileSize), serr
	}

	classes, cErr := ParseClassDefs(
		offsetData,
		strs,
		ctx.Rep.TypeIds,
		typeIdsOff,
		classDefsOff,
		ctx.Rep.ClassDefs,
	)
	ctx.Rep.Classes = classes
	if cErr != nil {
		return ctx, int(fileSize), cErr
	}

	if version != "041" && uint64(declaredFileSize) > uint64(len(raw)) {
		return ctx, int(fileSize), fmt.Errorf(
			"dex@%#x: declared file_size %#x exceeds available bytes %#x",
			fileOffset,
			declaredFileSize,
			fileSize,
		)
	}
	return ctx, int(fileSize), nil
}

func validateDataRange(name string, offset, count, itemSize, alignment uint32, minOffset, limit uint64) error {
	if count == 0 {
		if offset != 0 {
			return fmt.Errorf("%s has zero size/count with non-zero offset %#x", name, offset)
		}
		return nil
	}
	if offset == 0 {
		return fmt.Errorf("%s has non-zero size/count with zero offset", name)
	}
	if alignment > 1 && offset%alignment != 0 {
		return fmt.Errorf("%s offset %#x is not %d-byte aligned", name, offset, alignment)
	}
	start := uint64(offset)
	end := start + uint64(count)*uint64(itemSize)
	if start < minOffset || end < start || end > limit {
		return fmt.Errorf(
			"%s range [%#x,%#x) outside data bounds [%#x,%#x)",
			name,
			start,
			end,
			minOffset,
			limit,
		)
	}
	return nil
}

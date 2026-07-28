// Package dex parses individual Android DEX files.
//
// This package is independent of the VDEX container format.
// It receives raw DEX bytes and produces a model.DexContext
// containing header fields, string table, and class descriptors.
package dex

import (
	"bytes"
	"fmt"

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
	if len(raw) < 0x70 {
		return nil, 0, fmt.Errorf("dex@%#x: data shorter than header (%d bytes, need 112)", fileOffset, len(raw))
	}
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
	if fileSize < 0x70 {
		return nil, 0, fmt.Errorf("dex@%#x: invalid file_size %d", fileOffset, fileSize)
	}
	headerSize := binutil.ReadU32(raw, 0x24)
	if headerSize != 0x70 {
		return nil, 0, fmt.Errorf("dex@%#x: invalid header_size %#x (expected %#x)", fileOffset, headerSize, uint32(0x70))
	}
	declaredFileSize := fileSize
	effectiveFileSize := fileSize
	if uint64(effectiveFileSize) > uint64(len(raw)) {
		effectiveFileSize = uint32(len(raw))
	}

	sig := fmt.Sprintf("%x", raw[0x0C:0x20])

	stringIdsOff := binutil.ReadU32(raw, 0x3C)
	typeIdsOff := binutil.ReadU32(raw, 0x44)
	protoIdsOff := binutil.ReadU32(raw, 0x4C)
	fieldIdsOff := binutil.ReadU32(raw, 0x54)
	methodIdsOff := binutil.ReadU32(raw, 0x5C)
	classDefsOff := binutil.ReadU32(raw, 0x64)

	ctx := &model.DexContext{
		Rep: model.DexReport{
			Offset:       uint32(fileOffset),
			Size:         effectiveFileSize,
			Magic:        string(raw[0:4]),
			Version:      string(bytes.TrimRight(raw[4:8], "\x00")),
			ChecksumId:   binutil.ReadU32(raw, 0x08),
			Signature:    sig,
			FileSize:     effectiveFileSize,
			HeaderSize:   headerSize,
			Endian:       "little-endian",
			LinkSize:     binutil.ReadU32(raw, 0x2C),
			LinkOffset:   binutil.ReadU32(raw, 0x30),
			MapOffset:    binutil.ReadU32(raw, 0x34),
			StringIds:    binutil.ReadU32(raw, 0x38),
			StringIdsOff: stringIdsOff,
			TypeIds:      binutil.ReadU32(raw, 0x40),
			TypeIdsOff:   typeIdsOff,
			ProtoIds:     binutil.ReadU32(raw, 0x48),
			ProtoIdsOff:  protoIdsOff,
			FieldIds:     binutil.ReadU32(raw, 0x50),
			FieldIdsOff:  fieldIdsOff,
			MethodIds:    binutil.ReadU32(raw, 0x58),
			MethodIdsOff: methodIdsOff,
			ClassDefs:    binutil.ReadU32(raw, 0x60),
			ClassDefsOff: classDefsOff,
			DataSize:     binutil.ReadU32(raw, 0x68),
			DataOffset:   binutil.ReadU32(raw, 0x6C),
		},
		StringOffsetToName: map[uint32]string{},
	}

	dexBytes := raw[:effectiveFileSize]
	strs, offsetMap, serr := ParseStrings(dexBytes, ctx.Rep.StringIds, stringIdsOff)
	ctx.Strings = strs
	ctx.StringOffsetToName = offsetMap
	if serr != nil {
		return ctx, int(effectiveFileSize), serr
	}

	classes, cErr := ParseClassDefs(
		dexBytes,
		strs,
		ctx.Rep.TypeIds,
		typeIdsOff,
		classDefsOff,
		ctx.Rep.ClassDefs,
	)
	ctx.Rep.Classes = classes
	if cErr != nil {
		return ctx, int(effectiveFileSize), cErr
	}

	if declaredFileSize != effectiveFileSize {
		return ctx, int(effectiveFileSize), fmt.Errorf("dex@%#x: declared file_size %#x exceeds available bytes %#x", fileOffset, declaredFileSize, effectiveFileSize)
	}
	return ctx, int(effectiveFileSize), nil
}

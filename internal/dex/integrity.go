package dex

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

const maxDexMapItems = 1 << 16
const dexNoIndex = ^uint32(0)

type mapExpectation struct {
	size   uint32
	offset uint32
}

var validDexMapTypes = map[uint16]uint32{
	0x0000: 0x70,
	0x0001: 0x04,
	0x0002: 0x04,
	0x0003: 0x0C,
	0x0004: 0x08,
	0x0005: 0x08,
	0x0006: 0x20,
	0x0007: 0x04,
	0x0008: 0x08,
	0x1000: 0,
	0x1001: 0,
	0x1002: 0,
	0x1003: 0,
	0x2000: 0,
	0x2001: 0,
	0x2002: 0,
	0x2003: 0,
	0x2004: 0,
	0x2005: 0,
	0x2006: 0,
	0xF000: 0,
}

func validateMapList(raw []byte, mapOff, headerOff uint32, rep model.DexReport) error {
	if mapOff == 0 {
		return nil
	}
	count := binary.LittleEndian.Uint32(raw[mapOff : mapOff+4])
	if count == 0 || count > maxDexMapItems {
		return fmt.Errorf("map_list size %d outside supported range [1,%d]", count, maxDexMapItems)
	}
	end := uint64(mapOff) + 4 + uint64(count)*12
	if end > uint64(len(raw)) {
		return fmt.Errorf("map_list needs %#x bytes at %#x, dex size is %#x", end-uint64(mapOff), mapOff, len(raw))
	}

	expected := map[uint16]mapExpectation{
		0x0000: {size: 1, offset: headerOff},
		0x0001: {size: rep.StringIds, offset: rep.StringIdsOff},
		0x0002: {size: rep.TypeIds, offset: rep.TypeIdsOff},
		0x0003: {size: rep.ProtoIds, offset: rep.ProtoIdsOff},
		0x0004: {size: rep.FieldIds, offset: rep.FieldIdsOff},
		0x0005: {size: rep.MethodIds, offset: rep.MethodIdsOff},
		0x0006: {size: rep.ClassDefs, offset: rep.ClassDefsOff},
		0x1000: {size: 1, offset: mapOff},
	}
	seen := make(map[uint16]struct{}, min(int(count), 64))
	for index := uint32(0); index < count; index++ {
		base := int(mapOff) + 4 + int(index)*12
		itemType := binary.LittleEndian.Uint16(raw[base:])
		if _, knownType := validDexMapTypes[itemType]; !knownType {
			return fmt.Errorf("map_item[%d] has unknown type %#x", index, itemType)
		}
		if _, duplicate := seen[itemType]; duplicate {
			return fmt.Errorf("map_item[%d] duplicates type %#x", index, itemType)
		}
		seen[itemType] = struct{}{}
	}
	var previousOffset uint32
	for index := uint32(0); index < count; index++ {
		base := int(mapOff) + 4 + int(index)*12
		itemType := binary.LittleEndian.Uint16(raw[base:])
		unused := binary.LittleEndian.Uint16(raw[base+2:])
		size := binary.LittleEndian.Uint32(raw[base+4:])
		offset := binary.LittleEndian.Uint32(raw[base+8:])
		itemSize := validDexMapTypes[itemType]
		if unused != 0 {
			return fmt.Errorf("map_item[%d] unused field is %#x, expected zero", index, unused)
		}
		if size == 0 {
			return fmt.Errorf("map_item[%d] type %#x has zero size", index, itemType)
		}
		if uint64(offset) >= uint64(len(raw)) || offset < headerOff {
			return fmt.Errorf("map_item[%d] type %#x offset %#x outside owned DEX range [%#x,%#x)", index, itemType, offset, headerOff, len(raw))
		}
		if index > 0 && offset < previousOffset {
			return fmt.Errorf("map_item[%d] offset %#x precedes previous offset %#x", index, offset, previousOffset)
		}
		if itemSize != 0 || itemType == 0x1000 {
			itemEnd := uint64(offset) + uint64(size)*uint64(itemSize)
			switch itemType {
			case 0x0000:
				itemEnd = uint64(offset) + uint64(rep.HeaderSize)
			case 0x1000:
				itemEnd = uint64(offset) + 4 + uint64(size)*12
			}
			if itemEnd > uint64(len(raw)) {
				return fmt.Errorf("map_item[%d] type %#x range [%#x,%#x) exceeds DEX size %#x", index, itemType, offset, itemEnd, len(raw))
			}
			if index+1 < count {
				nextBase := base + 12
				nextOffset := binary.LittleEndian.Uint32(raw[nextBase+8:])
				if itemEnd > uint64(nextOffset) {
					return fmt.Errorf("map_item[%d] type %#x range ending at %#x overlaps next item at %#x", index, itemType, itemEnd, nextOffset)
				}
			}
		}
		previousOffset = offset
		if want, known := expected[itemType]; known &&
			(size != want.size || offset != want.offset) {
			return fmt.Errorf(
				"map_item[%d] type %#x has size/off %d/%#x, header declares %d/%#x",
				index,
				itemType,
				size,
				offset,
				want.size,
				want.offset,
			)
		}
	}
	for itemType, want := range expected {
		if want.size == 0 {
			continue
		}
		if _, present := seen[itemType]; !present {
			return fmt.Errorf("map_list is missing type %#x declared by the DEX header", itemType)
		}
	}
	return nil
}

type dexRange struct {
	name       string
	start, end uint64
}

func validateFixedTableRanges(headerOff, headerSize uint32, rep model.DexReport) error {
	ranges := []dexRange{{
		name:  "header",
		start: uint64(headerOff),
		end:   uint64(headerOff) + uint64(headerSize),
	}}
	for _, table := range []struct {
		name                  string
		offset, count, stride uint32
	}{
		{"string_ids", rep.StringIdsOff, rep.StringIds, 4},
		{"type_ids", rep.TypeIdsOff, rep.TypeIds, 4},
		{"proto_ids", rep.ProtoIdsOff, rep.ProtoIds, 12},
		{"field_ids", rep.FieldIdsOff, rep.FieldIds, 8},
		{"method_ids", rep.MethodIdsOff, rep.MethodIds, 8},
		{"class_defs", rep.ClassDefsOff, rep.ClassDefs, 32},
	} {
		if table.count == 0 {
			continue
		}
		ranges = append(ranges, dexRange{
			name:  table.name,
			start: uint64(table.offset),
			end:   uint64(table.offset) + uint64(table.count)*uint64(table.stride),
		})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})
	for index := 1; index < len(ranges); index++ {
		if ranges[index].start < ranges[index-1].end {
			return fmt.Errorf(
				"%s range [%#x,%#x) overlaps %s range [%#x,%#x)",
				ranges[index-1].name,
				ranges[index-1].start,
				ranges[index-1].end,
				ranges[index].name,
				ranges[index].start,
				ranges[index].end,
			)
		}
	}
	return nil
}

func validateIDReferences(raw []byte, rep model.DexReport) error {
	for index := uint32(0); index < rep.TypeIds; index++ {
		offset := int(rep.TypeIdsOff + index*4)
		descriptorIndex := binary.LittleEndian.Uint32(raw[offset:])
		if descriptorIndex >= rep.StringIds {
			return fmt.Errorf("type_id[%d] descriptor_idx %d outside string_ids count %d", index, descriptorIndex, rep.StringIds)
		}
	}
	for index := uint32(0); index < rep.ProtoIds; index++ {
		offset := int(rep.ProtoIdsOff + index*12)
		shortyIndex := binary.LittleEndian.Uint32(raw[offset:])
		returnTypeIndex := binary.LittleEndian.Uint32(raw[offset+4:])
		if shortyIndex >= rep.StringIds {
			return fmt.Errorf("proto_id[%d] shorty_idx %d outside string_ids count %d", index, shortyIndex, rep.StringIds)
		}
		if returnTypeIndex >= rep.TypeIds {
			return fmt.Errorf("proto_id[%d] return_type_idx %d outside type_ids count %d", index, returnTypeIndex, rep.TypeIds)
		}
	}
	for index := uint32(0); index < rep.FieldIds; index++ {
		offset := int(rep.FieldIdsOff + index*8)
		classIndex := uint32(binary.LittleEndian.Uint16(raw[offset:]))
		typeIndex := uint32(binary.LittleEndian.Uint16(raw[offset+2:]))
		nameIndex := binary.LittleEndian.Uint32(raw[offset+4:])
		if classIndex >= rep.TypeIds || typeIndex >= rep.TypeIds || nameIndex >= rep.StringIds {
			return fmt.Errorf("field_id[%d] contains an out-of-range class, type, or name index", index)
		}
	}
	for index := uint32(0); index < rep.MethodIds; index++ {
		offset := int(rep.MethodIdsOff + index*8)
		classIndex := uint32(binary.LittleEndian.Uint16(raw[offset:]))
		protoIndex := uint32(binary.LittleEndian.Uint16(raw[offset+2:]))
		nameIndex := binary.LittleEndian.Uint32(raw[offset+4:])
		if classIndex >= rep.TypeIds || protoIndex >= rep.ProtoIds || nameIndex >= rep.StringIds {
			return fmt.Errorf("method_id[%d] contains an out-of-range class, proto, or name index", index)
		}
	}
	for index := uint32(0); index < rep.ClassDefs; index++ {
		offset := int(rep.ClassDefsOff + index*32)
		classIndex := binary.LittleEndian.Uint32(raw[offset:])
		superclassIndex := binary.LittleEndian.Uint32(raw[offset+8:])
		if classIndex >= rep.TypeIds {
			return fmt.Errorf("class_def[%d] class_idx %d outside type_ids count %d", index, classIndex, rep.TypeIds)
		}
		if superclassIndex != dexNoIndex && superclassIndex >= rep.TypeIds {
			return fmt.Errorf("class_def[%d] superclass_idx %d outside type_ids count %d", index, superclassIndex, rep.TypeIds)
		}
	}
	return nil
}

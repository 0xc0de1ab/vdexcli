package dex

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
)

// ParseStrings reads the string_ids table and resolves each entry to its
// modified UTF-8 value. Returns both an ordered slice and an offset→string map
// used by the type lookup table.
func ParseStrings(raw []byte, stringCount uint32, stringIdOff uint32) ([]string, map[uint32]string, error) {
	if stringCount == 0 {
		return []string{}, map[uint32]string{}, nil
	}
	tableEnd := uint64(stringIdOff) + uint64(stringCount)*4
	if tableEnd > uint64(len(raw)) {
		return nil, nil, fmt.Errorf("dex: string_ids table out of range (off=%#x count=%d, dex size=%d)", stringIdOff, stringCount, len(raw))
	}
	count := int(stringCount)
	tableOffset := int(stringIdOff)
	out := make([]string, count)
	offsetMap := make(map[uint32]string, count)
	offsets := make([]uint32, count)
	for i := 0; i < count; i++ {
		stringOffset := binutil.ReadU32(raw, tableOffset+i*4)
		if uint64(stringOffset) >= uint64(len(raw)) {
			return out, offsetMap, fmt.Errorf("string_id[%d] points to invalid offset %#x", i, stringOffset)
		}
		offsets[i] = stringOffset
	}

	uniqueOffsets := append([]uint32(nil), offsets...)
	sort.Slice(uniqueOffsets, func(i, j int) bool { return uniqueOffsets[i] < uniqueOffsets[j] })
	uniqueOffsets = compactOffsets(uniqueOffsets)

	decoded := make(map[uint32]string, len(uniqueOffsets))
	for i, stringOffset := range uniqueOffsets {
		limit := len(raw)
		if i+1 < len(uniqueOffsets) {
			limit = int(uniqueOffsets[i+1])
		}
		off := int(stringOffset)
		s, _, err := parseModifiedUtf8(raw[:limit], off)
		if err != nil {
			return out, offsetMap, fmt.Errorf("string data at %#x: %w", stringOffset, err)
		}
		offsetMap[stringOffset] = s
		decoded[stringOffset] = s
	}

	for i, stringOffset := range offsets {
		out[i] = decoded[stringOffset]
	}
	return out, offsetMap, nil
}

func compactOffsets(offsets []uint32) []uint32 {
	if len(offsets) < 2 {
		return offsets
	}
	write := 1
	for read := 1; read < len(offsets); read++ {
		if offsets[read] == offsets[write-1] {
			continue
		}
		offsets[write] = offsets[read]
		write++
	}
	return offsets[:write]
}

func parseModifiedUtf8(raw []byte, off int) (string, int, error) {
	if off < 0 || off >= len(raw) {
		return "", 0, fmt.Errorf("dex: string offset %#x out of range (size=%d)", off, len(raw))
	}
	_, l, err := binutil.ReadULEB128(raw, off)
	if err != nil {
		return "", 0, fmt.Errorf("dex: string@%#x: %w", off, err)
	}
	start := off + l
	if start >= len(raw) {
		return "", 0, fmt.Errorf("dex: string@%#x: malformed modified UTF-8 (data starts beyond end)", off)
	}
	n := bytes.IndexByte(raw[start:], 0)
	if n < 0 {
		return "", 0, fmt.Errorf("dex: string@%#x: unterminated (no null byte found)", off)
	}
	return string(raw[start : start+n]), l + n + 1, nil
}

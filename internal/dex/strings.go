package dex

import (
	"bytes"
	"fmt"

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
	decoded := make(map[uint32]string)
	for i := 0; i < count; i++ {
		stringOffset := binutil.ReadU32(raw, tableOffset+i*4)
		if uint64(stringOffset) >= uint64(len(raw)) {
			return out, offsetMap, fmt.Errorf("string_id[%d] points to invalid offset %#x", i, stringOffset)
		}
		if cached, ok := decoded[stringOffset]; ok {
			out[i] = cached
			continue
		}
		off := int(stringOffset)
		s, _, err := parseModifiedUtf8(raw, off)
		if err != nil {
			return out, offsetMap, fmt.Errorf("string_id[%d]: %w", i, err)
		}
		out[i] = s
		offsetMap[stringOffset] = s
		decoded[stringOffset] = s
	}
	return out, offsetMap, nil
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

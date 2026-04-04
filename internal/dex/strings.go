package dex

import (
	"bytes"
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
)

// ParseStrings reads the string_ids table and resolves each entry to its
// modified UTF-8 value. Returns both an ordered slice and an offset→string map
// used by the type lookup table.
func ParseStrings(raw []byte, stringCount int, stringIdOff int) ([]string, map[uint32]string, error) {
	if stringCount == 0 {
		return []string{}, map[uint32]string{}, nil
	}
	if stringIdOff < 0 || stringIdOff+stringCount*4 > len(raw) {
		return nil, nil, fmt.Errorf("invalid string_ids table range")
	}
	out := make([]string, stringCount)
	offsetMap := make(map[uint32]string, stringCount)
	for i := 0; i < stringCount; i++ {
		off := int(binutil.ReadU32(raw, stringIdOff+i*4))
		if off < 0 || off >= len(raw) {
			return out, offsetMap, fmt.Errorf("string_id[%d] points to invalid offset %#x", i, off)
		}
		s, _, err := parseModifiedUtf8(raw, off)
		if err != nil {
			return out, offsetMap, fmt.Errorf("string_id[%d]: %w", i, err)
		}
		out[i] = s
		offsetMap[uint32(off)] = s
	}
	return out, offsetMap, nil
}

func parseModifiedUtf8(raw []byte, off int) (string, int, error) {
	if off < 0 || off >= len(raw) {
		return "", 0, fmt.Errorf("string offset invalid")
	}
	_, l, err := binutil.ReadULEB128(raw, off)
	if err != nil {
		return "", 0, err
	}
	start := off + l
	if start >= len(raw) {
		return "", 0, fmt.Errorf("malformed modified UTF-8")
	}
	n := bytes.IndexByte(raw[start:], 0)
	if n < 0 {
		return "", 0, fmt.Errorf("unterminated string")
	}
	return string(raw[start : start+n]), l + n + 1, nil
}

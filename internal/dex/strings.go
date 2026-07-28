package dex

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
)

const maxDexStringIDs = 250_000

// ParseStrings reads the string_ids table and resolves each entry to its
// modified UTF-8 value. Returns both an ordered slice and an offset→string map
// used by the type lookup table.
func ParseStrings(raw []byte, stringCount uint32, stringIdOff uint32) ([]string, map[uint32]string, error) {
	if stringCount == 0 {
		return []string{}, map[uint32]string{}, nil
	}
	if stringCount > maxDexStringIDs {
		return nil, nil, fmt.Errorf(
			"dex: string_ids count %d exceeds safety limit %d",
			stringCount,
			maxDexStringIDs,
		)
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
	}

	for i, stringOffset := range offsets {
		out[i] = offsetMap[stringOffset]
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
	declaredLength, l, err := binutil.ReadULEB128(raw, off)
	if err != nil {
		return "", 0, fmt.Errorf("dex: string@%#x: %w", off, err)
	}
	start := off + l
	if start >= len(raw) {
		return "", 0, fmt.Errorf("dex: string@%#x: malformed modified UTF-8 (data starts beyond end)", off)
	}
	var out strings.Builder
	growHint := uint64(declaredLength)
	if available := uint64(len(raw) - start); growHint > available {
		growHint = available
	}
	out.Grow(int(growHint))
	utf16Length := uint32(0)
	pendingHigh := uint16(0)
	cursor := start
	for cursor < len(raw) {
		first := raw[cursor]
		if first == 0 {
			if pendingHigh != 0 {
				out.WriteRune(utf8.RuneError)
			}
			if utf16Length != declaredLength {
				return "", 0, fmt.Errorf(
					"dex: string@%#x: utf16_size=%d but decoded %d code units",
					off,
					declaredLength,
					utf16Length,
				)
			}
			return out.String(), cursor - off + 1, nil
		}

		codeUnit, width, decodeErr := decodeMUTF8CodeUnit(raw[cursor:])
		if decodeErr != nil {
			return "", 0, fmt.Errorf("dex: string@%#x: %w", off, decodeErr)
		}
		cursor += width
		utf16Length++

		switch {
		case pendingHigh != 0:
			if codeUnit >= 0xDC00 && codeUnit <= 0xDFFF {
				out.WriteRune(utf16.DecodeRune(rune(pendingHigh), rune(codeUnit)))
				pendingHigh = 0
				continue
			}
			out.WriteRune(utf8.RuneError)
			pendingHigh = 0
			if codeUnit >= 0xD800 && codeUnit <= 0xDBFF {
				pendingHigh = codeUnit
			} else if codeUnit >= 0xDC00 && codeUnit <= 0xDFFF {
				out.WriteRune(utf8.RuneError)
			} else {
				out.WriteRune(rune(codeUnit))
			}
		case codeUnit >= 0xD800 && codeUnit <= 0xDBFF:
			pendingHigh = codeUnit
		case codeUnit >= 0xDC00 && codeUnit <= 0xDFFF:
			out.WriteRune(utf8.RuneError)
		default:
			out.WriteRune(rune(codeUnit))
		}
	}
	return "", 0, fmt.Errorf("dex: string@%#x: unterminated (no null byte found)", off)
}

func decodeMUTF8CodeUnit(raw []byte) (uint16, int, error) {
	if len(raw) == 0 {
		return 0, 0, fmt.Errorf("truncated modified UTF-8 sequence")
	}
	first := raw[0]
	switch {
	case first >= 0x01 && first <= 0x7F:
		return uint16(first), 1, nil
	case first >= 0xC0 && first <= 0xDF:
		if len(raw) < 2 || raw[1]&0xC0 != 0x80 {
			return 0, 0, fmt.Errorf("invalid 2-byte modified UTF-8 sequence")
		}
		value := uint16(first&0x1F)<<6 | uint16(raw[1]&0x3F)
		if value == 0 {
			if first != 0xC0 || raw[1] != 0x80 {
				return 0, 0, fmt.Errorf("invalid modified UTF-8 NUL encoding")
			}
		} else if value < 0x80 {
			return 0, 0, fmt.Errorf("overlong modified UTF-8 sequence")
		}
		return value, 2, nil
	case first >= 0xE0 && first <= 0xEF:
		if len(raw) < 3 || raw[1]&0xC0 != 0x80 || raw[2]&0xC0 != 0x80 {
			return 0, 0, fmt.Errorf("invalid 3-byte modified UTF-8 sequence")
		}
		value := uint16(first&0x0F)<<12 | uint16(raw[1]&0x3F)<<6 | uint16(raw[2]&0x3F)
		if value < 0x800 {
			return 0, 0, fmt.Errorf("overlong modified UTF-8 sequence")
		}
		return value, 3, nil
	default:
		return 0, 0, fmt.Errorf("invalid modified UTF-8 leading byte %#x", first)
	}
}

// Package binutil provides low-level binary reading/writing helpers
// shared across parser and modifier packages.
package binutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"
)

func ReadU32(raw []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(raw[off : off+4])
}

func ReadULEB128(raw []byte, off int) (uint32, int, error) {
	var value uint32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(raw) {
			return 0, 0, fmt.Errorf("uleb128 out of bounds")
		}
		b := raw[off+i]
		value |= uint32(b&0x7f) << shift
		if (b & 0x80) == 0 {
			return value, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("uleb128 overflow")
}

func EncodeULEB128(out []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

func ReadCString(raw []byte) string {
	n := bytes.IndexByte(raw, 0)
	if n < 0 {
		return string(raw)
	}
	return string(raw[:n])
}

// DecodeCStringOffsets decodes unique NUL-terminated strings without allowing
// one entry to scan or copy through the start of the next entry.
func DecodeCStringOffsets(raw []byte, offsets []int, minOffset, endOffset int) (map[int]string, map[int]error) {
	decoded := make(map[int]string, len(offsets))
	failures := make(map[int]error)
	if minOffset < 0 || endOffset < minOffset || endOffset > len(raw) {
		err := fmt.Errorf("invalid C-string table bounds [%#x,%#x)", minOffset, endOffset)
		for _, off := range offsets {
			failures[off] = err
		}
		return decoded, failures
	}

	unique := append([]int(nil), offsets...)
	sort.Ints(unique)
	write := 0
	for _, off := range unique {
		if write > 0 && off == unique[write-1] {
			continue
		}
		unique[write] = off
		write++
	}
	unique = unique[:write]

	for i, off := range unique {
		if off < minOffset || off >= endOffset {
			failures[off] = fmt.Errorf("C-string offset %#x outside [%#x,%#x)", off, minOffset, endOffset)
			continue
		}
		limit := endOffset
		if i+1 < len(unique) && unique[i+1] < limit {
			limit = unique[i+1]
		}
		if limit <= off {
			failures[off] = fmt.Errorf("C-string offset %#x has no available data", off)
			continue
		}
		n := bytes.IndexByte(raw[off:limit], 0)
		if n < 0 {
			failures[off] = fmt.Errorf("C-string at %#x overlaps the next entry or is unterminated", off)
			continue
		}
		decoded[off] = string(raw[off : off+n])
	}
	return decoded, failures
}

func AppendUint32LE(out []byte, v uint32) []byte {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], v)
	return append(out, n[:]...)
}

func Align4(v int) int {
	return (v + 3) &^ 3
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MinimumBitsToStore(v uint32) uint32 {
	if v == 0 {
		return 0
	}
	// bits.Len32 returns the position of the highest set bit + 1
	return uint32(bits.Len32(v))
}

func CalcPercent(v, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(v) / float64(total) * 100
}

// TrimNulls removes trailing null bytes from b and returns the result.
// It does not allocate a new slice; it returns a sub-slice of b.
func TrimNulls(b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			return b[:i+1]
		}
	}
	return b[:0]
}

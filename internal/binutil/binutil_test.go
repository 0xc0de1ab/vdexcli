package binutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ReadU32 ---

func TestReadU32(t *testing.T) {
	raw := []byte{0x78, 0x56, 0x34, 0x12, 0xFF, 0xFF, 0xFF, 0xFF}
	assert.Equal(t, uint32(0x12345678), ReadU32(raw, 0))
	assert.Equal(t, uint32(0xFFFFFFFF), ReadU32(raw, 4))
}

// --- ReadULEB128 ---

func TestReadULEB128_SingleByte(t *testing.T) {
	// 0x00 = 0, 0x7F = 127
	val, n, err := ReadULEB128([]byte{0x00}, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), val)
	assert.Equal(t, 1, n)

	val, n, err = ReadULEB128([]byte{0x7F}, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(127), val)
	assert.Equal(t, 1, n)
}

func TestReadULEB128_MultiByte(t *testing.T) {
	// 128 = 0x80 0x01
	val, n, err := ReadULEB128([]byte{0x80, 0x01}, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(128), val)
	assert.Equal(t, 2, n)

	// 624485 = 0xE5 0x8E 0x26
	val, n, err = ReadULEB128([]byte{0xE5, 0x8E, 0x26}, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(624485), val)
	assert.Equal(t, 3, n)
}

func TestReadULEB128_WithOffset(t *testing.T) {
	raw := []byte{0xFF, 0xFF, 0x05, 0x00} // value 5 at offset 2
	val, n, err := ReadULEB128(raw, 2)
	require.NoError(t, err)
	assert.Equal(t, uint32(5), val)
	assert.Equal(t, 1, n)
}

func TestReadULEB128_OutOfBounds(t *testing.T) {
	_, _, err := ReadULEB128([]byte{0x80}, 0) // needs continuation but no more bytes
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of bounds")
}

func TestReadULEB128_Overflow(t *testing.T) {
	// 6-byte LEB128 (more than 5 bytes = overflow for uint32)
	raw := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	_, _, err := ReadULEB128(raw, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "overflow")
}

func TestReadULEB128_EmptySlice(t *testing.T) {
	_, _, err := ReadULEB128([]byte{}, 0)
	assert.Error(t, err)
}

// --- EncodeULEB128 ---

func TestEncodeULEB128_Roundtrip(t *testing.T) {
	values := []uint32{0, 1, 127, 128, 255, 624485, 0xFFFFFFFF}
	for _, v := range values {
		encoded := EncodeULEB128(nil, v)
		decoded, n, err := ReadULEB128(encoded, 0)
		require.NoError(t, err, "value=%d", v)
		assert.Equal(t, v, decoded, "value=%d", v)
		assert.Equal(t, len(encoded), n, "value=%d consumed bytes", v)
	}
}

func TestEncodeULEB128_KnownValues(t *testing.T) {
	assert.Equal(t, []byte{0x00}, EncodeULEB128(nil, 0))
	assert.Equal(t, []byte{0x05}, EncodeULEB128(nil, 5))
	assert.Equal(t, []byte{0x80, 0x01}, EncodeULEB128(nil, 128))
}

// --- ReadCString ---

func TestReadCString_NullTerminated(t *testing.T) {
	assert.Equal(t, "hello", ReadCString([]byte("hello\x00world")))
}

func TestReadCString_NoNull(t *testing.T) {
	assert.Equal(t, "hello", ReadCString([]byte("hello")))
}

func TestReadCString_EmptyString(t *testing.T) {
	assert.Equal(t, "", ReadCString([]byte{0x00, 0x41}))
}

// --- AppendUint32LE ---

func TestAppendUint32LE(t *testing.T) {
	buf := AppendUint32LE(nil, 0x12345678)
	assert.Equal(t, []byte{0x78, 0x56, 0x34, 0x12}, buf)
}

func TestAppendUint32LE_Append(t *testing.T) {
	buf := []byte{0xAA}
	buf = AppendUint32LE(buf, 1)
	assert.Len(t, buf, 5)
	assert.Equal(t, byte(0xAA), buf[0])
	assert.Equal(t, uint32(1), ReadU32(buf, 1))
}

// --- Align4 ---

func TestAlign4(t *testing.T) {
	assert.Equal(t, 0, Align4(0))
	assert.Equal(t, 4, Align4(1))
	assert.Equal(t, 4, Align4(2))
	assert.Equal(t, 4, Align4(3))
	assert.Equal(t, 4, Align4(4))
	assert.Equal(t, 8, Align4(5))
	assert.Equal(t, 100, Align4(100))
	assert.Equal(t, 104, Align4(101))
}

// --- MinInt ---

func TestMinInt(t *testing.T) {
	assert.Equal(t, 3, MinInt(3, 5))
	assert.Equal(t, 3, MinInt(5, 3))
	assert.Equal(t, -1, MinInt(-1, 0))
	assert.Equal(t, 0, MinInt(0, 0))
}

// --- MinimumBitsToStore ---

func TestMinimumBitsToStore(t *testing.T) {
	assert.Equal(t, uint32(0), MinimumBitsToStore(0))
	assert.Equal(t, uint32(1), MinimumBitsToStore(1))
	assert.Equal(t, uint32(2), MinimumBitsToStore(2))
	assert.Equal(t, uint32(2), MinimumBitsToStore(3))
	assert.Equal(t, uint32(8), MinimumBitsToStore(255))
	assert.Equal(t, uint32(16), MinimumBitsToStore(0xFFFF))
}

// --- CalcPercent ---

func TestCalcPercent(t *testing.T) {
	assert.InDelta(t, 50.0, CalcPercent(1, 2), 0.01)
	assert.InDelta(t, 100.0, CalcPercent(5, 5), 0.01)
	assert.InDelta(t, 0.0, CalcPercent(0, 100), 0.01)
	assert.InDelta(t, 0.0, CalcPercent(5, 0), 0.01, "zero total returns 0")
	assert.InDelta(t, 0.0, CalcPercent(5, -1), 0.01, "negative total returns 0")
}

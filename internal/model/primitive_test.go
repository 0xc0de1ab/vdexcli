package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestByteArray_JSONNumberArrayRoundTrip(t *testing.T) {
	original := ByteArray{0, 1, 127, 255}

	encoded, err := json.Marshal(original)
	require.NoError(t, err)
	assert.JSONEq(t, `[0,1,127,255]`, string(encoded))

	var decoded ByteArray
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, original, decoded)
}

func TestByteArray_UnmarshalsLegacyBase64(t *testing.T) {
	var decoded ByteArray

	require.NoError(t, json.Unmarshal([]byte(`"dmRleA=="`), &decoded))
	assert.Equal(t, ByteArray("vdex"), decoded)
}

func TestByteArray_RejectsOutOfRangeValue(t *testing.T) {
	var decoded ByteArray

	err := json.Unmarshal([]byte(`[256]`), &decoded)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

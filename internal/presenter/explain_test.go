package presenter

import (
	"bytes"
	"testing"

	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteExplain_TableText(t *testing.T) {
	pm := &model.PrimitiveMap{
		Fields: []*model.PrimitiveField{
			{
				Offset:      0,
				Size:        4,
				Type:        model.TypeMagic,
				RawBytes:    []byte("vdex"),
				ParsedValue: "vdex",
				LogicalPath: "vdex.header.magic",
				Summary:     "VDEX magic",
				Description: "Identifies the file as a VDEX file.",
			},
			{
				Offset:      4,
				Size:        4,
				Type:        model.TypeCString,
				RawBytes:    []byte("027\x00"),
				ParsedValue: "027",
				LogicalPath: "vdex.header.version",
				Summary:     "VDEX version",
				Description: "The version of the VDEX format.",
			},
		},
		TotalBytes: 8,
	}

	// Test Text output
	var buf bytes.Buffer
	err := WriteExplain(&buf, pm, "text", nil)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "[Offset]")
	assert.Contains(t, out, "0x00000000")
	assert.Contains(t, out, "vdex.header.magic")
	assert.Contains(t, out, "magic")
	assert.Contains(t, out, "0x00000004")
	assert.Contains(t, out, "vdex.header.version")
}

func TestWriteExplain_JSON(t *testing.T) {
	pm := &model.PrimitiveMap{
		Fields: []*model.PrimitiveField{
			{
				Offset:      0,
				Size:        4,
				Type:        model.TypeMagic,
				RawBytes:    []byte("vdex"),
				ParsedValue: "vdex",
				LogicalPath: "vdex.header.magic",
				Summary:     "VDEX magic",
				Description: "Identifies the file as a VDEX file.",
			},
		},
		TotalBytes: 4,
	}

	var buf bytes.Buffer
	err := WriteExplain(&buf, pm, "json", nil)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, `"offset": 0`)
	assert.Contains(t, out, `"logical_path": "vdex.header.magic"`)
}

func TestWriteExplain_OffsetFilter(t *testing.T) {
	pm := &model.PrimitiveMap{
		Fields: []*model.PrimitiveField{
			{
				Offset:      0,
				Size:        4,
				Type:        model.TypeMagic,
				RawBytes:    []byte("vdex"),
				ParsedValue: "vdex",
				LogicalPath: "vdex.header.magic",
				Summary:     "VDEX magic",
				Description: "Identifies the file as a VDEX file.",
			},
			{
				Offset:      4,
				Size:        4,
				Type:        model.TypeCString,
				RawBytes:    []byte("027\x00"),
				ParsedValue: "027",
				LogicalPath: "vdex.header.version",
				Summary:     "VDEX version",
				Description: "The version of the VDEX format.",
			},
		},
		TotalBytes: 8,
	}

	// 1. Text format single field
	offset := uint32(5) // falls inside version field (4 to 7)
	var buf bytes.Buffer
	err := WriteExplain(&buf, pm, "text", &offset)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Field Details at Offset 0x00000004:")
	assert.Contains(t, out, "vdex.header.version")
	assert.Contains(t, out, "The version of the VDEX format.")

	// 2. JSON format single field
	buf.Reset()
	err = WriteExplain(&buf, pm, "json", &offset)
	require.NoError(t, err)

	out = buf.String()
	assert.Contains(t, out, `"offset": 4`)
	assert.Contains(t, out, `"logical_path": "vdex.header.version"`)

	// 3. Not found
	offset = uint32(9)
	buf.Reset()
	err = WriteExplain(&buf, pm, "text", &offset)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No field found containing offset 0x9")
}

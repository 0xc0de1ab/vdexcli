package modifier

import (
	"encoding/binary"
	"sort"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// RelayoutVdex rebuilds a VDEX file with a replaced section payload.
// When a new payload is larger than the original section, subsequent
// sections are shifted to accommodate the change. Section header offsets
// are updated accordingly.
//
// The function preserves the 12-byte VdexFileHeader and rewrites
// the 48-byte section header table followed by each section's data
// in offset order with 4-byte alignment padding.
func RelayoutVdex(raw []byte, sections []model.VdexSection, targetKind uint32, newPayload []byte) []byte {
	headerSize := 12 + len(sections)*12

	// Sort sections by offset (skip zero-size sections for ordering).
	type entry struct {
		kind   uint32
		offset uint32
		size   uint32
	}
	ordered := make([]entry, 0, len(sections))
	for _, s := range sections {
		ordered = append(ordered, entry{kind: s.Kind, offset: s.Offset, size: s.Size})
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].offset < ordered[j].offset
	})

	// Build new file: header (placeholder) + sections in order.
	out := make([]byte, headerSize)
	copy(out[:12], raw[:12]) // VdexFileHeader

	// Track new offsets/sizes per section kind.
	newHeaders := make(map[uint32]model.VdexSection)

	for _, e := range ordered {
		var data []byte
		if e.kind == targetKind {
			data = newPayload
		} else if e.size == 0 {
			// Zero-size section (e.g., empty DexFileSection in DM format).
			newHeaders[e.kind] = model.VdexSection{
				Kind:   e.kind,
				Offset: 0,
				Size:   0,
			}
			continue
		} else {
			end := int(e.offset) + int(e.size)
			if end > len(raw) {
				end = len(raw)
			}
			data = raw[e.offset:end]
		}

		// 4-byte alignment padding.
		aligned := binutil.Align4(len(out))
		for len(out) < aligned {
			out = append(out, 0)
		}

		newHeaders[e.kind] = model.VdexSection{
			Kind:   e.kind,
			Offset: uint32(len(out)),
			Size:   uint32(len(data)),
		}
		out = append(out, data...)
	}

	// Write section header table at offset 12.
	for i, s := range sections {
		ns, ok := newHeaders[s.Kind]
		if !ok {
			ns = model.VdexSection{Kind: s.Kind, Offset: 0, Size: 0}
		}
		base := 12 + i*12
		binary.LittleEndian.PutUint32(out[base:], ns.Kind)
		binary.LittleEndian.PutUint32(out[base+4:], ns.Offset)
		binary.LittleEndian.PutUint32(out[base+8:], ns.Size)
	}

	return out
}

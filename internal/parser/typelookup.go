package parser

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseTypeLookupSection parses the kTypeLookupTableSection.
// Each per-dex block starts with a uint32 raw-size followed by
// that many bytes of 8-byte hash table entries.
func ParseTypeLookupSection(raw []byte, s model.VdexSection, dexes []*model.DexContext, expected int) (*model.TypeLookupReport, []string) {
	out := &model.TypeLookupReport{
		Offset: s.Offset,
		Size:   s.Size,
	}
	var warnings []string
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end > len(raw) {
		warnings = append(warnings, "type-lookup section out of file range")
		return out, warnings
	}
	if expected == 0 {
		expected = len(dexes)
	}

	cursor := start
	for i := 0; i < expected; i++ {
		if cursor+4 > end {
			warnings = append(warnings, fmt.Sprintf("type-lookup section truncated before dex %d", i))
			break
		}
		size := int(binutil.ReadU32(raw, cursor))
		cursor += 4
		if cursor+size > end {
			warnings = append(warnings, fmt.Sprintf("type-lookup dex %d size %d exceeds section", i, size))
			break
		}
		var d *model.DexContext
		if i < len(dexes) {
			d = dexes[i]
		}
		rep := parseTypeLookupDex(raw[cursor:cursor+size], d)
		rep.DexIndex = i
		out.Dexes = append(out.Dexes, rep)
		cursor += size
	}
	return out, warnings
}

func parseTypeLookupDex(raw []byte, dex *model.DexContext) model.TypeLookupDexReport {
	out := model.TypeLookupDexReport{
		RawSize: uint32(len(raw)),
	}
	if len(raw) == 0 {
		out.Warnings = append(out.Warnings, "empty payload")
		return out
	}
	if len(raw)%8 != 0 {
		out.Warnings = append(out.Warnings, "payload size is not aligned to 8-byte entries; last entry may be truncated")
		raw = raw[:len(raw)-(len(raw)%8)]
	}

	buckets := len(raw) / 8
	out.BucketCount = buckets
	if buckets == 0 {
		out.Warnings = append(out.Warnings, "empty table")
		return out
	}

	classDefs := uint32(0)
	if dex != nil {
		classDefs = dex.Rep.ClassDefs
	}
	if classDefs == 0 {
		out.Warnings = append(out.Warnings, "class_defs_size is 0; decode limited")
	}
	if classDefs > model.MaxTypeLookupClasses {
		out.Warnings = append(out.Warnings, fmt.Sprintf("unsupported class_defs_size=%d", classDefs))
	}
	maskBits := uint32(0)
	rawBits := uint32(0)
	if classDefs > 0 {
		capped := classDefs
		if capped > model.MaxTypeLookupClasses {
			capped = model.MaxTypeLookupClasses
		}
		rawBits = binutil.MinimumBitsToStore(capped - 1)
		maskBits = rawBits
	}
	if maskBits > 30 {
		maskBits = 30
		out.Warnings = append(out.Warnings, fmt.Sprintf("clamped type_lookup mask bits from %d to 30 for safety", rawBits))
	}
	out.MaskBits = maskBits
	mask := (uint32(1) << maskBits) - 1
	if maskBits == 0 {
		mask = 0
	}

	samples := make([]model.TypeLookupSample, 0, binutil.MinInt(buckets, model.MaxTypeLookupSamples))
	maxChain := 0
	totalChain := 0
	chainCount := 0
	for i := 0; i < buckets; i++ {
		base := i * 8
		offset := binutil.ReadU32(raw, base)
		packed := binutil.ReadU32(raw, base+4)

		if offset == 0 {
			continue
		}
		out.NonEmptyBuckets++
		classIdx := uint32(0)
		if maskBits > 0 {
			classIdx = (packed >> maskBits) & mask
		}
		nextDelta := packed & mask
		desc := ""
		if dex != nil {
			desc = dex.StringOffsetToName[offset]
		}
		if desc == "" {
			desc = fmt.Sprintf("<string_off_%#x>", offset)
		}
		out.EntryCount++
		if len(samples) < model.MaxTypeLookupSamples {
			samples = append(samples, model.TypeLookupSample{
				Bucket:       uint32(i),
				ClassDef:     classIdx,
				StringOffset: offset,
				NextDelta:    nextDelta,
				HashBits:     packed >> (2 * maskBits),
				Descriptor:   desc,
			})
		}

		// Chain stats
		pos := i
		chainLen := 0
		visited := make([]bool, buckets)
		for j := 0; j < buckets+1; j++ {
			if visited[pos] {
				out.Warnings = append(out.Warnings, "cycle detected in lookup chain")
				break
			}
			visited[pos] = true
			eOffset := binutil.ReadU32(raw, pos*8)
			if eOffset == 0 {
				break
			}
			ePacked := binutil.ReadU32(raw, pos*8+4)
			next := uint32(0)
			if maskBits != 0 {
				next = ePacked & mask
			}
			chainLen++
			if next == 0 {
				break
			}
			pos = (pos + int(next)) % buckets
		}
		if chainLen > maxChain {
			maxChain = chainLen
		}
		totalChain += chainLen
		chainCount++
	}
	out.Samples = samples
	out.MaxChainLen = maxChain
	if chainCount > 0 {
		out.AvgChainLen = float64(totalChain) / float64(chainCount)
	}
	return out
}

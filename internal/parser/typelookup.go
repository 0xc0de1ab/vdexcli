package parser

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseTypeLookupSection parses the kTypeLookupTableSection.
// Each per-dex block starts with a uint32 raw-size followed by
// that many bytes of 8-byte hash table entries.
func ParseTypeLookupSection(raw []byte, s model.VdexSection, dexes []*model.DexContext, expected int) (*model.TypeLookupReport, []model.ParseDiagnostic) {
	out := &model.TypeLookupReport{
		Offset: s.Offset,
		Size:   s.Size,
	}
	var diags []model.ParseDiagnostic
	start, end, ok := sectionBounds(len(raw), s)
	if !ok {
		diags = append(diags, model.DiagTypeLookupSectionRange())
		return out, diags
	}
	out.ContentHash = contentHash(raw[start:end])
	if expected == 0 {
		expected = len(dexes)
	}

	cursor := start
	for i := 0; i < expected; i++ {
		if cursor+4 > end {
			diags = append(diags, model.DiagTypeLookupTruncated(i))
			break
		}
		size := int(binutil.ReadU32(raw, cursor))
		cursor += 4
		if cursor+size > end {
			diags = append(diags, model.DiagTypeLookupDexExceeds(i, size))
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
	return out, diags
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
	nextPositions := make([]int, buckets)
	nonEmpty := make([]bool, buckets)
	for i := 0; i < buckets; i++ {
		base := i * 8
		offset := binutil.ReadU32(raw, base)
		packed := binutil.ReadU32(raw, base+4)

		if offset == 0 {
			continue
		}
		nonEmpty[i] = true
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
		if nextDelta != 0 {
			nextPositions[i] = (i + int(nextDelta)) % buckets
		} else {
			nextPositions[i] = -1
		}
	}

	chainLengths := make([]int, buckets)
	resolved := make([]bool, buckets)
	visitID := make([]int, buckets)
	visitStep := make([]int, buckets)
	cycleDetected := false
	path := make([]int, 0)
	for root := 0; root < buckets; root++ {
		if !nonEmpty[root] || resolved[root] {
			continue
		}
		token := root + 1
		path = path[:0]
		pos := root
		baseLen := 0
		prefixEnd := 0
		for {
			if !nonEmpty[pos] {
				prefixEnd = len(path)
				break
			}
			if resolved[pos] {
				baseLen = chainLengths[pos]
				prefixEnd = len(path)
				break
			}
			if visitID[pos] == token {
				cycleStart := visitStep[pos]
				cycleLen := len(path) - cycleStart
				for _, node := range path[cycleStart:] {
					chainLengths[node] = cycleLen
					resolved[node] = true
				}
				baseLen = cycleLen
				prefixEnd = cycleStart
				cycleDetected = true
				break
			}
			visitID[pos] = token
			visitStep[pos] = len(path)
			path = append(path, pos)
			if nextPositions[pos] < 0 {
				prefixEnd = len(path)
				break
			}
			pos = nextPositions[pos]
		}
		for i := prefixEnd - 1; i >= 0; i-- {
			baseLen++
			chainLengths[path[i]] = baseLen
			resolved[path[i]] = true
		}
	}
	if cycleDetected {
		out.Warnings = append(out.Warnings, "cycle detected in lookup chain")
	}

	maxChain := 0
	totalChain := 0
	chainCount := 0
	for i, present := range nonEmpty {
		if !present {
			continue
		}
		if chainLengths[i] > maxChain {
			maxChain = chainLengths[i]
		}
		totalChain += chainLengths[i]
		chainCount++
	}
	out.Samples = samples
	out.MaxChainLen = maxChain
	if chainCount > 0 {
		out.AvgChainLen = float64(totalChain) / float64(chainCount)
	}
	return out
}

// Package presenter formats VDEX parse results for text, JSON, and pipeline output.
package presenter

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/samber/lo"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func CategorizeWarning(w string) string {
	lw := strings.ToLower(w)
	switch {
	case strings.Contains(lw, "magic") || strings.Contains(lw, "version") || strings.Contains(lw, "file header"):
		return "header"
	case strings.Contains(lw, "section"):
		return "section"
	case strings.Contains(lw, "dex[") || strings.Contains(lw, "dex file") || strings.Contains(lw, "file_size") || strings.Contains(lw, "declared file_size") || strings.Contains(lw, "header_size"):
		return "dex"
	case strings.Contains(lw, "verifier"):
		return "verifier"
	case strings.Contains(lw, "type-lookup") || strings.Contains(lw, "type_lookup") || strings.Contains(lw, "type lookup"):
		return "type_lookup"
	case strings.Contains(lw, "template") || strings.Contains(lw, "extract"):
		return "extract"
	default:
		return "other"
	}
}

func GroupWarnings(warnings []string) map[string][]string {
	return lo.GroupBy(warnings, func(w string) string {
		return CategorizeWarning(w)
	})
}

func PrintGroupedWarnings(warnings []string) {
	grouped := GroupWarnings(warnings)
	if len(warnings) == 0 {
		return
	}
	order := []string{"header", "section", "dex", "verifier", "type_lookup", "extract", "other"}
	for _, c := range order {
		ws, ok := grouped[c]
		if !ok || len(ws) == 0 {
			continue
		}
		fmt.Printf("%s warnings (%d):\n", c, len(ws))
		for _, w := range ws {
			fmt.Printf("  - %s\n", w)
		}
	}
}

// PrintGroupedDiagnostics prints warnings grouped by category with hints.
func PrintGroupedDiagnostics(diags []model.ParseDiagnostic) {
	if len(diags) == 0 {
		return
	}
	grouped := lo.GroupBy(diags, func(d model.ParseDiagnostic) string {
		return string(d.Category)
	})
	order := []string{"header", "section", "checksum", "dex", "verifier", "type_lookup"}
	for _, c := range order {
		ds, ok := grouped[c]
		if !ok || len(ds) == 0 {
			continue
		}
		warns := lo.Filter(ds, func(d model.ParseDiagnostic, _ int) bool { return d.Severity == model.SeverityWarning })
		if len(warns) == 0 {
			continue
		}
		fmt.Printf("%s warnings (%d):\n", c, len(warns))
		for _, d := range warns {
			fmt.Printf("  - %s\n", d.Message)
			if d.Hint != "" {
				fmt.Printf("    %s %s\n", c_hint("hint:"), d.Hint)
			}
		}
	}
}

func c_hint(label string) string {
	return c(dimWht, label)
}

func StrictMatchingWarnings(warnings []string, filter string) ([]string, []string) {
	if len(warnings) == 0 {
		return nil, nil
	}
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return append([]string(nil), warnings...), nil
	}
	raw := strings.Split(filter, ",")
	containsPatterns := make([]string, 0, len(raw))
	regexPatterns := make([]*regexp.Regexp, 0, len(raw))
	filterWarnings := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			lower := strings.ToLower(p)
			if strings.HasPrefix(lower, "re:") {
				reSrc := strings.TrimSpace(p[3:])
				if reSrc == "" {
					filterWarnings = append(filterWarnings, `invalid --strict-warn regex pattern "re:" has empty expression`)
					continue
				}
				re, err := regexp.Compile("(?i)" + reSrc)
				if err == nil {
					regexPatterns = append(regexPatterns, re)
					continue
				}
				filterWarnings = append(filterWarnings, fmt.Sprintf("invalid --strict-warn regex %q: %v", reSrc, err))
				containsPatterns = append(containsPatterns, strings.ToLower(reSrc))
				continue
			}
			containsPatterns = append(containsPatterns, lower)
		}
	}
	if len(containsPatterns) == 0 && len(regexPatterns) == 0 {
		return nil, filterWarnings
	}

	out := lo.Filter(warnings, func(w string, _ int) bool {
		lw := strings.ToLower(w)
		if lo.SomeBy(containsPatterns, func(p string) bool { return strings.Contains(lw, p) }) {
			return true
		}
		return lo.SomeBy(regexPatterns, func(re *regexp.Regexp) bool { return re.MatchString(w) })
	})
	return out, filterWarnings
}

func PrintText(r *model.VdexReport) {
	if r == nil {
		return
	}
	fmt.Printf("file: %s\nsize: %d bytes\n", r.File, r.Size)
	fmt.Printf("vdex magic=%q version=%q sections=%d\n", r.Header.Magic, r.Header.Version, r.Header.NumSections)
	if r.Meanings != nil {
		PrintTextMeanings(r.Meanings)
	}

	fmt.Println("sections:")
	for _, s := range r.Sections {
		fmt.Printf("  kind=%s (%d) off=%#x size=%#x\n", s.Name, s.Kind, s.Offset, s.Size)
		fmt.Printf("    %s\n", s.Meaning)
	}

	fmt.Printf("checksums: %d\n", len(r.Checksums))
	for i, v := range r.Checksums {
		fmt.Printf("  [%d]=%#x\n", i, v)
	}

	fmt.Printf("dex files: %d\n", len(r.Dexes))
	for _, d := range r.Dexes {
		fmt.Printf("  [%d] off=%#x size=%#x magic=%q ver=%q endian=%s file_size=%d header=%d\n",
			d.Index, d.Offset, d.Size, d.Magic, d.Version, d.Endian, d.FileSize, d.HeaderSize)
		fmt.Printf("     sha1=%s checksum=%#x\n", d.Signature, d.ChecksumId)
		fmt.Printf("     strings=%d(@%#x) types=%d(@%#x) protos=%d(@%#x) fields=%d(@%#x) methods=%d(@%#x) class_defs=%d(@%#x)\n",
			d.StringIds, d.StringIdsOff, d.TypeIds, d.TypeIdsOff,
			d.ProtoIds, d.ProtoIdsOff, d.FieldIds, d.FieldIdsOff,
			d.MethodIds, d.MethodIdsOff, d.ClassDefs, d.ClassDefsOff)
		if len(d.Classes) > 0 {
			fmt.Printf("     class preview: ")
			for _, c := range d.Classes {
				fmt.Printf("%s ", c)
			}
			if d.ClassDefs > uint32(len(d.Classes)) {
				fmt.Printf("...")
			}
			fmt.Println()
		}
	}

	if r.Verifier != nil {
		fmt.Printf("verifier_deps: off=%#x size=%#x\n", r.Verifier.Offset, r.Verifier.Size)
		for _, d := range r.Verifier.Dexes {
			fmt.Printf("  [dex %d] verified=%d unverified=%d pairs=%d extra_strings=%d\n",
				d.DexIndex, d.VerifiedClasses, d.UnverifiedClasses, d.AssignabilityPairs, d.ExtraStringCount)
			for _, p := range d.FirstPairs {
				fmt.Printf("    class %d: %s(%d) -> %s(%d)\n", p.ClassDefIndex, p.Dest, p.DestID, p.Src, p.SrcID)
			}
		}
	}

	if r.TypeLookup != nil {
		fmt.Printf("type_lookup: off=%#x size=%#x\n", r.TypeLookup.Offset, r.TypeLookup.Size)
		for _, d := range r.TypeLookup.Dexes {
			fmt.Printf("  [dex %d] raw=%d buckets=%d entries=%d non_empty=%d max_chain=%d avg_chain=%.2f\n",
				d.DexIndex, d.RawSize, d.BucketCount, d.EntryCount, d.NonEmptyBuckets, d.MaxChainLen, d.AvgChainLen)
			for _, s := range d.Samples {
				fmt.Printf("    bucket=%d class=%d desc=%s next=%d hashbits=%d\n", s.Bucket, s.ClassDef, s.Descriptor, s.NextDelta, s.HashBits)
			}
			for _, w := range d.Warnings {
				fmt.Printf("    warn: %s\n", w)
			}
		}
	}

	if r.Coverage != nil {
		c := r.Coverage
		fmt.Printf("byte_coverage: %d/%d bytes (%.1f%%)\n", c.ParsedBytes, c.FileSize, c.CoveragePercent)
		for _, rng := range c.Ranges {
			fmt.Printf("  %#08x..%#08x  %6d bytes  %s\n", rng.Offset, rng.Offset+rng.Size, rng.Size, rng.Label)
		}
		if len(c.Gaps) > 0 {
			fmt.Println("  gaps:")
			for _, g := range c.Gaps {
				fmt.Printf("    %#08x..%#08x  %6d bytes  %s\n", g.Offset, g.Offset+g.Size, g.Size, g.Label)
			}
		}
	}

	if len(r.Diagnostics) > 0 {
		PrintGroupedDiagnostics(r.Diagnostics)
	} else if len(r.Warnings) > 0 {
		PrintGroupedWarnings(r.Warnings)
	}
	if len(r.Errors) > 0 {
		fmt.Println("errors:")
		for _, e := range r.Errors {
			fmt.Printf("  ! %s\n", e)
		}
		// Show hints for error diagnostics
		for _, d := range r.Diagnostics {
			if d.Severity == model.SeverityError && d.Hint != "" {
				fmt.Printf("    %s %s\n", c_hint("hint:"), d.Hint)
			}
		}
	}
}

func PrintTextMeanings(m *model.ParserMeanings) {
	if m == nil {
		return
	}
	fmt.Println("meanings:")
	fmt.Println("  vdex_file:")
	fmt.Printf("    magic: %s\n", m.VdexFile.Magic)
	fmt.Printf("    version: %s\n", m.VdexFile.Version)
	fmt.Printf("    sections: %s\n", m.VdexFile.Sections)
	fmt.Printf("    checksums: %s\n", m.VdexFile.Checksums)
	fmt.Printf("    dex_files: %s\n", m.VdexFile.DexFiles)
	fmt.Printf("    verifier_deps: %s\n", m.VdexFile.Verifier)
	fmt.Printf("    type_lookup: %s\n", m.VdexFile.TypeLookup)
	fmt.Printf("    warnings: %s\n", m.VdexFile.Warnings)
	fmt.Printf("    warnings_by_category: %s\n", m.VdexFile.WarningsByCategory)
	fmt.Printf("    errors: %s\n", m.VdexFile.Errors)
	fmt.Printf("    schema_version: %s\n", m.VdexFile.SchemaVer)
	fmt.Println("    section_kind:")
	fmt.Printf("      0: %s\n", m.SectionKind["0"])
	fmt.Printf("      1: %s\n", m.SectionKind["1"])
	fmt.Printf("      2: %s\n", m.SectionKind["2"])
	fmt.Printf("      3: %s\n", m.SectionKind["3"])
	fmt.Printf("      8: %s\n", m.SectionKind["8"])
	fmt.Printf("      9: %s\n", m.SectionKind["9"])
	fmt.Printf("      10: %s\n", m.SectionKind["10"])
	fmt.Println("  dex_header:")
	fmt.Printf("    magic: %s\n", m.DexHeader.Magic)
	fmt.Printf("    version: %s\n", m.DexHeader.Version)
	fmt.Printf("    checksum_field: %s\n", m.DexHeader.Checksum)
	fmt.Printf("    file_size: %s\n", m.DexHeader.FileSize)
	fmt.Printf("    header_size: %s\n", m.DexHeader.HeaderSize)
	fmt.Printf("    endian: %s\n", m.DexHeader.Endian)
	fmt.Printf("    string_ids_size: %s\n", m.DexHeader.StringIds)
	fmt.Printf("    type_ids_size: %s\n", m.DexHeader.TypeIds)
	fmt.Printf("    proto_ids_size: %s\n", m.DexHeader.ProtoIds)
	fmt.Printf("    field_ids_size: %s\n", m.DexHeader.FieldIds)
	fmt.Printf("    method_ids_size: %s\n", m.DexHeader.MethodIds)
	fmt.Printf("    class_defs_size: %s\n", m.DexHeader.ClassDefs)
	fmt.Printf("    data_size: %s\n", m.DexHeader.DataSize)
	fmt.Printf("    data_offset: %s\n", m.DexHeader.DataOffset)
	fmt.Printf("    class_def_preview: %s\n", m.DexHeader.ClassPreview)
	fmt.Println("  verifier_deps:")
	fmt.Printf("    offset: %s\n", m.VerifierDeps.Offset)
	fmt.Printf("    size: %s\n", m.VerifierDeps.Size)
	fmt.Printf("    verified_classes: %s\n", m.VerifierDeps.VerifiedClasses)
	fmt.Printf("    unverified_classes: %s\n", m.VerifierDeps.UnverifiedClasses)
	fmt.Printf("    assignability_pairs: %s\n", m.VerifierDeps.AssignabilityPair)
	fmt.Printf("    extra_string_count: %s\n", m.VerifierDeps.ExtraStringCount)
	fmt.Printf("    first_pairs: %s\n", m.VerifierDeps.FirstPairs)
	fmt.Println("  type_lookup:")
	fmt.Printf("    offset: %s\n", m.TypeLookup.Offset)
	fmt.Printf("    size: %s\n", m.TypeLookup.Size)
	fmt.Printf("    raw_size: %s\n", m.TypeLookup.RawSize)
	fmt.Printf("    bucket_count: %s\n", m.TypeLookup.BucketCount)
	fmt.Printf("    entry_count: %s\n", m.TypeLookup.EntryCount)
	fmt.Printf("    non_empty_buckets: %s\n", m.TypeLookup.NonEmptyBuckets)
	fmt.Printf("    max_chain_len: %s\n", m.TypeLookup.MaxChainLen)
	fmt.Printf("    avg_chain_len: %s\n", m.TypeLookup.AvgChainLen)
	fmt.Printf("    sample_entries: %s\n", m.TypeLookup.SampleEntries)
}

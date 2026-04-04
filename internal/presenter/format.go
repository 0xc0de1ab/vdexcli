package presenter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/samber/lo"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// WriteJSON writes pretty-printed JSON to w.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// WriteJSONL writes compact single-line JSON (newline-delimited) to w.
func WriteJSONL(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

// WriteSummary writes a one-line key=value summary suitable for CI/monitoring.
func WriteSummary(w io.Writer, r *model.VdexReport) {
	if r == nil {
		fmt.Fprintln(w, "status=error file= size=0")
		return
	}

	status := "ok"
	if len(r.Errors) > 0 {
		status = "error"
	} else if len(r.Warnings) > 0 {
		status = "warn"
	}

	covPct := 0.0
	gaps := 0
	if r.Coverage != nil {
		covPct = r.Coverage.CoveragePercent
		gaps = len(r.Coverage.Gaps)
	}

	fmt.Fprintf(w, "status=%s file=%s size=%d version=%s sections=%d checksums=%d dexes=%d warnings=%d errors=%d coverage=%.1f%% gaps=%d\n",
		status, r.File, r.Size,
		r.Header.Version, r.Header.NumSections,
		len(r.Checksums), len(r.Dexes),
		len(r.Warnings), len(r.Errors),
		covPct, gaps)
}

// WriteSections writes a TSV table of sections for easy grep/awk processing.
func WriteSections(w io.Writer, r *model.VdexReport) {
	if r == nil {
		return
	}
	fmt.Fprintln(w, "kind\tname\toffset\tsize")
	for _, s := range r.Sections {
		fmt.Fprintf(w, "%d\t%s\t%d\t%d\n", s.Kind, s.Name, s.Offset, s.Size)
	}
}

// WriteCoverage writes byte coverage in a concise format showing ranges and gaps.
func WriteCoverage(w io.Writer, r *model.VdexReport) {
	if r == nil || r.Coverage == nil {
		fmt.Fprintln(w, "no coverage data")
		return
	}
	c := r.Coverage
	fmt.Fprintf(w, "file=%s size=%d parsed=%d unparsed=%d coverage=%.2f%%\n",
		r.File, c.FileSize, c.ParsedBytes, c.UnparsedBytes, c.CoveragePercent)

	for _, rng := range c.Ranges {
		fmt.Fprintf(w, "  %#08x  %6d  %s\n", rng.Offset, rng.Size, rng.Label)
	}
	if len(c.Gaps) > 0 {
		fmt.Fprintln(w, "gaps:")
		for _, g := range c.Gaps {
			fmt.Fprintf(w, "  %#08x  %6d  %s\n", g.Offset, g.Size, g.Label)
		}
	}
}

// WriteModifySummary writes a one-line summary for modify results.
func WriteModifySummary(w io.Writer, s model.ModifySummary) {
	fmt.Fprintf(w, "status=%s mode=%s input=%s output=%s dry_run=%v classes_total=%d classes_modified=%d classes_unchanged=%d change=%.2f%% warnings=%d errors=%d\n",
		s.Status, s.Mode, s.InputFile, s.OutputFile, s.DryRun,
		s.TotalClasses, s.ModifiedClasses, s.UnmodifiedClasses,
		s.ClassChangePercent,
		len(s.Warnings), len(s.Errors))
}

// WriteExtractSummary writes a one-line summary for extract results.
func WriteExtractSummary(w io.Writer, s model.ExtractSummary) {
	fmt.Fprintf(w, "status=%s file=%s dir=%s extracted=%d failed=%d warnings=%d errors=%d\n",
		lo.Ternary(len(s.Errors) > 0, "error", "ok"),
		s.File, s.ExtractDir, s.Extracted, s.Failed,
		len(s.Warnings), len(s.Errors))
}

// WriteTable writes a formatted, aligned table of sections to w.
// When color is enabled, fields are highlighted by semantic role.
func WriteTable(w io.Writer, r *model.VdexReport) {
	if r == nil {
		return
	}

	fmt.Fprintf(w, "%s\n", c(bold, fmt.Sprintf("VDEX %s  v%s  %d bytes", r.Header.Magic, r.Header.Version, r.Size)))
	fmt.Fprintln(w)

	// Section table
	fmt.Fprintf(w, "  %-4s  %-28s  %10s  %10s\n",
		c(dim, "KIND"), c(dim, "NAME"), c(dim, "OFFSET"), c(dim, "SIZE"))
	fmt.Fprintf(w, "  %-4s  %-28s  %10s  %10s\n",
		c(dim, "----"), c(dim, "----------------------------"), c(dim, "----------"), c(dim, "----------"))
	for _, s := range r.Sections {
		sizeStr := fmt.Sprintf("%#x", s.Size)
		if s.Size == 0 {
			sizeStr = c(dim, "0")
		}
		fmt.Fprintf(w, "  %4d  %-28s  %#10x  %10s\n", s.Kind, s.Name, s.Offset, sizeStr)
	}
	fmt.Fprintln(w)

	// Checksums
	if len(r.Checksums) > 0 {
		fmt.Fprintf(w, "%s %d\n", c(bold, "checksums:"), len(r.Checksums))
		for i, v := range r.Checksums {
			fmt.Fprintf(w, "  [%d] %s\n", i, c(cyan, fmt.Sprintf("%#x", v)))
		}
		fmt.Fprintln(w)
	}

	// DEX files
	if len(r.Dexes) > 0 {
		fmt.Fprintf(w, "%s %d\n", c(bold, "dex files:"), len(r.Dexes))
		for _, d := range r.Dexes {
			magic := strings.ReplaceAll(d.Magic, "\n", "\\n")
			sigPreview := d.Signature
			if len(sigPreview) > 20 {
				sigPreview = sigPreview[:20] + "..."
			}
			fmt.Fprintf(w, "  [%d] %s  off=%#x  size=%d  endian=%s\n",
				d.Index, c(boldCyn, magic+d.Version), d.Offset, d.Size, d.Endian)
			fmt.Fprintf(w, "      sha1=%s  checksum=%s\n",
				c(dim, sigPreview), c(cyan, fmt.Sprintf("%#x", d.ChecksumId)))
			fmt.Fprintf(w, "      strings=%d types=%d protos=%d fields=%d methods=%d %s=%d\n",
				d.StringIds, d.TypeIds, d.ProtoIds, d.FieldIds, d.MethodIds,
				c(bold, "classes"), d.ClassDefs)
		}
		fmt.Fprintln(w)
	}

	// Verifier
	if r.Verifier != nil {
		fmt.Fprintf(w, "%s off=%#x size=%d\n", c(bold, "verifier_deps:"), r.Verifier.Offset, r.Verifier.Size)
		for _, d := range r.Verifier.Dexes {
			verified := c(green, fmt.Sprintf("%d", d.VerifiedClasses))
			unverified := fmt.Sprintf("%d", d.UnverifiedClasses)
			if d.UnverifiedClasses > 0 {
				unverified = c(yellow, unverified)
			}
			fmt.Fprintf(w, "  [dex %d] verified=%s unverified=%s pairs=%d extras=%d\n",
				d.DexIndex, verified, unverified, d.AssignabilityPairs, d.ExtraStringCount)
		}
		fmt.Fprintln(w)
	}

	// Coverage
	if r.Coverage != nil {
		cov := r.Coverage
		pctStr := fmt.Sprintf("%.1f%%", cov.CoveragePercent)
		if cov.CoveragePercent >= 99.9 {
			pctStr = c(boldGrn, pctStr)
		} else if cov.CoveragePercent >= 90 {
			pctStr = c(boldYlw, pctStr)
		} else {
			pctStr = c(boldRed, pctStr)
		}
		fmt.Fprintf(w, "%s %d/%d bytes (%s)\n", c(bold, "coverage:"), cov.ParsedBytes, cov.FileSize, pctStr)
		if len(cov.Gaps) > 0 {
			for _, g := range cov.Gaps {
				fmt.Fprintf(w, "  %s %#x..%#x  %d bytes  %s\n", c(yellow, "gap"), g.Offset, g.Offset+g.Size, g.Size, c(dim, g.Label))
			}
		}
		fmt.Fprintln(w)
	}

	// Warnings
	if len(r.Warnings) > 0 {
		fmt.Fprintf(w, "%s %d\n", c(boldYlw, "warnings:"), len(r.Warnings))
		for _, w2 := range r.Warnings {
			fmt.Fprintf(w, "  %s %s\n", c(yellow, "!"), w2)
		}
		fmt.Fprintln(w)
	}
	// Errors
	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "%s %d\n", c(boldRed, "errors:"), len(r.Errors))
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  %s %s\n", c(red, "!"), e)
		}
	}
}

// ValidateFormat checks if a format string is one of the supported output modes.
func ValidateFormat(f string) error {
	switch strings.ToLower(f) {
	case "", "text", "json", "jsonl", "summary", "sections", "coverage", "table":
		return nil
	default:
		return fmt.Errorf("unsupported --format %q; supported: text, json, jsonl, summary, sections, coverage, table", f)
	}
}

package presenter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

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
		lo_ternary(len(s.Errors) > 0, "error", "ok"),
		s.File, s.ExtractDir, s.Extracted, s.Failed,
		len(s.Warnings), len(s.Errors))
}

func lo_ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// ValidateFormat checks if a format string is supported.
func ValidateFormat(f string) error {
	switch strings.ToLower(f) {
	case "", "text", "json", "jsonl", "summary", "sections", "coverage":
		return nil
	default:
		return fmt.Errorf("unsupported --format %q; supported: text, json, jsonl, summary, sections, coverage", f)
	}
}

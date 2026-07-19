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

type outputWriter struct {
	dst io.Writer
	err error
}

func (w *outputWriter) printf(format string, args ...any) {
	if w.err == nil {
		_, w.err = fmt.Fprintf(w.dst, format, args...)
	}
}

func (w *outputWriter) println(args ...any) {
	if w.err == nil {
		_, w.err = fmt.Fprintln(w.dst, args...)
	}
}

// WriteSummary writes a one-line key=value summary suitable for CI/monitoring.
func WriteSummary(w io.Writer, r *model.VdexReport) error {
	out := outputWriter{dst: w}
	if r == nil {
		out.println("status=error file= size=0")
		return out.err
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

	out.printf("status=%s file=%s size=%d version=%s sections=%d checksums=%d dexes=%d warnings=%d errors=%d coverage=%.1f%% gaps=%d\n",
		status, r.File, r.Size,
		r.Header.Version, r.Header.NumSections,
		len(r.Checksums), len(r.Dexes),
		len(r.Warnings), len(r.Errors),
		covPct, gaps)
	return out.err
}

// WriteSections writes a TSV table of sections for easy grep/awk processing.
func WriteSections(w io.Writer, r *model.VdexReport) error {
	if r == nil {
		return nil
	}
	out := outputWriter{dst: w}
	out.println("kind\tname\toffset\tsize")
	for _, s := range r.Sections {
		out.printf("%d\t%s\t%d\t%d\n", s.Kind, s.Name, s.Offset, s.Size)
	}
	return out.err
}

// WriteCoverage writes byte coverage in a concise format showing ranges and gaps.
func WriteCoverage(w io.Writer, r *model.VdexReport) error {
	out := outputWriter{dst: w}
	if r == nil || r.Coverage == nil {
		out.println("no coverage data")
		return out.err
	}
	c := r.Coverage
	out.printf("file=%s size=%d parsed=%d unparsed=%d coverage=%.2f%%\n",
		r.File, c.FileSize, c.ParsedBytes, c.UnparsedBytes, c.CoveragePercent)

	for _, rng := range c.Ranges {
		out.printf("  %#08x  %6d  %s\n", rng.Offset, rng.Size, rng.Label)
	}
	if len(c.Gaps) > 0 {
		out.println("gaps:")
		for _, g := range c.Gaps {
			out.printf("  %#08x  %6d  %s\n", g.Offset, g.Size, g.Label)
		}
	}
	return out.err
}

// WriteModifySummary writes a one-line summary for modify results.
func WriteModifySummary(w io.Writer, s model.ModifySummary) error {
	out := outputWriter{dst: w}
	out.printf("status=%s mode=%s input=%s output=%s dry_run=%v classes_total=%d classes_modified=%d classes_unchanged=%d change=%.2f%% warnings=%d errors=%d\n",
		s.Status, s.Mode, s.InputFile, s.OutputFile, s.DryRun,
		s.TotalClasses, s.ModifiedClasses, s.UnmodifiedClasses,
		s.ClassChangePercent,
		len(s.Warnings), len(s.Errors))
	return out.err
}

// WriteExtractSummary writes a one-line summary for extract results.
func WriteExtractSummary(w io.Writer, s model.ExtractSummary) error {
	out := outputWriter{dst: w}
	out.printf("status=%s file=%s dir=%s extracted=%d failed=%d warnings=%d errors=%d\n",
		lo.Ternary(len(s.Errors) > 0, "error", "ok"),
		s.File, s.ExtractDir, s.Extracted, s.Failed,
		len(s.Warnings), len(s.Errors))
	return out.err
}

// WriteTable writes a formatted, aligned table of sections to w.
// When color is enabled, fields are highlighted by semantic role.
func WriteTable(w io.Writer, r *model.VdexReport) error {
	if r == nil {
		return nil
	}
	out := outputWriter{dst: w}

	out.printf("%s\n", c(bold, fmt.Sprintf("VDEX %s  v%s  %d bytes", r.Header.Magic, r.Header.Version, r.Size)))
	out.println()

	// Section table
	out.printf("  %-4s  %-28s  %10s  %10s\n",
		c(dim, "KIND"), c(dim, "NAME"), c(dim, "OFFSET"), c(dim, "SIZE"))
	out.printf("  %-4s  %-28s  %10s  %10s\n",
		c(dim, "----"), c(dim, "----------------------------"), c(dim, "----------"), c(dim, "----------"))
	for _, s := range r.Sections {
		sizeStr := fmt.Sprintf("%#x", s.Size)
		if s.Size == 0 {
			sizeStr = c(dim, "0")
		}
		out.printf("  %4d  %-28s  %#10x  %10s\n", s.Kind, s.Name, s.Offset, sizeStr)
	}
	out.println()

	// Checksums
	if len(r.Checksums) > 0 {
		out.printf("%s %d\n", c(bold, "checksums:"), len(r.Checksums))
		for i, v := range r.Checksums {
			out.printf("  [%d] %s\n", i, c(cyan, fmt.Sprintf("%#x", v)))
		}
		out.println()
	}

	// DEX files
	if len(r.Dexes) > 0 {
		out.printf("%s %d\n", c(bold, "dex files:"), len(r.Dexes))
		for _, d := range r.Dexes {
			magic := strings.ReplaceAll(d.Magic, "\n", "\\n")
			sigPreview := d.Signature
			if len(sigPreview) > 20 {
				sigPreview = sigPreview[:20] + "..."
			}
			out.printf("  [%d] %s  off=%#x  size=%d  endian=%s\n",
				d.Index, c(boldCyn, magic+d.Version), d.Offset, d.Size, d.Endian)
			out.printf("      sha1=%s  checksum=%s\n",
				c(dim, sigPreview), c(cyan, fmt.Sprintf("%#x", d.ChecksumId)))
			out.printf("      strings=%d types=%d protos=%d fields=%d methods=%d %s=%d\n",
				d.StringIds, d.TypeIds, d.ProtoIds, d.FieldIds, d.MethodIds,
				c(bold, "classes"), d.ClassDefs)
		}
		out.println()
	}

	// Verifier
	if r.Verifier != nil {
		out.printf("%s off=%#x size=%d\n", c(bold, "verifier_deps:"), r.Verifier.Offset, r.Verifier.Size)
		for _, d := range r.Verifier.Dexes {
			verified := c(green, fmt.Sprintf("%d", d.VerifiedClasses))
			unverified := fmt.Sprintf("%d", d.UnverifiedClasses)
			if d.UnverifiedClasses > 0 {
				unverified = c(yellow, unverified)
			}
			out.printf("  [dex %d] verified=%s unverified=%s pairs=%d extras=%d\n",
				d.DexIndex, verified, unverified, d.AssignabilityPairs, d.ExtraStringCount)
		}
		out.println()
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
		out.printf("%s %d/%d bytes (%s)\n", c(bold, "coverage:"), cov.ParsedBytes, cov.FileSize, pctStr)
		if len(cov.Gaps) > 0 {
			for _, g := range cov.Gaps {
				out.printf("  %s %#x..%#x  %d bytes  %s\n", c(yellow, "gap"), g.Offset, g.Offset+g.Size, g.Size, c(dim, g.Label))
			}
		}
		out.println()
	}

	// Warnings
	if len(r.Warnings) > 0 {
		out.printf("%s %d\n", c(boldYlw, "warnings:"), len(r.Warnings))
		for _, w2 := range r.Warnings {
			out.printf("  %s %s\n", c(yellow, "!"), w2)
		}
		out.println()
	}
	// Errors
	if len(r.Errors) > 0 {
		out.printf("%s %d\n", c(boldRed, "errors:"), len(r.Errors))
		for _, e := range r.Errors {
			out.printf("  %s %s\n", c(red, "!"), e)
		}
	}
	return out.err
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

package presenter

import (
	"io"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ReportWriter renders a VdexReport in a specific format.
type ReportWriter interface {
	Write(w io.Writer, report *model.VdexReport) error
}

// SummaryWriter renders a one-line summary for a specific operation.
type SummaryWriter interface {
	WriteModify(w io.Writer, s model.ModifySummary) error
	WriteExtract(w io.Writer, s model.ExtractSummary) error
}

// DiffWriter renders a structural diff between two VDEX files.
type DiffWriter interface {
	WriteDiff(w io.Writer, d model.VdexDiff) error
}

// WarningProcessor categorizes and filters warnings.
type WarningProcessor interface {
	Group(warnings []string) map[string][]string
	StrictMatch(warnings []string, filter string) (matched []string, filterWarnings []string)
}

// --- Default implementations wrapping the package-level functions ---

// JSONWriter implements ReportWriter for pretty JSON output.
type JSONWriter struct{}

func (JSONWriter) Write(w io.Writer, report *model.VdexReport) error {
	return WriteJSON(w, report)
}

// JSONLWriter implements ReportWriter for single-line JSON.
type JSONLWriter struct{}

func (JSONLWriter) Write(w io.Writer, report *model.VdexReport) error {
	return WriteJSONL(w, report)
}

// TextWriter implements ReportWriter for human-readable text.
type TextWriter struct{}

func (TextWriter) Write(_ io.Writer, report *model.VdexReport) error {
	PrintText(report)
	return nil
}

// TableWriter implements ReportWriter for aligned table with color.
type TableWriter struct{}

func (TableWriter) Write(w io.Writer, report *model.VdexReport) error {
	return WriteTable(w, report)
}

// SummaryLineWriter implements ReportWriter for one-line summary.
type SummaryLineWriter struct{}

func (SummaryLineWriter) Write(w io.Writer, report *model.VdexReport) error {
	return WriteSummary(w, report)
}

// SectionsWriter implements ReportWriter for TSV section table.
type SectionsWriter struct{}

func (SectionsWriter) Write(w io.Writer, report *model.VdexReport) error {
	return WriteSections(w, report)
}

// CoverageWriter implements ReportWriter for byte coverage report.
type CoverageWriter struct{}

func (CoverageWriter) Write(w io.Writer, report *model.VdexReport) error {
	return WriteCoverage(w, report)
}

// DefaultSummaryWriter implements SummaryWriter.
type DefaultSummaryWriter struct{}

func (DefaultSummaryWriter) WriteModify(w io.Writer, s model.ModifySummary) error {
	return WriteModifySummary(w, s)
}

func (DefaultSummaryWriter) WriteExtract(w io.Writer, s model.ExtractSummary) error {
	return WriteExtractSummary(w, s)
}

// DefaultWarningProcessor implements WarningProcessor.
type DefaultWarningProcessor struct{}

func (DefaultWarningProcessor) Group(warnings []string) map[string][]string {
	return GroupWarnings(warnings)
}

func (DefaultWarningProcessor) StrictMatch(warnings []string, filter string) ([]string, []string) {
	return StrictMatchingWarnings(warnings, filter)
}

// DefaultDiffWriter implements DiffWriter.
type DefaultDiffWriter struct{}

func (DefaultDiffWriter) WriteDiff(w io.Writer, d model.VdexDiff) error {
	return WriteDiffText(w, d)
}

// Compile-time interface compliance checks.
var (
	_ ReportWriter     = JSONWriter{}
	_ ReportWriter     = JSONLWriter{}
	_ ReportWriter     = TextWriter{}
	_ ReportWriter     = TableWriter{}
	_ ReportWriter     = SummaryLineWriter{}
	_ ReportWriter     = SectionsWriter{}
	_ ReportWriter     = CoverageWriter{}
	_ SummaryWriter    = DefaultSummaryWriter{}
	_ WarningProcessor = DefaultWarningProcessor{}
	_ DiffWriter       = DefaultDiffWriter{}
)

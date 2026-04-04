package presenter

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// mockReportWriter verifies ReportWriter can be mocked.
type mockReportWriter struct {
	called bool
}

func (m *mockReportWriter) Write(_ *bytes.Buffer, _ *model.VdexReport) error {
	m.called = true
	return nil
}

func TestReportWriter_JSONWriter(t *testing.T) {
	var w ReportWriter = JSONWriter{}
	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf, sampleReport()))
	assert.Contains(t, buf.String(), "schema_version")
}

func TestReportWriter_JSONLWriter(t *testing.T) {
	var w ReportWriter = JSONLWriter{}
	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf, sampleReport()))
	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	assert.Equal(t, 1, lines)
}

func TestReportWriter_TableWriter(t *testing.T) {
	SetColor(false)
	var w ReportWriter = TableWriter{}
	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf, sampleReport()))
	assert.Contains(t, buf.String(), "VDEX vdex")
}

func TestReportWriter_SummaryLineWriter(t *testing.T) {
	var w ReportWriter = SummaryLineWriter{}
	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf, sampleReport()))
	assert.Contains(t, buf.String(), "status=")
}

func TestReportWriter_SectionsWriter(t *testing.T) {
	var w ReportWriter = SectionsWriter{}
	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf, sampleReport()))
	assert.Contains(t, buf.String(), "kind\tname")
}

func TestReportWriter_CoverageWriter(t *testing.T) {
	var w ReportWriter = CoverageWriter{}
	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf, sampleReport()))
	assert.Contains(t, buf.String(), "coverage=")
}

func TestWarningProcessor_Default(t *testing.T) {
	var p WarningProcessor = DefaultWarningProcessor{}
	grouped := p.Group([]string{"section kind 3", "verifier bad"})
	assert.Len(t, grouped["section"], 1)
	assert.Len(t, grouped["verifier"], 1)

	matched, _ := p.StrictMatch([]string{"section bad", "other"}, "section")
	assert.Len(t, matched, 1)
}

func TestSummaryWriter_Default(t *testing.T) {
	var sw SummaryWriter = DefaultSummaryWriter{}
	var buf bytes.Buffer
	sw.WriteModify(&buf, model.ModifySummary{Status: "ok"})
	assert.Contains(t, buf.String(), "status=ok")

	buf.Reset()
	sw.WriteExtract(&buf, model.ExtractSummary{Extracted: 3})
	assert.Contains(t, buf.String(), "extracted=3")
}

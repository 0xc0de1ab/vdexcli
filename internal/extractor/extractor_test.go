package extractor

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// --- Mock FileWriter ---

type mockFileWriter struct {
	dirs    []string
	files   map[string][]byte
	statErr map[string]error
}

func newMockFS() *mockFileWriter {
	return &mockFileWriter{
		files:   map[string][]byte{},
		statErr: map[string]error{},
	}
}

func (m *mockFileWriter) MkdirAll(path string, _ os.FileMode) error {
	m.dirs = append(m.dirs, path)
	return nil
}

func (m *mockFileWriter) WriteFile(name string, data []byte, _ os.FileMode) error {
	m.files[name] = append([]byte{}, data...)
	return nil
}

func (m *mockFileWriter) Stat(name string) (os.FileInfo, error) {
	if err, ok := m.statErr[name]; ok {
		return nil, err
	}
	return nil, os.ErrNotExist
}

// --- Mock NameRenderer ---

type mockRenderer struct {
	names map[int]string
}

func (m *mockRenderer) Render(_ string, _ string, d model.DexReport) (string, string, error) {
	if name, ok := m.names[d.Index]; ok {
		return name, "", nil
	}
	return fmt.Sprintf("dex_%d.dex", d.Index), "", nil
}

// --- Tests ---

func TestExtractor_BasicExtraction(t *testing.T) {
	raw := make([]byte, 256)
	copy(raw[100:120], []byte("fake dex content 0!"))
	copy(raw[200:220], []byte("fake dex content 1!"))

	dexes := []model.DexReport{
		{Index: 0, Offset: 100, Size: 20},
		{Index: 1, Offset: 200, Size: 20},
	}

	fs := newMockFS()
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}

	res, err := ext.Extract("app.vdex", raw, dexes, "/out", Options{})
	require.NoError(t, err)

	assert.Equal(t, 2, res.Extracted)
	assert.Equal(t, 0, res.Failed)
	assert.Empty(t, res.Warnings)
	assert.Len(t, fs.files, 2)
	assert.Equal(t, raw[100:120], fs.files["/out/app.vdex_0_0.dex"])
	assert.Equal(t, raw[200:220], fs.files["/out/app.vdex_1_0.dex"])
}

func TestExtractor_InvalidRange_StopsOnError(t *testing.T) {
	raw := make([]byte, 50)
	dexes := []model.DexReport{
		{Index: 0, Offset: 100, Size: 20}, // out of bounds
	}

	fs := newMockFS()
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}

	res, err := ext.Extract("app.vdex", raw, dexes, "/out", Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid range")
	assert.Equal(t, 0, res.Extracted)
	assert.Equal(t, 1, res.Failed)
}

func TestExtractor_InvalidRange_ContinueOnError(t *testing.T) {
	raw := make([]byte, 256)
	copy(raw[200:220], []byte("good dex!"))

	dexes := []model.DexReport{
		{Index: 0, Offset: 999, Size: 20}, // bad
		{Index: 1, Offset: 200, Size: 20}, // good
	}

	fs := newMockFS()
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}

	res, err := ext.Extract("app.vdex", raw, dexes, "/out", Options{ContinueOnError: true})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Extracted)
	assert.Equal(t, 1, res.Failed)
	assert.Len(t, res.Warnings, 1)
	assert.Contains(t, res.Warnings[0], "invalid range")
}

func TestExtractor_EmptyDexList(t *testing.T) {
	fs := newMockFS()
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}

	res, err := ext.Extract("app.vdex", []byte{}, nil, "/out", Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Extracted)
	assert.Empty(t, fs.dirs)
}

func TestExtractor_CustomRenderer(t *testing.T) {
	raw := make([]byte, 128)
	copy(raw[10:20], []byte("content!!"))

	dexes := []model.DexReport{{Index: 0, Offset: 10, Size: 10}}

	fs := newMockFS()
	renderer := &mockRenderer{names: map[int]string{0: "custom_name.dex"}}
	ext := &Extractor{FS: fs, Renderer: renderer}

	res, err := ext.Extract("app.vdex", raw, dexes, "/out", Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Extracted)
	assert.Contains(t, fs.files, "/out/custom_name.dex")
}

func TestExtractor_TemplateRenderer_ValidTokens(t *testing.T) {
	r := &TemplateRenderer{}
	d := model.DexReport{Index: 2, Checksum: 0xCAFE, Offset: 0x100, Size: 0x200}

	name, warn, err := r.Render("{base}_{index}_{checksum_hex}.dex", "app.vdex", d)
	require.NoError(t, err)
	assert.Empty(t, warn)
	assert.Equal(t, "app.vdex_2_0xcafe.dex", name)
}

func TestExtractor_TemplateRenderer_UnknownToken(t *testing.T) {
	r := &TemplateRenderer{}
	d := model.DexReport{Index: 0, Checksum: 1}

	name, warn, err := r.Render("{base}_{bogus}.dex", "app.vdex", d)
	require.NoError(t, err)
	assert.Contains(t, warn, "unsupported template tokens")
	assert.Contains(t, warn, "bogus")
	assert.NotContains(t, name, "bogus", "should fall back to default template")
}

func TestExtractor_TemplateRenderer_WarnOnce(t *testing.T) {
	r := &TemplateRenderer{}
	d0 := model.DexReport{Index: 0, Checksum: 1}
	d1 := model.DexReport{Index: 1, Checksum: 2}

	_, warn1, _ := r.Render("{bogus}", "a.vdex", d0)
	_, warn2, _ := r.Render("{bogus}", "a.vdex", d1)

	assert.NotEmpty(t, warn1, "first call should warn")
	assert.Empty(t, warn2, "second call should suppress")
}

func TestExtract_ConvenienceFunction(t *testing.T) {
	raw := make([]byte, 64)
	report := &model.VdexReport{
		Dexes: []model.DexReport{{Index: 0, Offset: 0, Size: 32}},
	}

	dir := t.TempDir()
	res, err := Extract("test.vdex", raw, report, dir, Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Extracted)
}

func TestExtractor_MkdirAllFails(t *testing.T) {
	fs := &failMkdirFS{}
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}
	dexes := []model.DexReport{{Index: 0, Offset: 0, Size: 10}}
	res, err := ext.Extract("app.vdex", make([]byte, 64), dexes, "/out", Options{})
	require.Error(t, err)
	assert.Equal(t, 1, res.Failed)
}

type failMkdirFS struct{}

func (failMkdirFS) MkdirAll(_ string, _ os.FileMode) error        { return fmt.Errorf("mkdir failed") }
func (failMkdirFS) WriteFile(_ string, _ []byte, _ os.FileMode) error { return nil }
func (failMkdirFS) Stat(_ string) (os.FileInfo, error)            { return nil, os.ErrNotExist }

func TestExtractor_RendererError_Stops(t *testing.T) {
	fs := newMockFS()
	renderer := &errRenderer{}
	ext := &Extractor{FS: fs, Renderer: renderer}
	dexes := []model.DexReport{{Index: 0, Offset: 0, Size: 10}}
	_, err := ext.Extract("app.vdex", make([]byte, 64), dexes, "/out", Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "render fail")
}

func TestExtractor_RendererError_ContinueOnError(t *testing.T) {
	fs := newMockFS()
	renderer := &errRenderer{}
	ext := &Extractor{FS: fs, Renderer: renderer}
	dexes := []model.DexReport{
		{Index: 0, Offset: 0, Size: 10},
		{Index: 1, Offset: 10, Size: 10},
	}
	res, err := ext.Extract("app.vdex", make([]byte, 64), dexes, "/out", Options{ContinueOnError: true})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Extracted)
	assert.Equal(t, 2, res.Failed)
}

type errRenderer struct{}

func (errRenderer) Render(_, _ string, _ model.DexReport) (string, string, error) {
	return "", "", fmt.Errorf("render fail")
}

func TestExtractor_WriteFileFails_ContinueOnError(t *testing.T) {
	fs := &failWriteFS{}
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}
	dexes := []model.DexReport{{Index: 0, Offset: 0, Size: 10}}
	res, err := ext.Extract("app.vdex", make([]byte, 64), dexes, "/out", Options{ContinueOnError: true})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Extracted)
	assert.Equal(t, 1, res.Failed)
	assert.NotEmpty(t, res.Warnings)
}

func TestExtractor_WriteFileFails_Stops(t *testing.T) {
	fs := &failWriteFS{}
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}
	dexes := []model.DexReport{{Index: 0, Offset: 0, Size: 10}}
	_, err := ext.Extract("app.vdex", make([]byte, 64), dexes, "/out", Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write failed")
}

type failWriteFS struct{}

func (failWriteFS) MkdirAll(_ string, _ os.FileMode) error            { return nil }
func (failWriteFS) WriteFile(_ string, _ []byte, _ os.FileMode) error { return fmt.Errorf("write failed") }
func (failWriteFS) Stat(_ string) (os.FileInfo, error)                { return nil, os.ErrNotExist }

func TestExtractor_UniquePathCollision(t *testing.T) {
	// First path already exists on FS → should append _1
	fs := newMockFS()
	fs.statErr["/out/app.vdex_0_0.dex"] = nil // exists (no error = file found)
	ext := &Extractor{FS: fs, Renderer: &TemplateRenderer{}}
	dexes := []model.DexReport{{Index: 0, Offset: 0, Size: 10}}
	res, err := ext.Extract("app.vdex", make([]byte, 64), dexes, "/out", Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Extracted)
	// Should have written to _1 variant
	assert.Contains(t, fs.files, "/out/app.vdex_0_0_1.dex")
}

func TestExtract_NilReport(t *testing.T) {
	res, err := Extract("test.vdex", nil, nil, "/out", Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Extracted)
}

func TestExtract_EmptyDexes(t *testing.T) {
	res, err := Extract("test.vdex", nil, &model.VdexReport{}, "/out", Options{})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Extracted)
}

func TestExtractor_RendererWarningDuringExtract(t *testing.T) {
	// Renderer returns warnMsg → Extract should collect it in res.Warnings
	fs := newMockFS()
	renderer := &warnRenderer{}
	ext := &Extractor{FS: fs, Renderer: renderer}
	dexes := []model.DexReport{{Index: 0, Offset: 0, Size: 10}}
	res, err := ext.Extract("app.vdex", make([]byte, 64), dexes, "/out", Options{})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Extracted)
	assert.NotEmpty(t, res.Warnings)
	assert.Contains(t, res.Warnings[0], "renderer warning")
}

type warnRenderer struct{}

func (warnRenderer) Render(_, _ string, d model.DexReport) (string, string, error) {
	return fmt.Sprintf("dex_%d.dex", d.Index), "renderer warning", nil
}

func TestTemplateRenderer_UnclosedBrace(t *testing.T) {
	r := &TemplateRenderer{}
	d := model.DexReport{Index: 0}
	name, _, err := r.Render("prefix_{base", "app.vdex", d)
	require.NoError(t, err)
	assert.Contains(t, name, "prefix_{base")
}

// Verify interface compliance at compile time.
var (
	_ DexExtractor = (*Extractor)(nil)
	_ FileWriter   = OSFileWriter{}
	_ NameRenderer = (*TemplateRenderer)(nil)
)

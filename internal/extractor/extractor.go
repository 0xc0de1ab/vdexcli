// Package extractor handles DEX file extraction from parsed VDEX data.
//
// The core logic depends on two interfaces — FileWriter for filesystem
// operations and NameRenderer for output filename generation — making it
// testable without touching the real filesystem.
package extractor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// FileWriter abstracts filesystem write operations.
// Implementations: OSFileWriter (real), or a mock for testing.
type FileWriter interface {
	MkdirAll(path string, perm os.FileMode) error
	WriteFile(name string, data []byte, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
}

// NameRenderer generates output filenames from a template and DEX metadata.
type NameRenderer interface {
	Render(template string, baseName string, d model.DexReport) (name string, warning string, err error)
}

// DexExtractor extracts embedded DEX files from raw VDEX bytes.
// This is the primary interface for consumers (cmd layer).
type DexExtractor interface {
	Extract(vdexPath string, raw []byte, dexes []model.DexReport, outDir string, opts Options) (Result, error)
}

// Options controls extraction behavior.
type Options struct {
	NameTemplate    string
	ContinueOnError bool
}

// Result holds extraction statistics.
type Result struct {
	Extracted int
	Failed    int
	Warnings  []string
}

// --- Concrete implementations ---

// OSFileWriter implements FileWriter using the real filesystem.
type OSFileWriter struct{}

func (OSFileWriter) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (OSFileWriter) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

func (OSFileWriter) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// TemplateRenderer implements NameRenderer using brace-delimited templates.
type TemplateRenderer struct {
	warned bool
}

func (r *TemplateRenderer) Render(tmpl string, baseName string, d model.DexReport) (string, string, error) {
	repl := map[string]string{
		"base":         sanitize(baseName),
		"index":        fmt.Sprintf("%d", d.Index),
		"checksum":     fmt.Sprintf("%d", d.Checksum),
		"checksum_hex": fmt.Sprintf("%#x", d.Checksum),
		"offset":       fmt.Sprintf("%#x", d.Offset),
		"size":         fmt.Sprintf("%#x", d.Size),
	}

	var name string
	var unknown []string
	unknownSet := map[string]bool{}
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '{' {
			name += string(tmpl[i])
			i++
			continue
		}
		end := strings.IndexByte(tmpl[i+1:], '}')
		if end < 0 {
			name += tmpl[i:]
			break
		}
		end = i + 1 + end
		key := tmpl[i+1 : end]
		if val, ok := repl[key]; ok {
			name += val
		} else {
			name += "{" + key + "}"
			if !unknownSet[key] {
				unknownSet[key] = true
				unknown = append(unknown, key)
			}
		}
		i = end + 1
	}

	if len(unknown) > 0 {
		fallback, _, _ := r.Render(model.DefaultNameTemplate, baseName, d)
		warnMsg := fmt.Sprintf("unsupported template tokens %s; falling back to %q",
			strings.Join(unknown, ", "), model.DefaultNameTemplate)
		if !r.warned {
			r.warned = true
			return fallback, warnMsg, nil
		}
		return fallback, "", nil
	}
	return name, "", nil
}

// Extractor is the standard DexExtractor implementation backed by
// a FileWriter and NameRenderer.
type Extractor struct {
	FS       FileWriter
	Renderer NameRenderer
}

// New creates an Extractor with real filesystem and template renderer.
func New() *Extractor {
	return &Extractor{
		FS:       OSFileWriter{},
		Renderer: &TemplateRenderer{},
	}
}

func (e *Extractor) Extract(vdexPath string, raw []byte, dexes []model.DexReport, outDir string, opts Options) (Result, error) {
	res := Result{}
	if len(dexes) == 0 {
		return res, nil
	}
	if err := e.FS.MkdirAll(outDir, 0o755); err != nil {
		res.Failed = len(dexes)
		return res, err
	}

	tmpl := opts.NameTemplate
	if tmpl == "" {
		tmpl = model.DefaultNameTemplate
	}

	usedPaths := map[string]struct{}{}
	base := filepath.Base(vdexPath)

	for _, d := range dexes {
		start := int(d.Offset)
		end := start + int(d.Size)
		if start < 0 || end > len(raw) || end <= start {
			err := fmt.Errorf("dex[%d] invalid range %#x-%#x", d.Index, start, end)
			res.Failed++
			if opts.ContinueOnError {
				res.Warnings = append(res.Warnings, err.Error())
				continue
			}
			return res, err
		}
		name, warnMsg, err := e.Renderer.Render(tmpl, base, d)
		if err != nil {
			res.Failed++
			if opts.ContinueOnError {
				res.Warnings = append(res.Warnings, err.Error())
				continue
			}
			return res, err
		}
		if warnMsg != "" {
			res.Warnings = append(res.Warnings, warnMsg)
		}
		path := e.uniquePath(outDir, name, usedPaths)
		if err := e.FS.WriteFile(path, raw[start:end], 0o644); err != nil {
			if opts.ContinueOnError {
				res.Failed++
				res.Warnings = append(res.Warnings, fmt.Sprintf("failed to write dex[%d] -> %s: %v", d.Index, path, err))
				continue
			}
			return res, err
		}
		res.Extracted++
	}
	res.Failed = len(dexes) - res.Extracted
	return res, nil
}

func (e *Extractor) uniquePath(baseDir, name string, used map[string]struct{}) string {
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	ext := filepath.Ext(name)
	candidate := name
	for idx := 1; ; idx++ {
		path := filepath.Join(baseDir, candidate)
		if _, existsUsed := used[path]; !existsUsed {
			if _, err := e.FS.Stat(path); os.IsNotExist(err) {
				used[path] = struct{}{}
				return path
			}
		}
		candidate = fmt.Sprintf("%s_%d%s", stem, idx, ext)
	}
}

func sanitize(v string) string {
	v = strings.ReplaceAll(v, string(filepath.Separator), "_")
	v = strings.ReplaceAll(v, "/", "_")
	v = strings.ReplaceAll(v, "\\", "_")
	return strings.TrimSpace(v)
}

// Extract is a convenience function using the default extractor.
// Kept for backward compatibility with existing callers.
func Extract(vdexPath string, raw []byte, report *model.VdexReport, outDir string, opts Options) (Result, error) {
	if report == nil || len(report.Dexes) == 0 {
		return Result{}, nil
	}
	return New().Extract(vdexPath, raw, report.Dexes, outDir, opts)
}

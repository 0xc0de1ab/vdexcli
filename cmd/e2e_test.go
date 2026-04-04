package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testBinary string
var testVdexPath string
var testModifiedVdexPath string
var testPatchPath string

func TestMain(m *testing.M) {
	// Build binary once for all e2e tests.
	tmp, err := os.MkdirTemp("", "vdexcli-e2e-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)

	testBinary = filepath.Join(tmp, "vdexcli")
	out, err := exec.Command("go", "build", "-o", testBinary, "..").CombinedOutput()
	if err != nil {
		panic("go build failed: " + string(out))
	}

	// Generate synthetic VDEX fixture.
	dex := buildSyntheticDex(3)
	verifier := buildSyntheticVerifierDeps(3)
	vdex := buildSyntheticVdex(dex, verifier)
	testVdexPath = filepath.Join(tmp, "test.vdex")
	if err := os.WriteFile(testVdexPath, vdex, 0644); err != nil {
		panic(err)
	}

	// Generate patch JSON fixture (no extra strings to avoid payload-too-large).
	testPatchPath = filepath.Join(tmp, "patch.json")
	patch := `{"mode":"replace","dexes":[{"dex_index":0,"classes":[{"class_index":0,"verified":false},{"class_index":1,"verified":false},{"class_index":2,"verified":false}]}]}`
	if err := os.WriteFile(testPatchPath, []byte(patch), 0644); err != nil {
		panic(err)
	}

	// Generate modified VDEX for diff tests.
	testModifiedVdexPath = filepath.Join(tmp, "modified.vdex")
	modCmd := exec.Command(testBinary, "modify", "--verifier-json", testPatchPath, testVdexPath, testModifiedVdexPath)
	if out, err := modCmd.CombinedOutput(); err != nil {
		panic("modify failed: " + string(out))
	}

	os.Exit(m.Run())
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(testBinary, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// --- version ---

func TestE2E_Version(t *testing.T) {
	out, _, code := runCLI(t, "version")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "vdexcli version")
}

func TestE2E_VersionFlag(t *testing.T) {
	out, _, code := runCLI(t, "--version")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "vdexcli version")
}

// --- parse ---

func TestE2E_Parse_Text(t *testing.T) {
	out, _, code := runCLI(t, "parse", "--show-meaning=false", testVdexPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, `vdex magic="vdex"`)
	assert.Contains(t, out, "kChecksumSection")
	assert.Contains(t, out, "byte_coverage:")
}

func TestE2E_Parse_JSON(t *testing.T) {
	out, _, code := runCLI(t, "parse", "--format", "json", "--show-meaning=false", testVdexPath)
	assert.Equal(t, 0, code)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &data))
	assert.Equal(t, "1.0.0", data["schema_version"])
	assert.Equal(t, "vdex", data["header"].(map[string]any)["magic"])
	assert.NotNil(t, data["byte_coverage"])
}

func TestE2E_Parse_JSONL(t *testing.T) {
	out, _, code := runCLI(t, "parse", "--format", "jsonl", "--show-meaning=false", testVdexPath)
	assert.Equal(t, 0, code)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1, "jsonl should be exactly 1 line")

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &data))
	assert.Equal(t, "vdex", data["header"].(map[string]any)["magic"])
}

func TestE2E_Parse_Summary(t *testing.T) {
	out, _, code := runCLI(t, "parse", "--format", "summary", testVdexPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "status=")
	assert.Contains(t, out, "coverage=")
	assert.Contains(t, out, "sections=4")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1, "summary should be exactly 1 line")
}

func TestE2E_Parse_Sections(t *testing.T) {
	out, _, code := runCLI(t, "parse", "--format", "sections", testVdexPath)
	assert.Equal(t, 0, code)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.GreaterOrEqual(t, len(lines), 2, "header + at least 1 row")
	assert.Equal(t, "kind\tname\toffset\tsize", lines[0])
	assert.Contains(t, lines[1], "kChecksumSection")
}

func TestE2E_Parse_Coverage(t *testing.T) {
	out, _, code := runCLI(t, "parse", "--format", "coverage", testVdexPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "coverage=")
	assert.Contains(t, out, "vdex_header")
}

func TestE2E_Parse_InvalidFormat(t *testing.T) {
	_, stderr, code := runCLI(t, "parse", "--format", "xml", testVdexPath)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "unsupported --format")
}

func TestE2E_Parse_RootShorthand(t *testing.T) {
	out, _, code := runCLI(t, "--show-meaning=false", testVdexPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, `vdex magic="vdex"`)
}

func TestE2E_Parse_NoArgs(t *testing.T) {
	_, stderr, code := runCLI(t, "parse")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "input vdex path is required")
}

func TestE2E_Parse_NonexistentFile(t *testing.T) {
	_, stderr, code := runCLI(t, "parse", "/tmp/nonexistent_12345.vdex")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "no such file")
}

func TestE2E_Parse_JSONFlag(t *testing.T) {
	out, _, code := runCLI(t, "parse", "--json", "--show-meaning=false", testVdexPath)
	assert.Equal(t, 0, code)
	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &data))
	assert.Equal(t, "vdex", data["header"].(map[string]any)["magic"])
}

// --- extract-dex ---

func TestE2E_ExtractDex(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "dex-out")
	out, _, code := runCLI(t, "extract-dex", testVdexPath, outDir)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "extracted")

	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "should extract at least one dex file")
}

func TestE2E_ExtractDex_JSON(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "dex-json")
	out, _, code := runCLI(t, "extract-dex", "--format", "json", testVdexPath, outDir)
	assert.Equal(t, 0, code)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &data))
	assert.Equal(t, "1.0.0", data["schema_version"])
}

func TestE2E_ExtractDex_Summary(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "dex-summary")
	out, _, code := runCLI(t, "extract-dex", "--format", "summary", testVdexPath, outDir)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "status=")
	assert.Contains(t, out, "extracted=")
}

func TestE2E_ExtractDex_MissingArgs(t *testing.T) {
	_, stderr, code := runCLI(t, "extract-dex", testVdexPath)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "accepts 2 arg")
}

// --- modify ---

func TestE2E_Modify_DryRun(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.vdex")
	out, stderr, code := runCLI(t, "modify", "--dry-run", "--verifier-json", testPatchPath, testVdexPath, outPath)
	if code != 0 {
		t.Logf("stderr: %s", stderr)
		t.Logf("stdout: %s", out)
	}
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "dry-run")

	_, err := os.Stat(outPath)
	assert.True(t, os.IsNotExist(err), "dry-run should not write output file")
}

func TestE2E_Modify_DryRun_JSON(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.vdex")
	out, _, code := runCLI(t, "modify", "--dry-run", "--format", "json", "--verifier-json", testPatchPath, testVdexPath, outPath)
	assert.Equal(t, 0, code)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &data))
	assert.Equal(t, "ok", data["status"])
	assert.Equal(t, true, data["dry_run"])
}

func TestE2E_Modify_DryRun_Summary(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.vdex")
	out, _, code := runCLI(t, "modify", "--dry-run", "--format", "summary", "--verifier-json", testPatchPath, testVdexPath, outPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "status=ok")
	assert.Contains(t, out, "dry_run=true")
}

func TestE2E_Modify_Write(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "modified.vdex")
	_, _, code := runCLI(t, "modify", "--verifier-json", testPatchPath, testVdexPath, outPath)
	assert.Equal(t, 0, code)

	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "output file should be non-empty")
}

func TestE2E_Modify_ReparseOutput(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "modified.vdex")
	_, _, code := runCLI(t, "modify", "--verifier-json", testPatchPath, testVdexPath, outPath)
	require.Equal(t, 0, code)

	out, _, code := runCLI(t, "parse", "--format", "summary", outPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, `version=027`)
}

func TestE2E_Modify_MissingPatch(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.vdex")
	_, stderr, code := runCLI(t, "modify", testVdexPath, outPath)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "--verifier-json is required")
}

func TestE2E_Modify_InvalidMode(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.vdex")
	_, stderr, code := runCLI(t, "modify", "--mode", "bogus", "--verifier-json", testPatchPath, testVdexPath, outPath)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "unsupported --mode")
}

func TestE2E_Modify_SameInputOutput(t *testing.T) {
	_, stderr, code := runCLI(t, "modify", "--verifier-json", testPatchPath, testVdexPath, testVdexPath)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "--force")
}

func TestE2E_Modify_LogFile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.vdex")
	logPath := filepath.Join(t.TempDir(), "modify.log")
	_, _, code := runCLI(t, "modify", "--dry-run", "--log-file", logPath, "--verifier-json", testPatchPath, testVdexPath, outPath)
	assert.Equal(t, 0, code)

	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.NotEmpty(t, logData)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logData, &entry))
	assert.NotEmpty(t, entry["timestamp"])
	assert.NotNil(t, entry["summary"])
}

// --- dump ---

func TestE2E_Dump_Text(t *testing.T) {
	out, _, code := runCLI(t, "dump")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "meanings:")
	assert.Contains(t, out, "magic:")
}

func TestE2E_Dump_JSON(t *testing.T) {
	out, _, code := runCLI(t, "dump", "--format", "json")
	assert.Equal(t, 0, code)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &data))
	assert.NotNil(t, data["vdex_file"])
}

func TestE2E_Dump_JSONL(t *testing.T) {
	out, _, code := runCLI(t, "dump", "--format", "jsonl")
	assert.Equal(t, 0, code)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1)
}

// --- strict mode ---

func TestE2E_Parse_Strict(t *testing.T) {
	_, _, code := runCLI(t, "parse", "--strict", "--show-meaning=false", testVdexPath)
	assert.NotEqual(t, 0, code, "strict mode should fail on any warning")
}

func TestE2E_Parse_StrictWarn_NoMatch(t *testing.T) {
	_, _, code := runCLI(t, "parse", "--strict", "--strict-warn", "nonexistent_pattern_xyz", "--show-meaning=false", testVdexPath)
	assert.Equal(t, 0, code, "strict with non-matching pattern should pass")
}

// --- diff ---

func TestE2E_Diff_Identical(t *testing.T) {
	out, _, code := runCLI(t, "diff", testVdexPath, testVdexPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "identical")
}

func TestE2E_Diff_Different_Text(t *testing.T) {
	out, _, code := runCLI(t, "diff", testVdexPath, testModifiedVdexPath)
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "VDEX diff")
	assert.Contains(t, out, "verifier_deps:")
	assert.Contains(t, out, "summary:")
}

func TestE2E_Diff_JSON(t *testing.T) {
	out, _, code := runCLI(t, "diff", "--format", "json", testVdexPath, testModifiedVdexPath)
	assert.Equal(t, 1, code)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &data))
	summary := data["summary"].(map[string]any)
	assert.Equal(t, false, summary["identical"])
	assert.NotNil(t, data["verifier_diff"])
}

func TestE2E_Diff_JSONL(t *testing.T) {
	out, _, code := runCLI(t, "diff", "--format", "jsonl", testVdexPath, testModifiedVdexPath)
	assert.Equal(t, 1, code)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &data))
	assert.NotNil(t, data["summary"])
}

func TestE2E_Diff_Summary_Different(t *testing.T) {
	out, _, code := runCLI(t, "diff", "--format", "summary", testVdexPath, testModifiedVdexPath)
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "status=different")
	assert.Contains(t, out, "verifier=")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1)
}

func TestE2E_Diff_Summary_Identical(t *testing.T) {
	out, _, code := runCLI(t, "diff", "--format", "summary", testVdexPath, testVdexPath)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "status=identical")
}

func TestE2E_Diff_JSON_Identical(t *testing.T) {
	out, _, code := runCLI(t, "diff", "--json", testVdexPath, testVdexPath)
	assert.Equal(t, 0, code)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &data))
	summary := data["summary"].(map[string]any)
	assert.Equal(t, true, summary["identical"])
}

func TestE2E_Diff_InvalidFormat(t *testing.T) {
	_, stderr, code := runCLI(t, "diff", "--format", "xml", testVdexPath, testVdexPath)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "unsupported --format")
}

func TestE2E_Diff_MissingArg(t *testing.T) {
	_, stderr, code := runCLI(t, "diff", testVdexPath)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "accepts 2 arg")
}

func TestE2E_Diff_NonexistentFile(t *testing.T) {
	_, stderr, code := runCLI(t, "diff", testVdexPath, "/nonexistent_xyz.vdex")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "no such file")
}

func TestE2E_Diff_ExitCode_Identical(t *testing.T) {
	_, _, code := runCLI(t, "diff", testVdexPath, testVdexPath)
	assert.Equal(t, 0, code, "identical files should exit 0")
}

func TestE2E_Diff_ExitCode_Different(t *testing.T) {
	_, _, code := runCLI(t, "diff", testVdexPath, testModifiedVdexPath)
	assert.Equal(t, 1, code, "different files should exit 1")
}

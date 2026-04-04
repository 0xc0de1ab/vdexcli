package cmd

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/0xc0de1ab/vdexcli/internal/modifier"
	"github.com/0xc0de1ab/vdexcli/internal/parser"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildSyntheticDex(classDefsSize uint32) []byte {
	dex := make([]byte, 0x70)
	copy(dex[0:4], "dex\n")
	copy(dex[4:8], "035\x00")
	binary.LittleEndian.PutUint32(dex[0x08:], 0xABCD1234)
	binary.LittleEndian.PutUint32(dex[0x20:], 0x70)
	binary.LittleEndian.PutUint32(dex[0x24:], 0x70)
	binary.LittleEndian.PutUint32(dex[0x28:], 0x12345678)
	binary.LittleEndian.PutUint32(dex[0x60:], classDefsSize)
	return dex
}

func buildSyntheticVerifierDeps(classDefsSize uint32) []byte {
	var section bytes.Buffer

	numDex := uint32(1)
	pairDataBase := numDex*4 + (classDefsSize+1)*4
	class0Data := []byte{0x05, 0x0A}

	class0Start := pairDataBase
	class2Start := class0Start + uint32(len(class0Data))
	sentinel := class2Start

	// Per-dex offset: dex 0 data starts at offset numDex*4
	binary.Write(&section, binary.LittleEndian, numDex*4)

	classOffsets := []uint32{class0Start, 0xFFFFFFFF, class2Start, sentinel}
	for _, off := range classOffsets {
		binary.Write(&section, binary.LittleEndian, off)
	}

	section.Write(class0Data)

	// Align to 4 bytes
	for section.Len()%4 != 0 {
		section.WriteByte(0)
	}

	// Extra strings: count=1
	binary.Write(&section, binary.LittleEndian, uint32(1))
	stringDataOffset := uint32(section.Len()) + 4
	binary.Write(&section, binary.LittleEndian, stringDataOffset)
	section.WriteString("Ltest/Class;")
	section.WriteByte(0)

	return section.Bytes()
}

func buildSyntheticVdex(dexData []byte, verifierDeps []byte) []byte {
	var buf bytes.Buffer

	buf.WriteString("vdex")
	buf.WriteString("027\x00")
	binary.Write(&buf, binary.LittleEndian, uint32(4))

	headerSize := uint32(12)
	sectionHeadersSize := uint32(48)
	dataStart := headerSize + sectionHeadersSize

	checksumOffset := dataStart
	checksumSize := uint32(4)
	dexOffset := checksumOffset + checksumSize
	dexSize := uint32(len(dexData))
	verifierOffset := dexOffset + dexSize
	for verifierOffset%4 != 0 {
		verifierOffset++
	}
	verifierSize := uint32(len(verifierDeps))
	typeLookupOffset := verifierOffset + verifierSize

	sections := []struct{ kind, offset, size uint32 }{
		{0, checksumOffset, checksumSize},
		{1, dexOffset, dexSize},
		{2, verifierOffset, verifierSize},
		{3, typeLookupOffset, 0},
	}
	for _, s := range sections {
		binary.Write(&buf, binary.LittleEndian, s.kind)
		binary.Write(&buf, binary.LittleEndian, s.offset)
		binary.Write(&buf, binary.LittleEndian, s.size)
	}

	binary.Write(&buf, binary.LittleEndian, uint32(0xDEADBEEF))
	buf.Write(dexData)

	for buf.Len() < int(verifierOffset) {
		buf.WriteByte(0)
	}
	buf.Write(verifierDeps)

	return buf.Bytes()
}

func TestParseVdex_VerifierDeps(t *testing.T) {
	classDefsSize := uint32(3)
	dexData := buildSyntheticDex(classDefsSize)
	verifierDeps := buildSyntheticVerifierDeps(classDefsSize)
	vdexBytes := buildSyntheticVdex(dexData, verifierDeps)

	tmpFile := filepath.Join(t.TempDir(), "test.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdexBytes, 0644))

	report, _, err := parser.ParseVdex(tmpFile, true)
	require.NoError(t, err)

	require.Len(t, report.Dexes, 1)
	assert.Equal(t, classDefsSize, report.Dexes[0].ClassDefs)

	require.NotNil(t, report.Verifier)
	require.Len(t, report.Verifier.Dexes, 1)

	vd := report.Verifier.Dexes[0]
	assert.Equal(t, 2, vd.VerifiedClasses)
	assert.Equal(t, 1, vd.UnverifiedClasses)
	assert.Equal(t, 1, vd.AssignabilityPairs)
	require.GreaterOrEqual(t, len(vd.FirstPairs), 1)
	assert.Equal(t, uint32(5), vd.FirstPairs[0].DestID)
	assert.Equal(t, uint32(10), vd.FirstPairs[0].SrcID)
	assert.Equal(t, 1, vd.ExtraStringCount)
}

func TestBuildVerifierSectionReplacement(t *testing.T) {
	classDefsSize := uint32(3)
	trueVal := true
	falseVal := false

	dexes := []model.DexReport{{Index: 0, ClassDefs: classDefsSize}}
	checksums := []uint32{0xDEADBEEF}
	patch := model.VerifierPatchSpec{
		Mode: "replace",
		Dexes: []model.VerifierPatchDex{{
			DexIndex:     0,
			ExtraStrings: []string{"Ltest/Class;"},
			Classes: []model.VerifierPatchClass{
				{ClassIndex: 0, Verified: &trueVal, Pairs: []model.VerifierPatchPair{{Dest: 5, Src: 10}}},
				{ClassIndex: 1, Verified: &falseVal},
				{ClassIndex: 2, Verified: &trueVal, Pairs: []model.VerifierPatchPair{}},
			},
		}},
	}

	sectionBytes, warnings, err := modifier.BuildVerifierSectionReplacement(dexes, checksums, patch)
	require.NoError(t, err)
	for _, w := range warnings {
		t.Logf("warning: %s", w)
	}

	require.GreaterOrEqual(t, len(sectionBytes), 4, "section too small")

	dex0Offset := binary.LittleEndian.Uint32(sectionBytes[0:4])
	assert.Equal(t, uint32(4), dex0Offset, "dex 0 offset should be section-absolute")

	classOffsetsStart := int(dex0Offset)
	numClassOffsets := int(classDefsSize) + 1
	require.GreaterOrEqual(t, len(sectionBytes), classOffsetsStart+numClassOffsets*4)

	classOffsets := make([]uint32, numClassOffsets)
	for i := 0; i < numClassOffsets; i++ {
		off := classOffsetsStart + i*4
		classOffsets[i] = binary.LittleEndian.Uint32(sectionBytes[off : off+4])
	}

	assert.NotEqual(t, uint32(0xFFFFFFFF), classOffsets[0], "class 0 should be verified")
	assert.Equal(t, uint32(0xFFFFFFFF), classOffsets[1], "class 1 should be unverified")
	assert.NotEqual(t, uint32(0xFFFFFFFF), classOffsets[2], "class 2 should be verified")

	class0DataOff := int(classOffsets[0])
	require.Less(t, class0DataOff+1, len(sectionBytes))
	assert.Equal(t, byte(5), sectionBytes[class0DataOff], "class 0 dest LEB128")
	assert.Equal(t, byte(10), sectionBytes[class0DataOff+1], "class 0 src LEB128")
	assert.Equal(t, classOffsets[3], classOffsets[2], "class 2 offset == sentinel for 0-pair class")

	// Round-trip: build full VDEX and re-parse
	dexData := buildSyntheticDex(classDefsSize)
	vdexBytes := buildSyntheticVdex(dexData, sectionBytes)

	tmpFile := filepath.Join(t.TempDir(), "roundtrip.vdex")
	require.NoError(t, os.WriteFile(tmpFile, vdexBytes, 0644))

	report, _, err := parser.ParseVdex(tmpFile, true)
	require.NoError(t, err)
	require.NotNil(t, report.Verifier)
	require.Len(t, report.Verifier.Dexes, 1)

	vd := report.Verifier.Dexes[0]
	assert.Equal(t, 2, vd.VerifiedClasses, "round-trip verified")
	assert.Equal(t, 1, vd.UnverifiedClasses, "round-trip unverified")
	assert.Equal(t, 1, vd.AssignabilityPairs, "round-trip pairs")
	assert.Equal(t, 1, vd.ExtraStringCount, "round-trip extra strings")
}

func TestRealVdexFiles_Android16(t *testing.T) {
	archivePath := filepath.Join("..", "testdata", "vdex-files-android-16.0.0_r4.tar.zst")
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		t.Skipf("test archive not found: %s", archivePath)
	}

	tarPath := filepath.Join(t.TempDir(), "vdex.tar")
	zstdCmd := exec.Command("zstd", "-d", archivePath, "-o", tarPath, "--force")
	out, err := zstdCmd.CombinedOutput()
	require.NoError(t, err, "zstd decompress failed: %s", out)

	tarFile, err := os.Open(tarPath)
	require.NoError(t, err)
	defer tarFile.Close()

	tr := tar.NewReader(tarFile)
	totalFiles, passFiles, dmFiles := 0, 0, 0
	var failures []string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err, "tar read error")
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".vdex") {
			continue
		}

		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		totalFiles++

		tmpFile := filepath.Join(t.TempDir(), fmt.Sprintf("test_%d.vdex", totalFiles))
		require.NoError(t, os.WriteFile(tmpFile, data, 0o644))

		report, _, parseErr := parser.ParseVdex(tmpFile, true)
		shortName := filepath.Base(filepath.Dir(filepath.Dir(hdr.Name))) + "/" + filepath.Base(hdr.Name)

		if parseErr != nil {
			failures = append(failures, fmt.Sprintf("%s: parse error: %v", shortName, parseErr))
			continue
		}
		if report == nil {
			failures = append(failures, fmt.Sprintf("%s: nil report", shortName))
			continue
		}
		if len(report.Errors) > 0 {
			failures = append(failures, fmt.Sprintf("%s: errors: %v", shortName, report.Errors))
			continue
		}

		isDM := true
		for _, s := range report.Sections {
			if s.Name == "kDexFileSection" && s.Size > 0 {
				isDM = false
				break
			}
		}
		if isDM {
			dmFiles++
		}

		if !assert.NotNil(t, report.Coverage, "%s: no coverage report", shortName) {
			failures = append(failures, fmt.Sprintf("%s: no coverage report", shortName))
			continue
		}
		cov := report.Coverage

		maxAllowedGapBytes := 16
		totalGapBytes := 0
		for _, g := range cov.Gaps {
			totalGapBytes += g.Size
			if g.Label == "trailing_bytes" && g.Size > 0 {
				failures = append(failures, fmt.Sprintf("%s: %d trailing bytes at offset %#x", shortName, g.Size, g.Offset))
			}
		}
		if totalGapBytes > maxAllowedGapBytes {
			failures = append(failures, fmt.Sprintf("%s: too many unparsed gap bytes: %d", shortName, totalGapBytes))
			continue
		}

		hasSections := map[string]bool{}
		for _, s := range report.Sections {
			hasSections[s.Name] = true
		}
		if !hasSections["kChecksumSection"] {
			failures = append(failures, fmt.Sprintf("%s: missing checksum section", shortName))
		}
		if !hasSections["kVerifierDepsSection"] {
			failures = append(failures, fmt.Sprintf("%s: missing verifier deps section", shortName))
		}
		if !hasSections["kTypeLookupTableSection"] {
			failures = append(failures, fmt.Sprintf("%s: missing type lookup table section", shortName))
		}

		for _, w := range report.Warnings {
			isVerifierWarn := strings.Contains(w, "verifier") || strings.Contains(w, "extra string")
			if isDM && isVerifierWarn {
				continue
			}
			if strings.Contains(w, "malformed") || strings.Contains(w, "truncated") ||
				strings.Contains(w, "invalid") || strings.Contains(w, "exceeds") {
				failures = append(failures, fmt.Sprintf("%s: warning: %s", shortName, w))
			}
		}

		passFiles++
	}

	t.Logf("Tested %d VDEX files: %d passed, %d DM-format (no dex section), %d issues",
		totalFiles, passFiles, dmFiles, len(failures))

	for i, f := range failures {
		if i >= 50 {
			t.Errorf("  ... and %d more issues", len(failures)-50)
			break
		}
		t.Errorf("  %s", f)
	}

	assert.NotZero(t, totalFiles, "no VDEX files found in archive")
	assert.Equal(t, totalFiles, passFiles, "not all files passed")
}

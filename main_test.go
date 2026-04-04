package main

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
)

// buildSyntheticDex creates a minimal DEX file with the given class_defs_size.
func buildSyntheticDex(classDefsSize uint32) []byte {
	buf := make([]byte, 0x70)

	// Magic: "dex\n" at 0x00
	copy(buf[0x00:], "dex\n")
	// Version: "035\0" at 0x04
	copy(buf[0x04:], "035\x00")
	// Checksum at 0x08
	binary.LittleEndian.PutUint32(buf[0x08:], 0xDEADBEEF)
	// SHA-1 at 0x0C: 20 zero bytes (already zero)
	// file_size at 0x20
	binary.LittleEndian.PutUint32(buf[0x20:], 0x70)
	// header_size at 0x24
	binary.LittleEndian.PutUint32(buf[0x24:], 0x70)
	// endian_tag at 0x28
	binary.LittleEndian.PutUint32(buf[0x28:], 0x12345678)
	// class_defs_size at 0x60
	binary.LittleEndian.PutUint32(buf[0x60:], classDefsSize)

	return buf
}

// buildSyntheticVerifierDeps builds a verifier deps section as ART would encode it
// for 1 dex with 3 classes:
//   - class 0: verified, 1 assignability pair (dest=5, src=10)
//   - class 1: unverified
//   - class 2: verified, 0 pairs
//   - 1 extra string: "Ltest/Class;"
//
// Offsets within the section are section-relative (offset from section byte 0),
// matching how ART's VerifierDeps::Encode() writes them and how the parser
// reconstructs file positions via sectionStart + offset.
func buildSyntheticVerifierDeps(classDefsSize uint32) []byte {
	var section bytes.Buffer

	// Section layout for 1 dex:
	//   [0..3]   per-dex offset array: uint32[1] (section-relative pointer to dex 0 block)
	//   [4..]    dex 0 block: class offsets + pair data + extra strings

	// Per-dex offsets: 1 dex => 1 uint32. Dex 0 block starts at byte 4.
	blockOffset := uint32(4)
	binary.Write(&section, binary.LittleEndian, blockOffset)

	// --- Dex 0 block ---
	// Class offsets table: uint32[classDefsSize + 1], section-relative.
	// After class offsets comes the pair data (no count prefix -- the parser uses
	// the range [offset[i] .. offset[nextValid]) to delimit each class's pairs).
	classOffsetsTableSize := (classDefsSize + 1) * 4

	// Build pair data blobs per class to compute offsets.
	// class 0: dest=5, src=10 as ULEB128
	class0Data := []byte{5, 10}
	// class 1: unverified, no data
	// class 2: verified, 0 pairs, empty blob

	// Pair data starts right after the class offsets table.
	pairDataBase := blockOffset + classOffsetsTableSize

	// class 0 data starts at pairDataBase
	class0Start := pairDataBase
	// class 2 data starts after class 0 data (class 1 is unverified, skipped)
	class2Start := class0Start + uint32(len(class0Data))
	// sentinel: end of all pair data
	sentinel := class2Start // class 2 has 0 pairs, so same as sentinel

	classOffsets := []uint32{
		class0Start,       // class 0: verified
		0xFFFFFFFF,        // class 1: unverified
		class2Start,       // class 2: verified (0 pairs)
		sentinel,          // sentinel
	}

	for _, off := range classOffsets {
		binary.Write(&section, binary.LittleEndian, off)
	}

	// Write pair data
	section.Write(class0Data)
	// class 2 has no pair data

	// Align to 4 bytes before extra strings
	for section.Len()%4 != 0 {
		section.WriteByte(0)
	}

	// Extra strings count
	binary.Write(&section, binary.LittleEndian, uint32(1))

	// Extra string offset table: 1 entry (section-relative)
	// The string data follows immediately after this offset table entry.
	stringDataOffset := uint32(section.Len()) + 4 // +4 for this offset entry itself
	binary.Write(&section, binary.LittleEndian, stringDataOffset)

	// String data: null-terminated
	section.WriteString("Ltest/Class;")
	section.WriteByte(0)

	return section.Bytes()
}

// buildSyntheticVdex constructs a full VDEX v027 file with the given verifier deps section.
func buildSyntheticVdex(dexData []byte, verifierDeps []byte) []byte {
	var buf bytes.Buffer

	// VdexFileHeader: 12 bytes
	buf.WriteString("vdex")         // magic
	buf.WriteString("027\x00")      // version
	binary.Write(&buf, binary.LittleEndian, uint32(4)) // num_sections

	// Section headers: 4 sections × 12 bytes each = 48 bytes
	// Compute offsets
	headerSize := uint32(12)
	sectionHeadersSize := uint32(48)
	dataStart := headerSize + sectionHeadersSize // 60

	// Section 0: Checksum (kind=0)
	checksumOffset := dataStart
	checksumSize := uint32(4) // 1 dex => 1 uint32 checksum

	// Section 1: Dex (kind=1)
	dexOffset := checksumOffset + checksumSize
	dexSize := uint32(len(dexData))

	// Section 2: VerifierDeps (kind=2)
	verifierOffset := dexOffset + dexSize
	verifierSize := uint32(len(verifierDeps))

	// Section 3: TypeLookup (kind=3) — empty
	typeLookupOffset := verifierOffset + verifierSize
	typeLookupSize := uint32(0)
	_ = typeLookupOffset
	_ = typeLookupSize

	// Write section headers
	sections := []struct {
		kind, offset, size uint32
	}{
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

	// Checksum data: 1 dex checksum
	binary.Write(&buf, binary.LittleEndian, uint32(0xDEADBEEF))

	// Dex data
	buf.Write(dexData)

	// Verifier deps data
	buf.Write(verifierDeps)

	return buf.Bytes()
}

func TestParseVdex_VerifierDeps(t *testing.T) {
	classDefsSize := uint32(3)
	dexData := buildSyntheticDex(classDefsSize)
	verifierDeps := buildSyntheticVerifierDeps(classDefsSize)

	vdexBytes := buildSyntheticVdex(dexData, verifierDeps)

	// Write to temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.vdex")
	if err := os.WriteFile(tmpFile, vdexBytes, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	report, _, err := parseVdex(tmpFile)
	if err != nil {
		t.Fatalf("parseVdex failed: %v", err)
	}

	// Check dex classes
	if len(report.Dexes) != 1 {
		t.Fatalf("expected 1 dex, got %d", len(report.Dexes))
	}
	if report.Dexes[0].ClassDefs != classDefsSize {
		t.Fatalf("expected %d class defs, got %d", classDefsSize, report.Dexes[0].ClassDefs)
	}

	// Check verifier deps
	if report.Verifier == nil {
		t.Fatal("verifier report is nil")
	}
	if len(report.Verifier.Dexes) != 1 {
		t.Fatalf("expected 1 verifier dex, got %d", len(report.Verifier.Dexes))
	}

	vd := report.Verifier.Dexes[0]

	if vd.VerifiedClasses != 2 {
		t.Errorf("expected 2 verified classes, got %d", vd.VerifiedClasses)
	}
	if vd.UnverifiedClasses != 1 {
		t.Errorf("expected 1 unverified class, got %d", vd.UnverifiedClasses)
	}
	if vd.AssignabilityPairs != 1 {
		t.Errorf("expected 1 assignability pair, got %d", vd.AssignabilityPairs)
	}
	if len(vd.FirstPairs) < 1 {
		t.Fatal("expected at least 1 first pair")
	}
	if vd.FirstPairs[0].DestID != 5 {
		t.Errorf("expected first pair dest=5, got %d", vd.FirstPairs[0].DestID)
	}
	if vd.FirstPairs[0].SrcID != 10 {
		t.Errorf("expected first pair src=10, got %d", vd.FirstPairs[0].SrcID)
	}
	if vd.ExtraStringCount != 1 {
		t.Errorf("expected 1 extra string, got %d", vd.ExtraStringCount)
	}
}

func TestBuildVerifierSectionReplacement(t *testing.T) {
	classDefsSize := uint32(3)

	trueVal := true
	falseVal := false

	dexes := []dexReport{
		{
			Index:    0,
			ClassDefs: classDefsSize,
		},
	}
	checksums := []uint32{0xDEADBEEF}

	patch := verifierPatchSpec{
		Mode: "replace",
		Dexes: []verifierPatchDex{
			{
				DexIndex:     0,
				ExtraStrings: []string{"Ltest/Class;"},
				Classes: []verifierPatchClass{
					{
						ClassIndex: 0,
						Verified:   &trueVal,
						Pairs:      []verifierPatchPair{{Dest: 5, Src: 10}},
					},
					{
						ClassIndex: 1,
						Verified:   &falseVal,
					},
					{
						ClassIndex: 2,
						Verified:   &trueVal,
						Pairs:      []verifierPatchPair{},
					},
				},
			},
		},
	}

	sectionBytes, warnings, err := buildVerifierSectionReplacement(dexes, checksums, patch)
	if err != nil {
		t.Fatalf("buildVerifierSectionReplacement failed: %v", err)
	}
	for _, w := range warnings {
		t.Logf("warning: %s", w)
	}

	// Verify the section-absolute offsets in the output.
	// Layout: uint32[1] per-dex offsets, then dex 0 data.

	if len(sectionBytes) < 4 {
		t.Fatalf("section too small: %d bytes", len(sectionBytes))
	}

	// Read the per-dex offset for dex 0
	dex0Offset := binary.LittleEndian.Uint32(sectionBytes[0:4])

	// The dex data should start right after the per-dex offsets array (1 * 4 = 4)
	if dex0Offset != 4 {
		t.Errorf("expected dex 0 offset=4 (section-absolute), got %d", dex0Offset)
	}

	// At dex0Offset, read class offsets: uint32[class_def_size + 1] = uint32[4]
	classOffsetsStart := int(dex0Offset)
	numClassOffsets := int(classDefsSize) + 1
	if len(sectionBytes) < classOffsetsStart+numClassOffsets*4 {
		t.Fatalf("section too small for class offsets")
	}

	classOffsets := make([]uint32, numClassOffsets)
	for i := 0; i < numClassOffsets; i++ {
		off := classOffsetsStart + i*4
		classOffsets[i] = binary.LittleEndian.Uint32(sectionBytes[off : off+4])
	}

	// Class 0 should be verified (offset != 0xFFFFFFFF)
	if classOffsets[0] == 0xFFFFFFFF {
		t.Error("class 0 offset should not be 0xFFFFFFFF (should be verified)")
	}
	// Class 1 should be unverified
	if classOffsets[1] != 0xFFFFFFFF {
		t.Errorf("class 1 offset should be 0xFFFFFFFF (unverified), got 0x%08X", classOffsets[1])
	}
	// Class 2 should be verified
	if classOffsets[2] == 0xFFFFFFFF {
		t.Error("class 2 offset should not be 0xFFFFFFFF (should be verified)")
	}

	// Verify class 0's data is at the offset indicated and contains pair (dest=5, src=10).
	// There is no count prefix -- the parser reads ULEB128 pairs until the next
	// valid class offset (or sentinel).
	class0DataOff := int(classOffsets[0])
	if class0DataOff+1 >= len(sectionBytes) {
		t.Fatalf("class 0 data offset %d out of bounds (section size %d)", class0DataOff, len(sectionBytes))
	}
	// dest=5 (0x05), src=10 (0x0A) as single-byte ULEB128 values
	if sectionBytes[class0DataOff] != 5 {
		t.Errorf("class 0: expected dest LEB128=5, got %d", sectionBytes[class0DataOff])
	}
	if sectionBytes[class0DataOff+1] != 10 {
		t.Errorf("class 0: expected src LEB128=10, got %d", sectionBytes[class0DataOff+1])
	}

	// Class 2 has 0 pairs, so its offset should equal the sentinel (empty range).
	sentinelOff := classOffsets[3]
	if classOffsets[2] != sentinelOff {
		t.Errorf("class 2 offset (%d) should equal sentinel (%d) for 0-pair class",
			classOffsets[2], sentinelOff)
	}

	// Now build a full VDEX with this section and re-parse to verify round-trip
	dexData := buildSyntheticDex(classDefsSize)
	vdexBytes := buildSyntheticVdex(dexData, sectionBytes)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "roundtrip.vdex")
	if err := os.WriteFile(tmpFile, vdexBytes, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	report, _, err := parseVdex(tmpFile)
	if err != nil {
		t.Fatalf("parseVdex on rebuilt VDEX failed: %v", err)
	}

	if report.Verifier == nil {
		t.Fatal("verifier report is nil after round-trip")
	}
	if len(report.Verifier.Dexes) != 1 {
		t.Fatalf("expected 1 verifier dex after round-trip, got %d", len(report.Verifier.Dexes))
	}

	vd := report.Verifier.Dexes[0]
	if vd.VerifiedClasses != 2 {
		t.Errorf("round-trip: expected 2 verified classes, got %d", vd.VerifiedClasses)
	}
	if vd.UnverifiedClasses != 1 {
		t.Errorf("round-trip: expected 1 unverified class, got %d", vd.UnverifiedClasses)
	}
	if vd.AssignabilityPairs != 1 {
		t.Errorf("round-trip: expected 1 assignability pair, got %d", vd.AssignabilityPairs)
	}
	if vd.ExtraStringCount != 1 {
		t.Errorf("round-trip: expected 1 extra string, got %d", vd.ExtraStringCount)
	}
}

func TestRealVdexFiles_Android16(t *testing.T) {
	archivePath := filepath.Join("testdata", "vdex-files-android-16.0.0_r4.tar.zst")
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		t.Skipf("test archive not found: %s", archivePath)
	}

	// Decompress zstd → tar
	tarPath := filepath.Join(t.TempDir(), "vdex.tar")
	zstdCmd := exec.Command("zstd", "-d", archivePath, "-o", tarPath, "--force")
	if out, err := zstdCmd.CombinedOutput(); err != nil {
		t.Fatalf("zstd decompress failed: %v\n%s", err, out)
	}

	tarFile, err := os.Open(tarPath)
	if err != nil {
		t.Fatalf("open tar: %v", err)
	}
	defer tarFile.Close()

	tr := tar.NewReader(tarFile)
	totalFiles := 0
	passFiles := 0
	dmFiles := 0
	var failures []string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read error: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".vdex") {
			continue
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		totalFiles++

		// Write to temp file for parseVdex
		tmpFile := filepath.Join(t.TempDir(), fmt.Sprintf("test_%d.vdex", totalFiles))
		if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
			t.Fatalf("write temp: %v", err)
		}

		report, _, parseErr := parseVdex(tmpFile)
		shortName := filepath.Base(filepath.Dir(filepath.Dir(hdr.Name))) + "/" + filepath.Base(hdr.Name)

		// Check parse errors
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

		// Determine if this is a DM-format VDEX (no DEX section)
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

		// Check byte coverage
		if report.Coverage == nil {
			failures = append(failures, fmt.Sprintf("%s: no coverage report", shortName))
			continue
		}

		cov := report.Coverage
		// Allow small alignment gaps (typically 1-3 bytes between sections)
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

		// Check sections are present
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

		// Verify no warnings indicate structural parse failures.
		// For DM-format files (no DEX section), verifier deps extra string
		// warnings are expected because class_def_size is unknown.
		for _, w := range report.Warnings {
			isVerifierWarn := strings.Contains(w, "verifier") || strings.Contains(w, "extra string")
			if isDM && isVerifierWarn {
				continue // expected for DM format
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

	if len(failures) > 0 {
		for i, f := range failures {
			if i >= 50 {
				t.Errorf("  ... and %d more issues", len(failures)-50)
				break
			}
			t.Errorf("  %s", f)
		}
	}

	if totalFiles == 0 {
		t.Error("no VDEX files found in archive")
	}
	if passFiles < totalFiles {
		t.Errorf("only %d/%d files passed without issues", passFiles, totalFiles)
	}
}

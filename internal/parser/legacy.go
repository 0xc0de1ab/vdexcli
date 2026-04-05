package parser

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/dex"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// legacyHeaderSize is the fixed header size for VDEX v021-v026.
const legacyHeaderSize = 28

// dexSectionHeaderSize is the optional DexSectionHeader (v002).
const dexSectionHeaderSize = 12

// IsLegacyVersion returns true for VDEX versions 021-026.
func IsLegacyVersion(version string) bool {
	return version >= model.VdexMinLegacyVersion && version <= model.VdexMaxLegacyVersion
}

// parseLegacyHeader reads the 28-byte VerifierDepsHeader (v021-v026).
func parseLegacyHeader(raw []byte) (model.VdexHeader, legacyFields) {
	h := model.VdexHeader{
		Magic:   string(raw[0:4]),
		Version: string(trimNulls(raw[4:8])),
	}
	lf := legacyFields{
		dexSectionVersion: string(trimNulls(raw[8:12])),
		numDexFiles:       binary.LittleEndian.Uint32(raw[12:16]),
		verifierDepsSize:  binary.LittleEndian.Uint32(raw[16:20]),
		bcpChecksumsSize:  binary.LittleEndian.Uint32(raw[20:24]),
		clcSize:           binary.LittleEndian.Uint32(raw[24:28]),
	}
	return h, lf
}

type legacyFields struct {
	dexSectionVersion string
	numDexFiles       uint32
	verifierDepsSize  uint32
	bcpChecksumsSize  uint32
	clcSize           uint32
}

// ParseVdexLegacy parses a VDEX v021-v026 file.
func ParseVdexLegacy(path string, includeMeanings bool) (*model.VdexReport, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	r := &model.VdexReport{
		File:          filepath.Clean(path),
		Size:          len(raw),
		SchemaVersion: model.VdexSchemaVersion,
	}
	if includeMeanings {
		r.Meanings = NewParserMeanings()
	}

	if len(raw) < legacyHeaderSize {
		d := model.DiagFileTooSmall(len(raw))
		r.AddDiag(d)
		return r, raw, d
	}

	h, lf := parseLegacyHeader(raw)
	r.Header = h
	r.Header.NumSections = 0 // legacy has no section table

	if h.Magic != "vdex" {
		r.AddDiag(model.DiagInvalidMagic(h.Magic))
	}
	if !IsLegacyVersion(h.Version) {
		r.AddDiag(model.DiagVersionMismatch("021-026", h.Version))
	}

	// Build synthetic sections from header fields for consistent reporting.
	cursor := legacyHeaderSize

	// Checksums: numDexFiles * 4 bytes, starting right after header.
	checksumSize := int(lf.numDexFiles) * 4
	if cursor+checksumSize > len(raw) {
		d := model.DiagChecksumExceedsFile()
		r.AddDiag(d)
		return r, raw, d
	}
	r.Sections = append(r.Sections, model.VdexSection{
		Kind: model.SectionChecksum, Offset: uint32(cursor), Size: uint32(checksumSize),
		Name: "kChecksumSection (legacy)", Meaning: "DEX file location checksum list",
	})
	checksums := make([]uint32, lf.numDexFiles)
	for i := uint32(0); i < lf.numDexFiles; i++ {
		checksums[i] = binutil.ReadU32(raw, cursor+int(i)*4)
	}
	r.Checksums = checksums
	cursor += checksumSize

	// Optional DexSectionHeader (dex_section_version == "002").
	var dexSize, dexSharedDataSize, quickeningSize uint32
	if lf.dexSectionVersion == "002" && cursor+dexSectionHeaderSize <= len(raw) {
		dexSize = binary.LittleEndian.Uint32(raw[cursor:])
		dexSharedDataSize = binary.LittleEndian.Uint32(raw[cursor+4:])
		quickeningSize = binary.LittleEndian.Uint32(raw[cursor+8:])
		_ = dexSharedDataSize // not used in current parser
		cursor += dexSectionHeaderSize
	}

	// DEX section.
	if dexSize > 0 {
		dexStart := cursor
		dexEnd := dexStart + int(dexSize)
		if dexEnd > len(raw) {
			r.AddDiag(model.DiagDexSectionRange())
			dexEnd = len(raw)
		}
		r.Sections = append(r.Sections, model.VdexSection{
			Kind: model.SectionDex, Offset: uint32(dexStart), Size: uint32(dexEnd - dexStart),
			Name: "kDexFileSection (legacy)", Meaning: "Concatenated DEX file payload",
		})
		dexContexts, dexDiags := dex.ParseSection(raw, model.VdexSection{
			Offset: uint32(dexStart), Size: uint32(dexEnd - dexStart),
		}, int(lf.numDexFiles))
		r.AddDiags(dexDiags)
		for _, d := range dexContexts {
			rep := d.Rep
			if rep.Index < len(checksums) {
				rep.Checksum = checksums[rep.Index]
			}
			r.Dexes = append(r.Dexes, rep)
		}
		cursor = dexEnd
	}

	// Verifier deps section.
	if lf.verifierDepsSize > 0 {
		vStart := cursor
		vEnd := vStart + int(lf.verifierDepsSize)
		if vEnd > len(raw) {
			r.AddDiag(model.DiagVerifierSectionRange())
			vEnd = len(raw)
		}
		r.Sections = append(r.Sections, model.VdexSection{
			Kind: model.SectionVerifierDeps, Offset: uint32(vStart), Size: uint32(vEnd - vStart),
			Name: "kVerifierDepsSection (legacy)", Meaning: "Verifier dependency section",
		})
		cursor = vEnd
	}

	// Quickening info (skip, not parsed).
	if quickeningSize > 0 {
		cursor += int(quickeningSize)
	}

	// Boot classpath checksums (skip).
	if lf.bcpChecksumsSize > 0 {
		cursor += int(lf.bcpChecksumsSize)
	}

	// Class loader context (skip).
	if lf.clcSize > 0 {
		cursor += int(lf.clcSize)
	}
	_ = cursor

	r.AddDiag(model.ParseDiagnostic{
		Severity: model.SeverityWarning,
		Category: model.CatHeader,
		Code:     model.WarnVersionMismatch,
		Message:  fmt.Sprintf("VDEX v%s: legacy format parsed with limited support (no type-lookup, quickening skipped)", h.Version),
		Hint:     "verifier deps and DEX extraction work; type lookup tables are not available in this format",
	})

	r.Coverage = ComputeByteCoverage(len(raw), r.Header, r.Sections, r.Dexes)

	if len(r.Errors) > 0 {
		return r, raw, fmt.Errorf("parse: %d error(s): %s", len(r.Errors), r.Errors[0])
	}
	return r, raw, nil
}

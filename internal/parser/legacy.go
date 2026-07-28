package parser

import (
	"encoding/binary"
	"fmt"

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
	switch version {
	case "021", "022", "023", "024", "025", "026":
		return true
	default:
		return false
	}
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

// ParseVdexLegacyBytes parses a VDEX v021-v026 file from raw bytes.
// This is the primary entry point and is compatible with all build targets including WASM.
func ParseVdexLegacyBytes(data []byte, includeMeanings bool) (*model.VdexReport, []byte, error) {
	raw := data

	r := &model.VdexReport{
		File:          "",
		Size:          len(raw),
		SchemaVersion: model.VdexSchemaVersion,
		ContentHash:   contentHash(raw),
	}
	if includeMeanings {
		r.Meanings = NewParserMeanings()
	}

	if len(raw) < legacyHeaderSize {
		d := model.DiagFileTooSmall(len(raw))
		r.AddDiag(d)
		return r, raw, d
	}
	if uint64(len(raw)) > uint64(^uint32(0)) {
		d := model.ParseDiagnostic{
			Severity: model.SeverityError,
			Category: model.CatHeader,
			Code:     model.ErrSectionTableTrunc,
			Message:  fmt.Sprintf("legacy VDEX exceeds uint32 file size limit: %d bytes", len(raw)),
			Hint:     "VDEX offsets and sizes are 32-bit values",
		}
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
	advance := func(size uint32, label string) bool {
		end64 := uint64(cursor) + uint64(size)
		if end64 > uint64(len(raw)) {
			r.AddDiag(model.ParseDiagnostic{
				Severity: model.SeverityError,
				Category: model.CatSection,
				Code:     model.ErrSectionTableTrunc,
				Message:  fmt.Sprintf("legacy %s exceeds file boundary", label),
				Hint:     "the legacy VDEX is truncated or its size fields are corrupt",
			})
			cursor = len(raw)
			return false
		}
		cursor = int(end64)
		return true
	}

	// Checksums: numDexFiles * 4 bytes, starting right after header.
	checksumSize64 := uint64(lf.numDexFiles) * 4
	if uint64(cursor)+checksumSize64 > uint64(len(raw)) {
		d := model.DiagChecksumExceedsFile()
		r.AddDiag(d)
		return r, raw, d
	}
	checksumSize := int(checksumSize64)
	r.Sections = append(r.Sections, model.VdexSection{
		Kind: model.SectionChecksum, Offset: uint32(cursor), Size: uint32(checksumSize),
		Name: "kChecksumSection (legacy)", Meaning: "DEX file location checksum list",
	})
	checksumCount := int(lf.numDexFiles)
	checksums := make([]uint32, checksumCount)
	for i := 0; i < checksumCount; i++ {
		checksums[i] = binutil.ReadU32(raw, cursor+i*4)
	}
	r.Checksums = checksums
	cursor += checksumSize

	// Optional DexSectionHeader (dex_section_version == "002").
	var dexSize, dexSharedDataSize, quickeningSize uint32
	if lf.dexSectionVersion == "002" {
		if uint64(cursor)+dexSectionHeaderSize > uint64(len(raw)) {
			d := model.ParseDiagnostic{
				Severity: model.SeverityError,
				Category: model.CatDex,
				Code:     model.ErrDexTooShort,
				Message:  "legacy DexSectionHeader is truncated",
				Hint:     "the legacy VDEX ends before its 12-byte DexSectionHeader",
			}
			r.AddDiag(d)
			return r, raw, d
		}
		dexSize = binary.LittleEndian.Uint32(raw[cursor:])
		dexSharedDataSize = binary.LittleEndian.Uint32(raw[cursor+4:])
		quickeningSize = binary.LittleEndian.Uint32(raw[cursor+8:])
		cursor += dexSectionHeaderSize
	}

	// DEX section.
	if dexSize > 0 {
		dexStart := cursor
		dexEnd64 := uint64(dexStart) + uint64(dexSize)
		dexEnd := len(raw)
		if dexEnd64 > uint64(len(raw)) {
			r.AddDiag(model.DiagDexSectionRange())
		} else {
			dexEnd = int(dexEnd64)
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
	if !advance(dexSharedDataSize, "DEX shared-data section") {
		return r, raw, r.Diagnostics[len(r.Diagnostics)-1]
	}

	// Verifier deps section.
	if lf.verifierDepsSize > 0 {
		vStart := cursor
		if !advance(lf.verifierDepsSize, "verifier-deps section") {
			return r, raw, r.Diagnostics[len(r.Diagnostics)-1]
		}
		vEnd := cursor
		r.Sections = append(r.Sections, model.VdexSection{
			Kind: model.SectionVerifierDeps, Offset: uint32(vStart), Size: uint32(vEnd - vStart),
			Name: "kVerifierDepsSection (legacy)", Meaning: "Verifier dependency section",
		})
	}

	// Quickening info (skip, not parsed).
	if !advance(quickeningSize, "quickening-info section") {
		return r, raw, r.Diagnostics[len(r.Diagnostics)-1]
	}

	// Boot classpath checksums (skip).
	if !advance(lf.bcpChecksumsSize, "boot-classpath checksum data") {
		return r, raw, r.Diagnostics[len(r.Diagnostics)-1]
	}

	// Class loader context (skip).
	if !advance(lf.clcSize, "class-loader context data") {
		return r, raw, r.Diagnostics[len(r.Diagnostics)-1]
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

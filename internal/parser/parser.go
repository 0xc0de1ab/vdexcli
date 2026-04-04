// Package parser implements VDEX v027 file parsing.
//
// ParseVdex is the top-level entry point. It reads the file, parses
// header/sections/checksums, then delegates to section-specific parsers
// (dex, verifier-deps, type-lookup) and computes byte-level coverage.
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

// ParseVdex reads a VDEX file and returns a structured report.
// When includeMeanings is true the report includes human-readable field descriptions.
func ParseVdex(path string, includeMeanings bool) (*model.VdexReport, []byte, error) {
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

	if len(raw) < 12 {
		d := model.DiagFileTooSmall(len(raw))
		r.Errors = append(r.Errors, d.Message)
		return r, raw, d
	}

	r.Header = parseHeader(raw)
	if r.Header.Magic != "vdex" {
		d := model.DiagInvalidMagic(r.Header.Magic)
		r.Errors = append(r.Errors, d.Message)
	}
	if r.Header.Version != model.VdexCurrentVersion {
		d := model.DiagVersionMismatch(model.VdexCurrentVersion, r.Header.Version)
		r.Warnings = append(r.Warnings, d.Message)
	}

	headerEnd := int(12 + r.Header.NumSections*12)
	if len(raw) < headerEnd {
		d := model.DiagSectionTableTruncated(headerEnd, len(raw))
		r.Errors = append(r.Errors, d.Message)
		return r, raw, d
	}

	sections, secIndex, err := ParseSections(raw[12:headerEnd], r.Header.NumSections)
	if err != nil {
		r.Warnings = append(r.Warnings, err.Error())
	}
	r.Sections = sections
	r.Warnings = append(r.Warnings, ValidateSections(len(raw), sections)...)

	r.Checksums = parseChecksums(raw, sections, secIndex, r)

	var dexContexts []*model.DexContext
	if idx, ok := secIndex[model.SectionDex]; ok {
		var dexWarnings []string
		dexContexts, dexWarnings = dex.ParseSection(raw, sections[idx], len(r.Checksums))
		r.Warnings = append(r.Warnings, dexWarnings...)
	}
	for _, d := range dexContexts {
		rep := d.Rep
		if rep.Index < len(r.Checksums) {
			rep.Checksum = r.Checksums[rep.Index]
		}
		r.Dexes = append(r.Dexes, rep)
	}

	if len(r.Checksums) == 0 {
		d := model.DiagNoChecksumSection()
		r.Warnings = append(r.Warnings, d.Message)
	}

	expected := len(r.Checksums)
	if expected == 0 {
		expected = len(dexContexts)
	}
	if idx, ok := secIndex[model.SectionVerifierDeps]; ok {
		rep, ws := ParseVerifierSection(raw, sections[idx], dexContexts, expected)
		r.Verifier = rep
		r.Warnings = append(r.Warnings, ws...)
	}
	if idx, ok := secIndex[model.SectionTypeLookup]; ok {
		rep, ws := ParseTypeLookupSection(raw, sections[idx], dexContexts, expected)
		r.TypeLookup = rep
		r.Warnings = append(r.Warnings, ws...)
	}

	r.Coverage = ComputeByteCoverage(len(raw), r.Header, r.Sections, r.Dexes)

	if len(r.Errors) > 0 {
		return r, raw, fmt.Errorf("parse: %d error(s): %s", len(r.Errors), r.Errors[0])
	}
	return r, raw, nil
}

func parseHeader(raw []byte) model.VdexHeader {
	return model.VdexHeader{
		Magic:       string(raw[0:4]),
		Version:     string(trimNulls(raw[4:8])),
		NumSections: binary.LittleEndian.Uint32(raw[8:12]),
	}
}

func trimNulls(b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			return b[:i+1]
		}
	}
	return b[:0]
}

func parseChecksums(raw []byte, sections []model.VdexSection, secIndex map[uint32]int, r *model.VdexReport) []uint32 {
	idx, ok := secIndex[model.SectionChecksum]
	if !ok {
		return nil
	}
	s := sections[idx]
	if s.Offset+s.Size > uint32(len(raw)) {
		d := model.DiagChecksumExceedsFile()
		r.Errors = append(r.Errors, d.Message)
		return nil
	}
	if s.Size%4 != 0 {
		d := model.DiagChecksumAlignment()
		r.Warnings = append(r.Warnings, d.Message)
	}
	count := int(s.Size) / 4
	out := make([]uint32, count)
	for i := 0; i < count; i++ {
		o := int(s.Offset) + i*4
		out[i] = binutil.ReadU32(raw, o)
	}
	return out
}

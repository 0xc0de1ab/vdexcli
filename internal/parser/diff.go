package parser

import (
	"reflect"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// Diff compares two parsed VDEX reports and returns a structured diff.
func Diff(a, b *model.VdexReport) model.VdexDiff {
	d := model.VdexDiff{
		FileA: a.File, FileB: b.File,
		SizeA: a.Size, SizeB: b.Size,
		ContentChanged: reportsContentChanged(a, b),
	}

	d.HeaderDiff, d.HeaderChanged = diffHeaders(a.Header, b.Header)
	d.SectionDiffs = diffSections(a.Sections, b.Sections)
	d.ChecksumDiff = diffChecksums(a.Checksums, b.Checksums)
	d.DexDiffs = diffDexFiles(a.Dexes, b.Dexes)
	d.VerifierDiff = diffVerifier(a.Verifier, b.Verifier)
	d.TypeLookupDiff = diffTypeLookup(a.TypeLookup, b.TypeLookup)
	d.Summary = buildSummary(d)

	return d
}

func diffHeaders(a, b model.VdexHeader) (*model.HeaderDiff, bool) {
	if a.Magic == b.Magic && a.Version == b.Version && a.NumSections == b.NumSections {
		return nil, false
	}
	h := &model.HeaderDiff{}
	if a.Magic != b.Magic {
		h.MagicA = a.Magic
		h.MagicB = b.Magic
	}
	if a.Version != b.Version {
		h.VersionA = a.Version
		h.VersionB = b.Version
	}
	if a.NumSections != b.NumSections {
		h.NumSectionsA = a.NumSections
		h.NumSectionsB = b.NumSections
	}
	return h, true
}

func diffSections(a, b []model.VdexSection) []model.SectionDiff {
	m := map[uint32]model.VdexSection{}
	for _, s := range a {
		m[s.Kind] = s
	}
	var diffs []model.SectionDiff
	seen := map[uint32]bool{}
	for _, sb := range b {
		sa := m[sb.Kind]
		seen[sb.Kind] = true
		if sa.Offset != sb.Offset || sa.Size != sb.Size {
			diffs = append(diffs, model.SectionDiff{
				Kind: sb.Kind, Name: sb.Name,
				OffsetA: sa.Offset, OffsetB: sb.Offset,
				SizeA: sa.Size, SizeB: sb.Size,
				SizeDelta: int(sb.Size) - int(sa.Size),
			})
		}
	}
	for _, sa := range a {
		if !seen[sa.Kind] {
			diffs = append(diffs, model.SectionDiff{
				Kind: sa.Kind, Name: sa.Name,
				OffsetA: sa.Offset, SizeA: sa.Size,
				SizeDelta: -int(sa.Size),
			})
		}
	}
	return diffs
}

func diffChecksums(a, b []uint32) *model.ChecksumDiff {
	d := &model.ChecksumDiff{CountA: len(a), CountB: len(b)}
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			d.Changed = append(d.Changed, i)
		}
	}
	if len(b) > len(a) {
		d.AddedB = len(b) - len(a)
	}
	if len(a) > len(b) {
		d.RemovedA = len(a) - len(b)
	}
	if len(d.Changed) == 0 && d.AddedB == 0 && d.RemovedA == 0 {
		return nil
	}
	return d
}

func diffDexFiles(a, b []model.DexReport) []model.DexFileDiff {
	var diffs []model.DexFileDiff
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		dd := model.DexFileDiff{Index: i}
		switch {
		case i >= len(a):
			dd.Status = "added"
			dd.ChecksumB = b[i].ChecksumId
			dd.ClassDefsB = b[i].ClassDefs
			dd.SignatureB = b[i].Signature
		case i >= len(b):
			dd.Status = "removed"
			dd.ChecksumA = a[i].ChecksumId
			dd.ClassDefsA = a[i].ClassDefs
			dd.SignatureA = a[i].Signature
		default:
			da, db := a[i], b[i]
			dd.ChecksumA = da.ChecksumId
			dd.ChecksumB = db.ChecksumId
			dd.ClassDefsA = da.ClassDefs
			dd.ClassDefsB = db.ClassDefs
			dd.SignatureA = da.Signature
			dd.SignatureB = db.Signature
			if da.ChecksumId == db.ChecksumId && da.Signature == db.Signature && da.ClassDefs == db.ClassDefs {
				dd.Status = "unchanged"
			} else {
				dd.Status = "modified"
			}
		}
		if dd.Status != "unchanged" {
			diffs = append(diffs, dd)
		}
	}
	return diffs
}

func diffVerifier(a, b *model.VerifierReport) *model.VerifierDiffInfo {
	if a == nil && b == nil {
		return nil
	}
	ad := safeVerifierDexes(a)
	bd := safeVerifierDexes(b)
	contentChanged := safeVerifierHash(a) != safeVerifierHash(b)
	maxLen := len(ad)
	if len(bd) > maxLen {
		maxLen = len(bd)
	}
	if maxLen == 0 && !contentChanged {
		return nil
	}

	info := &model.VerifierDiffInfo{DexCount: maxLen, ContentChanged: contentChanged}
	for i := 0; i < maxLen; i++ {
		va := safeVerifierDexReport(ad, i)
		vb := safeVerifierDexReport(bd, i)
		dd := model.VerifierDexDiff{
			DexIndex:  i,
			VerifiedA: va.VerifiedClasses, VerifiedB: vb.VerifiedClasses,
			UnverifiedA: va.UnverifiedClasses, UnverifiedB: vb.UnverifiedClasses,
			PairsA: va.AssignabilityPairs, PairsB: vb.AssignabilityPairs,
			ExtraStringsA: va.ExtraStringCount, ExtraStringsB: vb.ExtraStringCount,
			VerifiedDelta:  vb.VerifiedClasses - va.VerifiedClasses,
			PairsDelta:     vb.AssignabilityPairs - va.AssignabilityPairs,
			ContentChanged: !reflect.DeepEqual(va.FirstPairs, vb.FirstPairs),
		}
		if dd.VerifiedDelta != 0 || dd.PairsDelta != 0 ||
			va.UnverifiedClasses != vb.UnverifiedClasses ||
			va.ExtraStringCount != vb.ExtraStringCount || dd.ContentChanged {
			info.DexDiffs = append(info.DexDiffs, dd)
			changed := abs(dd.VerifiedDelta)
			if changed == 0 {
				changed = 1
			}
			info.TotalChanged += changed
		}
	}
	if contentChanged && info.TotalChanged == 0 {
		info.TotalChanged = 1
	}
	if len(info.DexDiffs) == 0 && !contentChanged {
		return nil
	}
	return info
}

func diffTypeLookup(a, b *model.TypeLookupReport) *model.TypeLookupDiffInfo {
	if a == nil && b == nil {
		return nil
	}
	ad := safeTypeLookupDexes(a)
	bd := safeTypeLookupDexes(b)
	contentChanged := safeTypeLookupHash(a) != safeTypeLookupHash(b)
	maxLen := len(ad)
	if len(bd) > maxLen {
		maxLen = len(bd)
	}
	if maxLen == 0 && !contentChanged {
		return nil
	}

	info := &model.TypeLookupDiffInfo{DexCount: maxLen, ContentChanged: contentChanged}
	for i := 0; i < maxLen; i++ {
		ta := safeTypeLookupDexReport(ad, i)
		tb := safeTypeLookupDexReport(bd, i)
		dd := model.TypeLookupDexDiff{
			DexIndex: i,
			BucketsA: ta.BucketCount, BucketsB: tb.BucketCount,
			EntriesA: ta.EntryCount, EntriesB: tb.EntryCount,
			EntriesDelta:   tb.EntryCount - ta.EntryCount,
			ContentChanged: !reflect.DeepEqual(ta, tb),
		}
		if dd.EntriesDelta != 0 || ta.BucketCount != tb.BucketCount || dd.ContentChanged {
			info.DexDiffs = append(info.DexDiffs, dd)
		}
	}
	if len(info.DexDiffs) == 0 && !contentChanged {
		return nil
	}
	return info
}

func buildSummary(d model.VdexDiff) model.DiffSummary {
	s := model.DiffSummary{
		SectionsChanged: len(d.SectionDiffs),
		DexFilesChanged: len(d.DexDiffs),
	}
	if d.ChecksumDiff != nil {
		s.ChecksumsChanged = len(d.ChecksumDiff.Changed) + d.ChecksumDiff.AddedB + d.ChecksumDiff.RemovedA
	}
	if d.VerifierDiff != nil {
		s.VerifierChanged = d.VerifierDiff.TotalChanged
	}
	if d.TypeLookupDiff != nil {
		for _, dd := range d.TypeLookupDiff.DexDiffs {
			changed := abs(dd.EntriesDelta)
			if changed == 0 {
				changed = 1
			}
			s.TypeLookupChanged += changed
		}
		if d.TypeLookupDiff.ContentChanged && s.TypeLookupChanged == 0 {
			s.TypeLookupChanged = 1
		}
	}
	s.Identical = !d.HeaderChanged && s.SectionsChanged == 0 && s.ChecksumsChanged == 0 &&
		s.DexFilesChanged == 0 && s.VerifierChanged == 0 && s.TypeLookupChanged == 0 &&
		d.SizeA == d.SizeB && !d.ContentChanged
	return s
}

func reportsContentChanged(a, b *model.VdexReport) bool {
	if a.ContentHash == "" && b.ContentHash == "" {
		return false
	}
	return a.ContentHash != b.ContentHash
}

func safeVerifierDexes(r *model.VerifierReport) []model.VerifierDexReport {
	if r == nil {
		return nil
	}
	return r.Dexes
}

func safeVerifierHash(r *model.VerifierReport) string {
	if r == nil {
		return ""
	}
	return r.ContentHash
}

func safeVerifierDexReport(dexes []model.VerifierDexReport, i int) model.VerifierDexReport {
	if i < len(dexes) {
		return dexes[i]
	}
	return model.VerifierDexReport{}
}

func safeTypeLookupDexes(r *model.TypeLookupReport) []model.TypeLookupDexReport {
	if r == nil {
		return nil
	}
	return r.Dexes
}

func safeTypeLookupHash(r *model.TypeLookupReport) string {
	if r == nil {
		return ""
	}
	return r.ContentHash
}

func safeTypeLookupDexReport(dexes []model.TypeLookupDexReport, i int) model.TypeLookupDexReport {
	if i < len(dexes) {
		return dexes[i]
	}
	return model.TypeLookupDexReport{}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

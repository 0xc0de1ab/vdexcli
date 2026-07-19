package presenter

import (
	"fmt"
	"io"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// WriteDiffText writes a human-readable diff report to w.
func WriteDiffText(w io.Writer, d model.VdexDiff) error {
	out := outputWriter{dst: w}
	if d.Summary.Identical {
		out.printf("%s\n", c(boldGrn, "identical"))
		out.printf("  %s (%d bytes) == %s (%d bytes)\n", d.FileA, d.SizeA, d.FileB, d.SizeB)
		return out.err
	}

	out.printf("%s\n", c(bold, "VDEX diff"))
	out.printf("  A: %s (%d bytes)\n", d.FileA, d.SizeA)
	out.printf("  B: %s (%d bytes)\n", d.FileB, d.SizeB)
	if d.SizeA != d.SizeB {
		out.printf("  size delta: %s\n", c(yellow, fmt.Sprintf("%+d bytes", d.SizeB-d.SizeA)))
	}
	if d.ContentChanged && !d.HeaderChanged && len(d.SectionDiffs) == 0 && d.ChecksumDiff == nil &&
		len(d.DexDiffs) == 0 && d.VerifierDiff == nil && d.TypeLookupDiff == nil {
		out.println("  file content changed outside parsed structures")
	}
	out.println()

	if d.HeaderChanged && d.HeaderDiff != nil {
		out.printf("%s\n", c(bold, "header:"))
		h := d.HeaderDiff
		if h.MagicA != "" {
			out.printf("  magic: %s → %s\n", c(red, h.MagicA), c(green, h.MagicB))
		}
		if h.VersionA != "" {
			out.printf("  version: %s → %s\n", c(red, h.VersionA), c(green, h.VersionB))
		}
		if h.NumSectionsA != h.NumSectionsB {
			out.printf("  sections: %d → %d\n", h.NumSectionsA, h.NumSectionsB)
		}
		out.println()
	}

	if len(d.SectionDiffs) > 0 {
		out.printf("%s\n", c(bold, "sections:"))
		for _, s := range d.SectionDiffs {
			delta := fmt.Sprintf("%+d", s.SizeDelta)
			if s.SizeDelta > 0 {
				delta = c(green, delta)
			} else if s.SizeDelta < 0 {
				delta = c(red, delta)
			}
			out.printf("  %-28s  size %d → %d (%s)\n", s.Name, s.SizeA, s.SizeB, delta)
		}
		out.println()
	}

	if d.ChecksumDiff != nil {
		cd := d.ChecksumDiff
		out.printf("%s count %d → %d\n", c(bold, "checksums:"), cd.CountA, cd.CountB)
		if len(cd.Changed) > 0 {
			out.printf("  changed indices: %s\n", c(yellow, fmt.Sprint(cd.Changed)))
		}
		if cd.AddedB > 0 {
			out.printf("  added in B: %s\n", c(green, fmt.Sprintf("+%d", cd.AddedB)))
		}
		if cd.RemovedA > 0 {
			out.printf("  removed from A: %s\n", c(red, fmt.Sprintf("-%d", cd.RemovedA)))
		}
		out.println()
	}

	if len(d.DexDiffs) > 0 {
		out.printf("%s\n", c(bold, "dex files:"))
		for _, dd := range d.DexDiffs {
			switch dd.Status {
			case "added":
				out.printf("  [%d] %s  checksum=%#x classes=%d\n", dd.Index, c(green, "added"), dd.ChecksumB, dd.ClassDefsB)
			case "removed":
				out.printf("  [%d] %s  checksum=%#x classes=%d\n", dd.Index, c(red, "removed"), dd.ChecksumA, dd.ClassDefsA)
			case "modified":
				out.printf("  [%d] %s  checksum %#x→%#x  classes %d→%d\n",
					dd.Index, c(yellow, "modified"), dd.ChecksumA, dd.ChecksumB, dd.ClassDefsA, dd.ClassDefsB)
			}
		}
		out.println()
	}

	if d.VerifierDiff != nil {
		out.printf("%s (%d classes changed)\n", c(bold, "verifier_deps:"), d.VerifierDiff.TotalChanged)
		for _, vd := range d.VerifierDiff.DexDiffs {
			out.printf("  [dex %d] verified %d→%d (%s)  pairs %d→%d (%s)  extras %d→%d\n",
				vd.DexIndex,
				vd.VerifiedA, vd.VerifiedB, colorDelta(vd.VerifiedDelta),
				vd.PairsA, vd.PairsB, colorDelta(vd.PairsDelta),
				vd.ExtraStringsA, vd.ExtraStringsB)
		}
		if d.VerifierDiff.ContentChanged && len(d.VerifierDiff.DexDiffs) == 0 {
			out.println("  section content changed")
		}
		out.println()
	}

	if d.TypeLookupDiff != nil {
		out.printf("%s\n", c(bold, "type_lookup:"))
		for _, td := range d.TypeLookupDiff.DexDiffs {
			out.printf("  [dex %d] buckets %d→%d  entries %d→%d (%s)\n",
				td.DexIndex,
				td.BucketsA, td.BucketsB,
				td.EntriesA, td.EntriesB, colorDelta(td.EntriesDelta))
		}
		if d.TypeLookupDiff.ContentChanged && len(d.TypeLookupDiff.DexDiffs) == 0 {
			out.println("  section content changed")
		}
		out.println()
	}

	out.printf("%s sections=%d checksums=%d dexes=%d verifier=%d typelookup=%d\n",
		c(bold, "summary:"),
		d.Summary.SectionsChanged, d.Summary.ChecksumsChanged,
		d.Summary.DexFilesChanged, d.Summary.VerifierChanged,
		d.Summary.TypeLookupChanged)
	return out.err
}

func colorDelta(v int) string {
	s := fmt.Sprintf("%+d", v)
	if v > 0 {
		return c(green, s)
	} else if v < 0 {
		return c(red, s)
	}
	return c(dim, s)
}

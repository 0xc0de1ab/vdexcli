package presenter

import (
	"fmt"
	"io"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// WriteDiffText writes a human-readable diff report to w.
func WriteDiffText(w io.Writer, d model.VdexDiff) {
	if d.Summary.Identical {
		fmt.Fprintf(w, "%s\n", c(boldGrn, "identical"))
		fmt.Fprintf(w, "  %s (%d bytes) == %s (%d bytes)\n", d.FileA, d.SizeA, d.FileB, d.SizeB)
		return
	}

	fmt.Fprintf(w, "%s\n", c(bold, "VDEX diff"))
	fmt.Fprintf(w, "  A: %s (%d bytes)\n", d.FileA, d.SizeA)
	fmt.Fprintf(w, "  B: %s (%d bytes)\n", d.FileB, d.SizeB)
	if d.SizeA != d.SizeB {
		fmt.Fprintf(w, "  size delta: %s\n", c(yellow, fmt.Sprintf("%+d bytes", d.SizeB-d.SizeA)))
	}
	fmt.Fprintln(w)

	if d.HeaderChanged && d.HeaderDiff != nil {
		fmt.Fprintf(w, "%s\n", c(bold, "header:"))
		h := d.HeaderDiff
		if h.MagicA != "" {
			fmt.Fprintf(w, "  magic: %s → %s\n", c(red, h.MagicA), c(green, h.MagicB))
		}
		if h.VersionA != "" {
			fmt.Fprintf(w, "  version: %s → %s\n", c(red, h.VersionA), c(green, h.VersionB))
		}
		fmt.Fprintln(w)
	}

	if len(d.SectionDiffs) > 0 {
		fmt.Fprintf(w, "%s\n", c(bold, "sections:"))
		for _, s := range d.SectionDiffs {
			delta := fmt.Sprintf("%+d", s.SizeDelta)
			if s.SizeDelta > 0 {
				delta = c(green, delta)
			} else if s.SizeDelta < 0 {
				delta = c(red, delta)
			}
			fmt.Fprintf(w, "  %-28s  size %d → %d (%s)\n", s.Name, s.SizeA, s.SizeB, delta)
		}
		fmt.Fprintln(w)
	}

	if d.ChecksumDiff != nil {
		cd := d.ChecksumDiff
		fmt.Fprintf(w, "%s count %d → %d\n", c(bold, "checksums:"), cd.CountA, cd.CountB)
		if len(cd.Changed) > 0 {
			fmt.Fprintf(w, "  changed indices: %s\n", c(yellow, fmt.Sprint(cd.Changed)))
		}
		if cd.AddedB > 0 {
			fmt.Fprintf(w, "  added in B: %s\n", c(green, fmt.Sprintf("+%d", cd.AddedB)))
		}
		if cd.RemovedA > 0 {
			fmt.Fprintf(w, "  removed from A: %s\n", c(red, fmt.Sprintf("-%d", cd.RemovedA)))
		}
		fmt.Fprintln(w)
	}

	if len(d.DexDiffs) > 0 {
		fmt.Fprintf(w, "%s\n", c(bold, "dex files:"))
		for _, dd := range d.DexDiffs {
			switch dd.Status {
			case "added":
				fmt.Fprintf(w, "  [%d] %s  checksum=%#x classes=%d\n", dd.Index, c(green, "added"), dd.ChecksumB, dd.ClassDefsB)
			case "removed":
				fmt.Fprintf(w, "  [%d] %s  checksum=%#x classes=%d\n", dd.Index, c(red, "removed"), dd.ChecksumA, dd.ClassDefsA)
			case "modified":
				fmt.Fprintf(w, "  [%d] %s  checksum %#x→%#x  classes %d→%d\n",
					dd.Index, c(yellow, "modified"), dd.ChecksumA, dd.ChecksumB, dd.ClassDefsA, dd.ClassDefsB)
			}
		}
		fmt.Fprintln(w)
	}

	if d.VerifierDiff != nil {
		fmt.Fprintf(w, "%s (%d classes changed)\n", c(bold, "verifier_deps:"), d.VerifierDiff.TotalChanged)
		for _, vd := range d.VerifierDiff.DexDiffs {
			fmt.Fprintf(w, "  [dex %d] verified %d→%d (%s)  pairs %d→%d (%s)  extras %d→%d\n",
				vd.DexIndex,
				vd.VerifiedA, vd.VerifiedB, colorDelta(vd.VerifiedDelta),
				vd.PairsA, vd.PairsB, colorDelta(vd.PairsDelta),
				vd.ExtraStringsA, vd.ExtraStringsB)
		}
		fmt.Fprintln(w)
	}

	if d.TypeLookupDiff != nil {
		fmt.Fprintf(w, "%s\n", c(bold, "type_lookup:"))
		for _, td := range d.TypeLookupDiff.DexDiffs {
			fmt.Fprintf(w, "  [dex %d] buckets %d→%d  entries %d→%d (%s)\n",
				td.DexIndex,
				td.BucketsA, td.BucketsB,
				td.EntriesA, td.EntriesB, colorDelta(td.EntriesDelta))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s sections=%d checksums=%d dexes=%d verifier=%d typelookup=%d\n",
		c(bold, "summary:"),
		d.Summary.SectionsChanged, d.Summary.ChecksumsChanged,
		d.Summary.DexFilesChanged, d.Summary.VerifierChanged,
		d.Summary.TypeLookupChanged)
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

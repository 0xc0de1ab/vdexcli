package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/0xc0de1ab/vdexcli/internal/modifier"
	"github.com/0xc0de1ab/vdexcli/internal/parser"
	"github.com/0xc0de1ab/vdexcli/internal/presenter"
)

var (
	flagVerifierJSON string
	flagModifyMode   string
	flagDryRun       bool
	flagVerify       bool
	flagQuiet        bool
	flagForce        bool
	flagLogFile      string
)

var modifyCmd = &cobra.Command{
	Use:   "modify [flags] <input.vdex> <output.vdex>",
	Short: "Modify the verifier-deps section using a JSON patch",
	Long: `Apply a JSON patch to the kVerifierDepsSection of a VDEX file.

In "replace" mode (default) the entire verifier section is rebuilt from the patch.
In "merge" mode the patch is overlaid onto the existing verifier data —
only specified classes are overwritten and extra_strings are appended.

The output file is written atomically (temp file + rename).`,
	Example: `  vdexcli modify --verifier-json patch.json input.vdex output.vdex
  vdexcli modify --mode merge --verifier-json patch.json in.vdex out.vdex
  vdexcli modify --dry-run --json --verifier-json patch.json in.vdex out.vdex
  cat patch.json | vdexcli modify --verifier-json - in.vdex out.vdex
  vdexcli modify --log-file modify.log --verifier-json patch.json in.vdex out.vdex`,
	Args: cobra.ExactArgs(2),
	PreRunE: func(_ *cobra.Command, args []string) error {
		if flagVerify {
			flagDryRun = true
		}
		if strings.TrimSpace(flagVerifierJSON) == "" {
			return fmt.Errorf("--verifier-json is required")
		}
		mode := strings.ToLower(strings.TrimSpace(flagModifyMode))
		if mode != "replace" && mode != "merge" {
			return fmt.Errorf("unsupported --mode %q; supported: replace, merge", flagModifyMode)
		}
		flagModifyMode = mode
		return validateOutputPath(args)
	},
	RunE: runModify,
}

func init() {
	f := modifyCmd.Flags()
	f.StringVar(&flagVerifierJSON, "verifier-json", "", "path to verifier patch JSON (use - for stdin)")
	f.StringVar(&flagModifyMode, "mode", "replace", "patch mode: replace|merge")
	f.BoolVar(&flagDryRun, "dry-run", false, "validate and report changes without writing")
	f.BoolVar(&flagVerify, "verify", false, "alias for --dry-run")
	f.BoolVar(&flagQuiet, "quiet", false, "suppress text-mode summary output")
	f.BoolVar(&flagForce, "force", false, "allow output path equal to input path")
	f.StringVar(&flagLogFile, "log-file", "", "append result as NDJSON to file")
}

func validateOutputPath(args []string) error {
	if flagVerify || flagDryRun {
		return nil
	}
	inAbs, err1 := filepath.Abs(args[0])
	outAbs, err2 := filepath.Abs(args[1])
	if err1 != nil || err2 != nil {
		inAbs = filepath.Clean(args[0])
		outAbs = filepath.Clean(args[1])
	}
	if !flagForce && inAbs == outAbs {
		return fmt.Errorf("output path equals input path; add --force to allow in-place overwrite")
	}
	return nil
}

func runModify(_ *cobra.Command, args []string) error {
	inPath, outPath := args[0], args[1]

	// 1. Parse input VDEX
	report, raw, err := parser.ParseVdex(inPath, flagMeanings)
	parseErr := err
	if err != nil && report == nil {
		return err
	}
	if report == nil {
		return fmt.Errorf("no parse result for %s", inPath)
	}
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	}

	// 2. Load and validate patch
	patch, patchWarn, err := modifier.ParseVerifierPatch(flagVerifierJSON)
	if err != nil {
		return fmt.Errorf("load verifier patch %q: %w", flagVerifierJSON, err)
	}
	report.Warnings = append(report.Warnings, patchWarn...)

	if patch.Mode == "" {
		patch.Mode = flagModifyMode
	} else if patch.Mode != flagModifyMode {
		return fmt.Errorf("patch mode %q conflicts with --mode %q", patch.Mode, flagModifyMode)
	}

	patchStats := countPatchStats(patch)

	// 3. Find verifier section
	section, err := findVerifierSection(report, raw)
	if err != nil {
		return err
	}

	// 4. Build new verifier payload
	newPayload, buildWarn, err := buildPayload(report, raw, section, patch)
	report.Warnings = append(report.Warnings, buildWarn...)
	if err != nil {
		return err
	}
	if len(newPayload) > int(section.Size) {
		return fmt.Errorf("verifier payload too large: %d bytes > section size %d", len(newPayload), section.Size)
	}

	// 5. Compare old vs new
	diff, dexDiffs, diffWarn, compareErr := modifier.CompareVerifierSectionDiff(raw, section, report.Dexes, report.Checksums, newPayload)
	report.Warnings = append(report.Warnings, diffWarn...)

	// 6. Build summary
	summary := buildModifySummary(inPath, outPath, patch, patchStats, report, section, newPayload, diff, dexDiffs, parseErr, compareErr)

	// 7. Apply strict
	strictMatched := applyStrictModify(report, &summary)

	// 8. Write output
	writeErr := writeOutput(raw, section, newPayload, outPath, &summary)

	// 9. Compute failure info
	failureReason := modifier.MakeFailureReason(summary, parseErr, compareErr, writeErr, strictMatched)
	failureCategory := modifier.MakeFailureCategory(summary, parseErr, compareErr, writeErr, strictMatched)
	summary.FailureCategory = failureCategory
	if failureCategory != "" {
		summary.FailureCategoryCounts[failureCategory]++
	}
	if failureReason != "" && !lo.Contains(summary.Errors, failureReason) {
		summary.Errors = append(summary.Errors, failureReason)
	}

	// 10. Append log
	if flagLogFile != "" {
		logArgs := map[string]string{
			"verifier_json": flagVerifierJSON, "mode": flagModifyMode,
			"dry_run": fmt.Sprintf("%v", flagDryRun), "quiet": fmt.Sprintf("%v", flagQuiet),
			"force": fmt.Sprintf("%v", flagForce), "strict": fmt.Sprintf("%v", flagStrict),
			"strict_warn": flagStrictWarn, "verify": fmt.Sprintf("%v", flagVerify),
			"log_file": flagLogFile,
		}
		if err := modifier.AppendModifyLog(flagLogFile, summary, logArgs, strictMatched, failureReason, failureCategory); err != nil {
			return err
		}
	}

	// 11. Output
	w := os.Stdout
	switch resolvedFormat() {
	case FormatJSON:
		if err := presenter.WriteJSON(w, summary); err != nil {
			return err
		}
		if failureReason != "" {
			return fmt.Errorf("%s", failureReason)
		}
		return nil
	case FormatJSONL:
		if err := presenter.WriteJSONL(w, summary); err != nil {
			return err
		}
		if failureReason != "" {
			return fmt.Errorf("%s", failureReason)
		}
		return nil
	case FormatSummary:
		presenter.WriteModifySummary(w, summary)
		return firstError(strictMatched, failureReason, compareErr, parseErr, writeErr)
	default:
		printModifyText(summary, section, newPayload, failureCategory, failureReason, strictMatched, report)
		return firstError(strictMatched, failureReason, compareErr, parseErr, writeErr)
	}
}

type patchStats struct {
	dexes, classes, extras int
}

func countPatchStats(patch model.VerifierPatchSpec) patchStats {
	var s patchStats
	for _, d := range patch.Dexes {
		s.dexes++
		s.classes += len(d.Classes)
		s.extras += len(d.ExtraStrings)
	}
	return s
}

func findVerifierSection(report *model.VdexReport, raw []byte) (model.VdexSection, error) {
	for _, s := range report.Sections {
		if s.Kind == model.SectionVerifierDeps {
			if int(s.Offset)+int(s.Size) > len(raw) {
				return s, fmt.Errorf("verifier section points outside file")
			}
			return s, nil
		}
	}
	return model.VdexSection{}, fmt.Errorf("verifier section not found in input file")
}

func buildPayload(report *model.VdexReport, raw []byte, section model.VdexSection, patch model.VerifierPatchSpec) ([]byte, []string, error) {
	if patch.Mode == "merge" {
		return modifier.BuildVerifierSectionMerge(report.Dexes, report.Checksums, section, raw, patch)
	}
	return modifier.BuildVerifierSectionReplacement(report.Dexes, report.Checksums, patch)
}

func buildModifySummary(inPath, outPath string, patch model.VerifierPatchSpec, ps patchStats,
	report *model.VdexReport, section model.VdexSection, newPayload []byte,
	diff model.VerifierSectionDiff, dexDiffs []model.ModifyDexDiff,
	parseErr, compareErr error) model.ModifySummary {
	s := model.ModifySummary{
		SchemaVersion:         model.VdexSchemaVersion,
		InputFile:             inPath,
		OutputFile:            outPath,
		Mode:                  patch.Mode,
		DryRun:                flagDryRun,
		Status:                "ok",
		PatchDexes:            ps.dexes,
		PatchClasses:          ps.classes,
		PatchExtraStrings:     ps.extras,
		ExpectedDexes:         len(report.Dexes),
		VerifierSectionOld:    section.Size,
		VerifierSectionNew:    len(newPayload),
		TotalClasses:          diff.TotalClasses,
		ModifiedClasses:       diff.ModifiedClasses,
		UnmodifiedClasses:     diff.UnmodifiedClasses,
		DexDiffs:              dexDiffs,
		ClassChangePercent:    calcPercent(diff.ModifiedClasses, diff.TotalClasses),
		Warnings:              report.Warnings,
		WarningsByCategory:    presenter.GroupWarnings(report.Warnings),
		Errors:                report.Errors,
		FailureCategoryCounts: map[string]int{},
	}
	if compareErr != nil {
		s.Status = "failed"
		s.Errors = append(s.Errors, compareErr.Error())
	}
	if s.ExpectedDexes == 0 && len(report.Checksums) > 0 {
		s.ExpectedDexes = len(report.Checksums)
	}
	if parseErr != nil {
		s.Status = "failed"
	}
	return s
}

func applyStrictModify(report *model.VdexReport, summary *model.ModifySummary) []string {
	if !flagStrict {
		return nil
	}
	matched, filterWarn := presenter.StrictMatchingWarnings(report.Warnings, flagStrictWarn)
	if len(filterWarn) > 0 {
		report.Warnings = append(report.Warnings, filterWarn...)
		summary.Warnings = report.Warnings
		summary.WarningsByCategory = presenter.GroupWarnings(summary.Warnings)
	}
	if len(matched) > 0 && summary.Status == "ok" {
		summary.Status = "strict_failed"
	}
	return matched
}

func writeOutput(raw []byte, section model.VdexSection, newPayload []byte, outPath string, summary *model.ModifySummary) error {
	if summary.Status != "ok" || flagDryRun {
		return nil
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	sectionBuf := make([]byte, int(section.Size))
	copy(sectionBuf, newPayload)
	copy(out[int(section.Offset):int(section.Offset)+int(section.Size)], sectionBuf)

	if err := modifier.WriteOutputFileAtomic(outPath, out); err != nil {
		summary.Status = "failed"
		if !lo.Contains(summary.Errors, err.Error()) {
			summary.Errors = append(summary.Errors, err.Error())
		}
		return err
	}
	return nil
}

func printModifyText(s model.ModifySummary, section model.VdexSection, newPayload []byte,
	failureCategory, failureReason string, strictMatched []string, report *model.VdexReport) {
	if flagQuiet && s.Status == "ok" {
		return
	}
	delta := len(newPayload) - int(section.Size)
	fmt.Printf("modify summary: mode=%s patch_dexes=%d patch_classes=%d patch_extra_strings=%d\n",
		s.Mode, s.PatchDexes, s.PatchClasses, s.PatchExtraStrings)
	fmt.Printf("modify diff: classes=%d modified=%d unchanged=%d change=%.2f%%\n",
		s.TotalClasses, s.ModifiedClasses, s.UnmodifiedClasses, s.ClassChangePercent)

	var changedDex []int
	var topChanged []string
	for _, d := range s.DexDiffs {
		if d.ModifiedClasses > 0 {
			changedDex = append(changedDex, d.DexIndex)
			if len(topChanged) < 4 {
				topChanged = append(topChanged, fmt.Sprintf("dex=%d classes=%v", d.DexIndex, d.ChangedClassIdxs))
			}
		}
	}
	if len(changedDex) > 0 {
		maxShow := binutil.MinInt(len(changedDex), 8)
		fmt.Printf("modify changed dexes: %v", changedDex[:maxShow])
		if len(changedDex) > maxShow {
			fmt.Printf(" ... +%d more", len(changedDex)-maxShow)
		}
		fmt.Println()
		if len(topChanged) > 0 {
			fmt.Printf("modify changed class samples: %s\n", strings.Join(topChanged, "; "))
		}
	}

	fmt.Printf("modify status: %s\n", s.Status)
	if failureCategory != "" {
		fmt.Printf("modify failure: %s — %s\n", failureCategory, failureReason)
	}
	fmt.Printf("verifier section size: old=%d new=%d delta=%+d\n", section.Size, len(newPayload), delta)

	switch {
	case flagDryRun:
		fmt.Println("modify output: dry-run (no file written)")
	case s.Status != "ok":
		fmt.Printf("modify output: skipped due to %s\n", s.Status)
	default:
		fmt.Printf("modify output: wrote %s\n", s.OutputFile)
	}

	if len(report.Warnings) > 0 && (!flagQuiet || s.Status != "ok") {
		presenter.PrintGroupedWarnings(report.Warnings)
	}
}

func firstError(strictMatched []string, failureReason string, errs ...error) error {
	if len(strictMatched) > 0 {
		return fmt.Errorf("strict mode: %d matching warning(s): %v", len(strictMatched), strictMatched)
	}
	if failureReason != "" {
		return fmt.Errorf("%s", failureReason)
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func calcPercent(v, total int) float64 {
	return binutil.CalcPercent(v, total)
}

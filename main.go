package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	vdexCurrentVersion = "027"
	notVerifiedMarker  = uint32(0xFFFFFFFF)
	vdexSchemaVersion  = "1.0.0"
	cliVersion        = "0.2.1"
	defaultNameTemplate = "{base}_{index}_{checksum}.dex"

	sectionChecksum     = 0
	sectionDex          = 1
	sectionVerifierDeps = 2
	sectionTypeLookup   = 3

	maxClassPreview      = 20
	maxVerifierPairs     = 20
	maxTypeLookupSamples = 24
	maxTypeLookupClasses = 0xFFFF
	maxModifyClassSamples = 8
)

var sectionName = map[uint32]string{
	sectionChecksum:     "kChecksumSection",
	sectionDex:          "kDexFileSection",
	sectionVerifierDeps: "kVerifierDepsSection",
	sectionTypeLookup:   "kTypeLookupTableSection",
}

var sectionMeaning = map[uint32]string{
	sectionChecksum: "DEX file location checksum list (one uint32 per input dex)",
	sectionDex:      "Concatenated DEX file payload",
	sectionVerifierDeps: "Verifier dependency section",
	sectionTypeLookup:   "Class descriptor lookup table section",
}

type vdexSection struct {
	Kind    uint32 `json:"kind"`
	Offset  uint32 `json:"offset"`
	Size    uint32 `json:"size"`
	Name    string `json:"name"`
	Meaning string `json:"meaning"`
}

type vdexHeader struct {
	Magic       string `json:"magic"`
	Version     string `json:"version"`
	NumSections uint32 `json:"number_of_sections"`
}

type dexReport struct {
	Index         int      `json:"index"`
	Offset        uint32   `json:"offset"`
	Size          uint32   `json:"size"`
	Checksum      uint32   `json:"checksum"`
	Magic         string   `json:"magic"`
	Version       string   `json:"version"`
	ChecksumId    uint32   `json:"checksum_field"`
	Signature     string   `json:"signature"`
	FileSize      uint32   `json:"file_size"`
	HeaderSize    uint32   `json:"header_size"`
	Endian        string   `json:"endian"`
	LinkSize      uint32   `json:"link_size"`
	LinkOffset    uint32   `json:"link_offset"`
	MapOffset     uint32   `json:"map_offset"`
	StringIds     uint32   `json:"string_ids_size"`
	StringIdsOff  uint32   `json:"string_ids_off"`
	TypeIds       uint32   `json:"type_ids_size"`
	TypeIdsOff    uint32   `json:"type_ids_off"`
	ProtoIds      uint32   `json:"proto_ids_size"`
	ProtoIdsOff   uint32   `json:"proto_ids_off"`
	FieldIds      uint32   `json:"field_ids_size"`
	FieldIdsOff   uint32   `json:"field_ids_off"`
	MethodIds     uint32   `json:"method_ids_size"`
	MethodIdsOff  uint32   `json:"method_ids_off"`
	ClassDefs     uint32   `json:"class_defs_size"`
	ClassDefsOff  uint32   `json:"class_defs_off"`
	DataSize      uint32   `json:"data_size"`
	DataOffset    uint32   `json:"data_offset"`
	Classes       []string `json:"class_def_preview,omitempty"`
}

type verifierPair struct {
	ClassDefIndex uint32 `json:"class_def_index"`
	DestID        uint32 `json:"destination_id"`
	Dest          string `json:"destination"`
	SrcID         uint32 `json:"source_id"`
	Src           string `json:"source"`
}

type verifierDexReport struct {
	DexIndex           int            `json:"dex_index"`
	VerifiedClasses    int            `json:"verified_classes"`
	UnverifiedClasses  int            `json:"unverified_classes"`
	AssignabilityPairs int            `json:"assignability_pairs"`
	ExtraStringCount   int            `json:"extra_string_count"`
	FirstPairs         []verifierPair `json:"first_pairs"`
}

type verifierReport struct {
	Offset uint32             `json:"offset"`
	Size   uint32             `json:"size"`
	Dexes  []verifierDexReport `json:"dexes"`
}

type typeLookupSample struct {
	Bucket       uint32 `json:"bucket"`
	ClassDef     uint32 `json:"class_def_index"`
	StringOffset uint32 `json:"string_offset"`
	NextDelta    uint32 `json:"next_delta"`
	HashBits     uint32 `json:"hash_bits"`
	Descriptor   string `json:"descriptor"`
}

type typeLookupDexReport struct {
	DexIndex        int                `json:"dex_index"`
	RawSize         uint32             `json:"raw_size"`
	MaskBits        uint32             `json:"mask_bits"`
	BucketCount     int                `json:"bucket_count"`
	EntryCount      int                `json:"entry_count"`
	NonEmptyBuckets int                `json:"non_empty_buckets"`
	MaxChainLen     int                `json:"max_chain_len"`
	AvgChainLen     float64            `json:"avg_chain_len"`
	Samples         []typeLookupSample `json:"sample_entries"`
	Warnings        []string           `json:"warnings"`
}

type typeLookupReport struct {
	Offset uint32                `json:"offset"`
	Size   uint32                `json:"size"`
	Dexes  []typeLookupDexReport `json:"dexes"`
}

type extractSummary struct {
	SchemaVersion string              `json:"schema_version"`
	File          string              `json:"file"`
	Size          int                 `json:"size"`
	ExtractDir    string              `json:"extract_dir"`
	NameTemplate  string              `json:"name_template"`
	Extracted     int                 `json:"extracted"`
	Failed        int                 `json:"failed"`
	Warnings      []string            `json:"warnings"`
	WarningsByCategory map[string][]string `json:"warnings_by_category,omitempty"`
	Errors        []string            `json:"errors"`
}

type verifierPatchPair struct {
	Dest uint32 `json:"dest"`
	Src  uint32 `json:"src"`
}

type verifierPatchClass struct {
	ClassIndex int                `json:"class_index"`
	Verified   *bool              `json:"verified,omitempty"`
	Pairs      []verifierPatchPair `json:"pairs,omitempty"`
}

type verifierPatchDex struct {
	DexIndex     int                 `json:"dex_index"`
	ExtraStrings []string            `json:"extra_strings"`
	Classes      []verifierPatchClass `json:"classes"`
}

type verifierPatchSpec struct {
	Mode  string            `json:"mode"`
	Dexes []verifierPatchDex `json:"dexes"`
}

type modifySummary struct {
	SchemaVersion      string              `json:"schema_version"`
	InputFile          string              `json:"input_file"`
	OutputFile         string              `json:"output_file"`
	Mode               string              `json:"mode"`
	DryRun             bool                `json:"dry_run"`
	Status             string              `json:"status"`
	PatchDexes         int                 `json:"patch_dexes"`
	PatchClasses       int                 `json:"patch_classes"`
	PatchExtraStrings  int                 `json:"patch_extra_strings"`
	ExpectedDexes      int                 `json:"expected_dexes"`
	VerifierSectionOld  uint32              `json:"verifier_section_old_size"`
	VerifierSectionNew  int                 `json:"verifier_section_new_size"`
	TotalClasses       int                 `json:"total_classes"`
	ModifiedClasses    int                 `json:"modified_classes"`
	UnmodifiedClasses  int                 `json:"unmodified_classes"`
	DexDiffs           []modifyDexDiff     `json:"dex_diffs,omitempty"`
	ClassChangePercent float64             `json:"class_change_percent"`
	WarningsByCategory map[string][]string `json:"warnings_by_category,omitempty"`
	Warnings           []string            `json:"warnings"`
	Errors             []string            `json:"errors"`
	FailureCategory    string              `json:"failure_category,omitempty"`
	FailureCategoryCounts map[string]int    `json:"failure_category_counts,omitempty"`
}

type modifyDexDiff struct {
	DexIndex          int `json:"dex_index"`
	TotalClasses      int `json:"total_classes"`
	ModifiedClasses   int `json:"modified_classes"`
	UnmodifiedClasses int `json:"unmodified_classes"`
	ChangedClassIdxs  []int `json:"changed_class_indices,omitempty"`
}

type verifierSectionDiff struct {
	TotalClasses      int
	ModifiedClasses   int
	UnmodifiedClasses int
}

type parserMeanings struct {
	VdexFile struct {
		Magic       string `json:"magic"`
		Version     string `json:"version"`
		Sections    string `json:"sections"`
		Checksums   string `json:"checksums"`
		DexFiles    string `json:"dex_files"`
		Verifier    string `json:"verifier_deps"`
		TypeLookup  string `json:"type_lookup"`
		Warnings    string `json:"warnings"`
		WarningsByCategory string `json:"warnings_by_category"`
		Errors      string `json:"errors"`
		SchemaVer   string `json:"schema_version"`
	} `json:"vdex_file"`
	SectionKind map[string]string `json:"section_kind"`
	DexHeader struct {
		Magic         string `json:"magic"`
		Version       string `json:"version"`
		Checksum      string `json:"checksum_field"`
		Signature     string `json:"signature"`
		FileSize      string `json:"file_size"`
		HeaderSize    string `json:"header_size"`
		Endian        string `json:"endian"`
		StringIds     string `json:"string_ids_size"`
		StringIdsOff  string `json:"string_ids_off"`
		TypeIds       string `json:"type_ids_size"`
		TypeIdsOff    string `json:"type_ids_off"`
		ProtoIds      string `json:"proto_ids_size"`
		ProtoIdsOff   string `json:"proto_ids_off"`
		FieldIds      string `json:"field_ids_size"`
		FieldIdsOff   string `json:"field_ids_off"`
		MethodIds     string `json:"method_ids_size"`
		MethodIdsOff  string `json:"method_ids_off"`
		ClassDefs     string `json:"class_defs_size"`
		ClassDefsOff  string `json:"class_defs_off"`
		DataSize      string `json:"data_size"`
		DataOffset    string `json:"data_offset"`
		ClassPreview  string `json:"class_def_preview"`
	} `json:"dex_header"`
	VerifierDeps struct {
		Offset            string `json:"offset"`
		Size              string `json:"size"`
		VerifiedClasses   string `json:"verified_classes"`
		UnverifiedClasses string `json:"unverified_classes"`
		AssignabilityPair string `json:"assignability_pairs"`
		ExtraStringCount  string `json:"extra_string_count"`
		FirstPairs        string `json:"first_pairs"`
	} `json:"verifier_deps"`
	TypeLookup struct {
		Offset            string `json:"offset"`
		Size              string `json:"size"`
		RawSize           string `json:"raw_size"`
		BucketCount       string `json:"bucket_count"`
		EntryCount        string `json:"entry_count"`
		NonEmptyBuckets   string `json:"non_empty_buckets"`
		MaxChainLen       string `json:"max_chain_len"`
		AvgChainLen       string `json:"avg_chain_len"`
		SampleEntries     string `json:"sample_entries"`
	} `json:"type_lookup"`
}

type byteCoverageRange struct {
	Offset int    `json:"offset"`
	Size   int    `json:"size"`
	Label  string `json:"label"`
}

type byteCoverageReport struct {
	FileSize       int                  `json:"file_size"`
	ParsedBytes    int                  `json:"parsed_bytes"`
	UnparsedBytes  int                  `json:"unparsed_bytes"`
	CoveragePercent float64             `json:"coverage_percent"`
	Ranges         []byteCoverageRange  `json:"ranges"`
	Gaps           []byteCoverageRange  `json:"gaps,omitempty"`
}

type vdexReport struct {
	SchemaVersion string            `json:"schema_version"`
	Meanings      *parserMeanings   `json:"meanings,omitempty"`
	File       string            `json:"file"`
	Size       int               `json:"size"`
	Header     vdexHeader        `json:"header"`
	Sections   []vdexSection     `json:"sections"`
	Checksums  []uint32          `json:"checksums"`
	Dexes      []dexReport       `json:"dex_files"`
	Verifier   *verifierReport   `json:"verifier_deps,omitempty"`
	TypeLookup *typeLookupReport `json:"type_lookup,omitempty"`
	Coverage   *byteCoverageReport `json:"byte_coverage,omitempty"`
	Warnings   []string          `json:"warnings"`
	WarningsByCategory map[string][]string `json:"warnings_by_category,omitempty"`
	Errors     []string          `json:"errors"`
}

type dexContext struct {
	rep               dexReport
	strings           []string
	stringOffsetToName map[uint32]string
}

var (
	inputPath  string
	showJSON   bool
	extractDir string
	extractNameTemplate string
	extractContinueOnError bool
	extractTemplateWarned bool
	modifyVerifierPatch string
	modifyMode string
	modifyDryRun bool
	modifyVerify bool
	modifyQuiet bool
	modifyLogPath string
	modifyForce bool
	strictMode bool
	showMeanings bool
	showVersion bool
	strictWarn string
	parseCmd   = &cobra.Command{
		Use:   "parse [flags] <file.vdex>",
		Short: "Parse and print vdex information",
		RunE:  run,
		Args:  cobra.MaximumNArgs(1),
	}
	extractCmd = &cobra.Command{
		Use:   "extract <file.vdex> <out-dir>",
		Short: "Extract embedded dex files from vdex",
		Args:  cobra.ExactArgs(2),
		RunE:  runExtract,
	}
	meaningsCmd = &cobra.Command{
		Use:   "meanings",
		Short: "Print vdexcli parsing field meanings",
		Args:  cobra.NoArgs,
		RunE:  runMeanings,
	}
	modifyCmd = &cobra.Command{
		Use:   "modify [flags] <input.vdex> <output.vdex>",
		Short: "Modify verifier section using JSON patch",
		Args:  cobra.ExactArgs(2),
		RunE:  runModify,
	}
	rootCmd    = &cobra.Command{
		Use:   "vdexcli [flags] <file.vdex>",
		Short: "Parse Android ART vdex files and print semantic structure",
		Long: "Parse Android ART vdex files and print semantic structure.\n" +
			"Output is generated as much as possible even with recoverable parse issues.\n" +
			"When --strict is enabled, warnings matched by --strict-warn cause non-zero exit.\n" +
			"Parse errors are also reported as failures; for best compatibility, --strict takes precedence only when it matches first.",
		Args:  cobra.MaximumNArgs(1),
	}
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print vdexcli version",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Printf("vdexcli version %s\n", cliVersion)
		return nil
	},
}

func main() {
	rootCmd.RunE = run
	rootCmd.Version = cliVersion
	rootCmd.SetVersionTemplate("vdexcli version {{.Version}}\n")
	rootCmd.PersistentFlags().StringVarP(&inputPath, "in", "i", "", "input vdex path (or first positional argument)")
	rootCmd.PersistentFlags().BoolVar(&showJSON, "json", false, "output JSON")
	rootCmd.PersistentFlags().BoolVar(&showMeanings, "show-meaning", true, "include meanings in text output and JSON")
	rootCmd.PersistentFlags().BoolVar(&showVersion, "version", false, "print version and exit")
	rootCmd.PersistentFlags().StringVar(&extractDir, "extract-dex", "", "extract embedded dex files into this directory (parse command only)")
	rootCmd.PersistentFlags().StringVar(&extractNameTemplate, "extract-name-template", defaultNameTemplate, "template for extracted dex file names: {base}, {index}, {checksum}, {checksum_hex}, {offset}, {size}")
	rootCmd.PersistentFlags().BoolVar(&extractContinueOnError, "extract-continue-on-error", false, "continue extracting remaining dex files when one file fails")
	rootCmd.PersistentFlags().BoolVar(&strictMode, "strict", false, "treat warnings as fatal errors")
	rootCmd.PersistentFlags().StringVar(&strictWarn, "strict-warn", "", "comma-separated patterns for strict mode (empty => all warnings). Prefix re: for regex, e.g. re:(checksum|version)")
	modifyCmd.Flags().StringVar(&modifyVerifierPatch, "verifier-json", "", "path to verifier patch JSON (use - to read from stdin)")
	modifyCmd.Flags().StringVar(&modifyMode, "mode", "replace", "patch mode for verifier section (replace|merge)")
	modifyCmd.Flags().BoolVar(&modifyDryRun, "dry-run", false, "validate and report changes without writing output file")
	modifyCmd.Flags().BoolVar(&modifyVerify, "verify", false, "alias for --dry-run; keep output unchanged and focus on verifier diff summary")
	modifyCmd.Flags().BoolVar(&modifyQuiet, "quiet", false, "suppress modify text-mode summary output (success lines)")
	modifyCmd.Flags().BoolVar(&modifyForce, "force", false, "allow output path equal to input path")
	modifyCmd.Flags().StringVar(&modifyLogPath, "log-file", "", "append modify result summary to file")
	rootCmd.AddCommand(versionCmd, meaningsCmd, parseCmd, extractCmd, modifyCmd)
	rootCmd.SilenceUsage = true
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type modifyLogEntry struct {
	Timestamp string              `json:"timestamp"`
	Cmd       []string            `json:"command"`
	Summary   modifySummary       `json:"summary"`
	Args      map[string]string   `json:"args"`
	ModifiedDexes []int            `json:"modified_dexes,omitempty"`
	TopSamples []string             `json:"top_modified_class_samples,omitempty"`
	ModifiedClassCount int          `json:"modified_class_count,omitempty"`
	StrictMatched []string        `json:"strict_matched_warnings,omitempty"`
	FailureReason string          `json:"failure_reason,omitempty"`
	FailureCategory string        `json:"failure_category,omitempty"`
	FailureCategoryCounts map[string]int `json:"failure_category_counts,omitempty"`
}

func run(_ *cobra.Command, args []string) error {
	if showVersion {
		fmt.Printf("vdexcli version %s\n", cliVersion)
		return nil
	}

	if modifyVerify {
		modifyDryRun = true
	}
	path := inputPath
	if path == "" {
		if len(args) < 1 {
			rootCmd.Usage()
			return fmt.Errorf("input vdex path is required")
		}
		path = args[0]
	}

	report, raw, err := parseVdex(path)
	parseErr := err
	extractErr := error(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
	}

	if report != nil && extractDir != "" {
		extracted, failed, e := extractDex(path, raw, report, extractDir, extractNameTemplate)
		if e != nil {
			extractErr = e
			fmt.Fprintf(os.Stderr, "extract error: %v\n", e)
		}
		fmt.Printf("extract summary: success=%d failed=%d\n", extracted, failed)
	}
	if report != nil {
		report.WarningsByCategory = groupWarnings(report.Warnings)
	}

	var strictMatched []string
	if strictMode && report != nil {
		var filterWarn []string
		strictMatched, filterWarn = strictMatchingWarnings(report.Warnings, strictWarn)
		if len(filterWarn) > 0 {
			report.Warnings = append(report.Warnings, filterWarn...)
			report.WarningsByCategory = groupWarnings(report.Warnings)
		}
	}

	if showJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("json encode error: %w", err)
		}
		if len(strictMatched) > 0 {
			return fmt.Errorf("strict mode: %d matching warning(s): %v", len(strictMatched), strictMatched)
		}
		if parseErr != nil {
			return parseErr
		}
		return nil
	}

	printText(report)
	if strictMode && report != nil {
		if len(strictMatched) > 0 {
			return fmt.Errorf("strict mode: %d matching warning(s): %v", len(strictMatched), strictMatched)
		}
	}
	if parseErr != nil {
		return parseErr
	}
	return extractErr
}

func runMeanings(_ *cobra.Command, _ []string) error {
	m := newParserMeanings()
	if showJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m); err != nil {
			return fmt.Errorf("json encode error: %w", err)
		}
		return nil
	}

	printTextMeanings(m)
	return nil
}

func categorizeWarning(w string) string {
	lw := strings.ToLower(w)
	switch {
	case strings.Contains(lw, "magic") || strings.Contains(lw, "version") || strings.Contains(lw, "file header"):
		return "header"
	case strings.Contains(lw, "section"):
		return "section"
	case strings.Contains(lw, "dex[") || strings.Contains(lw, "dex file") || strings.Contains(lw, "file_size") || strings.Contains(lw, "declared file_size") || strings.Contains(lw, "header_size"):
		return "dex"
	case strings.Contains(lw, "verifier"):
		return "verifier"
	case strings.Contains(lw, "type-lookup") || strings.Contains(lw, "type_lookup") || strings.Contains(lw, "type lookup"):
		return "type_lookup"
	case strings.Contains(lw, "template") || strings.Contains(lw, "extract"):
		return "extract"
	default:
		return "other"
	}
}

func groupWarnings(warnings []string) map[string][]string {
	grouped := map[string][]string{}
	for _, w := range warnings {
		c := categorizeWarning(w)
		grouped[c] = append(grouped[c], w)
	}
	return grouped
}

func printGroupedWarnings(warnings []string) {
	grouped := groupWarnings(warnings)
	if len(warnings) == 0 {
		return
	}
	order := []string{"header", "section", "dex", "verifier", "type_lookup", "extract", "other"}
	for _, c := range order {
		ws, ok := grouped[c]
		if !ok || len(ws) == 0 {
			continue
		}
		fmt.Printf("%s warnings (%d):\n", c, len(ws))
		for _, w := range ws {
			fmt.Printf("  - %s\n", w)
		}
	}
}

func runExtract(_ *cobra.Command, args []string) error {
	if showVersion {
		fmt.Printf("vdexcli version %s\n", cliVersion)
		return nil
	}
	vdexPath := args[0]
	outDir := args[1]

	report, raw, err := parseVdex(vdexPath)
	if err != nil && report == nil {
		return err
	}
	parseErr := err
	if report == nil {
		return fmt.Errorf("no parse result")
	}
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	}
	extracted, failed, err := extractDex(vdexPath, raw, report, outDir, extractNameTemplate)
	report.WarningsByCategory = groupWarnings(report.Warnings)
	if err != nil {
		return err
	}
	if !showJSON {
		fmt.Printf("extract summary: success=%d failed=%d\n", extracted, failed)
	}
	if strictMode {
		matched, filterWarn := strictMatchingWarnings(report.Warnings, strictWarn)
		if len(filterWarn) > 0 {
			report.Warnings = append(report.Warnings, filterWarn...)
			report.WarningsByCategory = groupWarnings(report.Warnings)
		}
		if len(matched) > 0 {
			return fmt.Errorf("strict mode: %d matching warning(s): %v", len(matched), matched)
		}
	}
	if len(report.Warnings) > 0 && !showJSON {
		printGroupedWarnings(report.Warnings)
	}
	if showJSON {
		extractSummaryReport := extractSummary{
			SchemaVersion:      vdexSchemaVersion,
			File:               vdexPath,
			Size:               len(raw),
			ExtractDir:         outDir,
			NameTemplate:       extractNameTemplate,
			Extracted:          extracted,
			Failed:             failed,
			Warnings:           report.Warnings,
			WarningsByCategory: report.WarningsByCategory,
			Errors:             report.Errors,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if e := enc.Encode(extractSummaryReport); e != nil {
			return fmt.Errorf("json encode error: %w", e)
		}
		if parseErr != nil {
			return parseErr
		}
		return nil
	}
	if parseErr != nil {
		return parseErr
	}
	fmt.Printf("extracted %d dex files to %s\n", extracted, outDir)
	return nil
}

func runModify(_ *cobra.Command, args []string) error {
	if showVersion {
		fmt.Printf("vdexcli version %s\n", cliVersion)
		return nil
	}

	if modifyVerify {
		modifyDryRun = true
	}

	inPath := args[0]
	outPath := args[1]
	if !modifyVerify && inPath == outPath {
		inAbs, errIn := filepath.Abs(inPath)
		outAbs, errOut := filepath.Abs(outPath)
		if errIn != nil || errOut != nil {
			inAbs = filepath.Clean(inPath)
			outAbs = filepath.Clean(outPath)
		}
		if !modifyForce && inAbs == outAbs {
			return fmt.Errorf("output path equals input path; add --force to allow in-place overwrite")
		}
	}
	if strings.TrimSpace(modifyVerifierPatch) == "" {
		return fmt.Errorf("--verifier-json is required")
	}
	if strings.TrimSpace(modifyMode) == "" {
		modifyMode = "replace"
	}
	modifyMode = strings.ToLower(strings.TrimSpace(modifyMode))
	if modifyMode != "replace" && modifyMode != "merge" {
		return fmt.Errorf("unsupported --mode %q; supported modes: replace, merge", modifyMode)
	}

	report, raw, err := parseVdex(inPath)
	parseErr := err
	if err != nil && report == nil {
		return err
	}
	if report == nil {
		return fmt.Errorf("no parse result")
	}
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	}

	patch, patchWarn, err := parseVerifierPatch(modifyVerifierPatch)
	if err != nil {
		return fmt.Errorf("load verifier patch %q: %w", modifyVerifierPatch, err)
	}
	patchDexCount := 0
	patchClassCount := 0
	patchExtraCount := 0
	for _, d := range patch.Dexes {
		patchDexCount++
		patchClassCount += len(d.Classes)
		patchExtraCount += len(d.ExtraStrings)
	}
	if patch.Mode == "" {
		patch.Mode = modifyMode
	} else if patch.Mode != modifyMode {
		return fmt.Errorf("patch mode %q does not match --mode %q", patch.Mode, modifyMode)
	}
	report.Warnings = append(report.Warnings, patchWarn...)

	var section vdexSection
	found := false
	for _, s := range report.Sections {
		if s.Kind == sectionVerifierDeps {
			section = s
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("verifier section not found in input file")
	}

	if int(section.Offset)+int(section.Size) > len(raw) {
		return fmt.Errorf("verifier section points outside file")
	}

	var newPayload []byte
	var buildWarn []string
	if modifyMode == "merge" {
		newPayload, buildWarn, err = buildVerifierSectionMerge(report.Dexes, report.Checksums, section, raw, patch)
	} else {
		newPayload, buildWarn, err = buildVerifierSectionReplacement(report.Dexes, report.Checksums, patch)
	}
	report.Warnings = append(report.Warnings, buildWarn...)
	if err != nil {
		return err
	}
	if len(newPayload) > int(section.Size) {
		return fmt.Errorf("verifier patch payload too large: %d bytes > section size %d", len(newPayload), section.Size)
	}
	diff, dexDiffs, diffWarn, compareErr := compareVerifierSectionDiff(raw, section, report.Dexes, report.Checksums, newPayload)
	report.Warnings = append(report.Warnings, diffWarn...)

	modSummary := modifySummary{
		SchemaVersion:      vdexSchemaVersion,
		InputFile:          inPath,
		OutputFile:         outPath,
		Mode:               patch.Mode,
		DryRun:             modifyDryRun,
		Status:             "ok",
		PatchDexes:         patchDexCount,
		PatchClasses:       patchClassCount,
		PatchExtraStrings:  patchExtraCount,
		ExpectedDexes:      len(report.Dexes),
		VerifierSectionOld:  section.Size,
		VerifierSectionNew:  len(newPayload),
		TotalClasses:       diff.TotalClasses,
		ModifiedClasses:    diff.ModifiedClasses,
		UnmodifiedClasses:  diff.UnmodifiedClasses,
		DexDiffs:           dexDiffs,
		ClassChangePercent: calcPercent(diff.ModifiedClasses, diff.TotalClasses),
		Warnings:           report.Warnings,
		WarningsByCategory: groupWarnings(report.Warnings),
		Errors:             report.Errors,
		FailureCategoryCounts: map[string]int{},
	}
	if compareErr != nil {
		modSummary.Status = "failed"
		modSummary.Errors = append(modSummary.Errors, compareErr.Error())
	}
	if modSummary.ExpectedDexes == 0 && len(report.Checksums) > 0 {
		modSummary.ExpectedDexes = len(report.Checksums)
	}
	if parseErr != nil {
		modSummary.Status = "failed"
	}
	if modSummary.Status != "ok" && modifyQuiet {
		modSummary.WarningsByCategory = groupWarnings(modSummary.Warnings)
	}
	strictMatched := []string{}
	if strictMode {
		var filterWarn []string
		strictMatched, filterWarn = strictMatchingWarnings(report.Warnings, strictWarn)
		if len(filterWarn) > 0 {
			report.Warnings = append(report.Warnings, filterWarn...)
			modSummary.Warnings = report.Warnings
			modSummary.WarningsByCategory = groupWarnings(modSummary.Warnings)
		}
		if len(strictMatched) > 0 && modSummary.Status == "ok" {
			modSummary.Status = "strict_failed"
		}
	}
	writeErr := error(nil)
	if modSummary.Status == "ok" && !modifyDryRun {
		out := make([]byte, len(raw))
		copy(out, raw)
		sectionPayload := make([]byte, int(section.Size))
		copy(sectionPayload, newPayload)
		copy(out[int(section.Offset):int(section.Offset)+int(section.Size)], sectionPayload)

		if err := writeOutputFileAtomic(outPath, out); err != nil {
			writeErr = err
			modSummary.Status = "failed"
			alreadyHas := false
			for _, existing := range modSummary.Errors {
				if existing == err.Error() {
					alreadyHas = true
					break
				}
			}
			if !alreadyHas {
				modSummary.Errors = append(modSummary.Errors, err.Error())
			}
		}
	}
	failureReason := makeFailureReason(modSummary, parseErr, compareErr, writeErr, strictMatched)
	failureCategory := makeFailureCategory(modSummary, parseErr, compareErr, writeErr, strictMatched)
	modSummary.FailureCategory = failureCategory
	if failureCategory != "" {
		modSummary.FailureCategoryCounts[failureCategory]++
	}
	if failureReason != "" {
		alreadyHas := false
		for _, existing := range modSummary.Errors {
			if existing == failureReason {
				alreadyHas = true
				break
			}
		}
		if !alreadyHas {
			modSummary.Errors = append(modSummary.Errors, failureReason)
		}
	}
	if modifyLogPath != "" {
		if err := appendModifyLog(modifyLogPath, modSummary, strictMatched, failureReason, failureCategory); err != nil {
			return err
		}
	}

	if showJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if e := enc.Encode(modSummary); e != nil {
			return fmt.Errorf("json encode error: %w", e)
		}
		if failureCategory != "" && failureReason != "" {
			return fmt.Errorf("%s", failureReason)
		}
		return nil
	}

	delta := len(newPayload) - int(section.Size)
	if !modifyQuiet {
		fmt.Printf("modify summary: mode=%s patch_dexes=%d patch_classes=%d patch_extra_strings=%d\n", patch.Mode, patchDexCount, patchClassCount, patchExtraCount)
		fmt.Printf("modify diff: classes=%d modified=%d unchanged=%d change=%.2f%%\n", modSummary.TotalClasses, modSummary.ModifiedClasses, modSummary.UnmodifiedClasses, modSummary.ClassChangePercent)
		changedDex := make([]int, 0, len(modSummary.DexDiffs))
		topChanged := make([]string, 0)
		for _, d := range modSummary.DexDiffs {
			if d.ModifiedClasses > 0 {
				changedDex = append(changedDex, d.DexIndex)
				if len(topChanged) < 4 {
					topChanged = append(topChanged, fmt.Sprintf("dex=%d classes=%v", d.DexIndex, d.ChangedClassIdxs))
				}
			}
		}
		if len(changedDex) > 0 {
			maxShow := minInt(len(changedDex), 8)
			fmt.Printf("modify changed dexes: %v", changedDex[:maxShow])
			if len(changedDex) > maxShow {
				fmt.Printf(" ... +%d more", len(changedDex)-maxShow)
			}
			fmt.Printf("\n")
			if len(topChanged) > 0 {
				fmt.Printf("modify changed class samples: %s\n", strings.Join(topChanged, "; "))
			}
		}
		fmt.Printf("modify status: %s\n", modSummary.Status)
		if failureCategory != "" {
			fmt.Printf("modify failure category: %s\n", failureCategory)
		}
		if failureReason != "" {
			fmt.Printf("modify failure reason: %s\n", failureReason)
		}
		fmt.Printf("verifier section size: old=%d new=%d delta=%+d\n", section.Size, len(newPayload), delta)
		if modifyDryRun || modSummary.Status != "ok" {
			fmt.Printf("modify output: dry-run (no output file written)\n")
		} else {
			fmt.Printf("modify output: wrote file=%s\n", outPath)
		}
	}

	if strictMatched != nil && len(strictMatched) > 0 {
		return fmt.Errorf("strict mode: %d matching warning(s): %v", len(strictMatched), strictMatched)
	}
	if failureCategory != "" && failureReason != "" {
		return fmt.Errorf("%s", failureReason)
	}
	if compareErr != nil {
		return compareErr
	}
	if parseErr != nil {
		return parseErr
	}
	if writeErr != nil {
		return writeErr
	}
	if !modifyQuiet {
		if modifyDryRun {
			fmt.Printf("modify result: dry-run completed without writing output.\n")
		} else {
			fmt.Printf("modified verifier section successfully.\n")
		}
	}
	if len(report.Warnings) > 0 && (!modifyQuiet || modSummary.Status != "ok") {
		printGroupedWarnings(report.Warnings)
	}
	return nil
}

func makeFailureReason(summary modifySummary, parseErr error, compareErr error, writeErr error, strictMatched []string) string {
	if summary.Status == "strict_failed" && len(strictMatched) > 0 {
		return fmt.Sprintf("strict mode: matched %d warning(s): %v", len(strictMatched), strictMatched)
	}
	if writeErr != nil {
		return writeErr.Error()
	}
	if compareErr != nil {
		return compareErr.Error()
	}
	if parseErr != nil {
		return parseErr.Error()
	}
	if summary.Status != "ok" {
		for _, e := range summary.Errors {
			if e != "" {
				return e
			}
		}
		return "modify failed"
	}
	return ""
}

func makeFailureCategory(summary modifySummary, parseErr error, compareErr error, writeErr error, strictMatched []string) string {
	if summary.Status == "strict_failed" && len(strictMatched) > 0 {
		return "strict"
	}
	if writeErr != nil {
		return "write"
	}
	if compareErr != nil {
		return "compare"
	}
	if parseErr != nil {
		return "parse"
	}
	if summary.Status != "ok" {
		return "modify"
	}
	return ""
}

func parseVerifierPatch(path string) (verifierPatchSpec, []string, error) {
	out := verifierPatchSpec{}
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return out, nil, fmt.Errorf("read verifier patch: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out, nil, fmt.Errorf("invalid verifier patch json: empty input")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, nil, fmt.Errorf("invalid verifier patch json: %w", err)
	}
	if err := func() error {
		var extra any
		if err := dec.Decode(&extra); err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected extra json content")
	}(); err != nil {
		return out, nil, fmt.Errorf("invalid verifier patch json: %w", err)
	}
	if err := validateVerifierPatchIndices(out); err != nil {
		return out, nil, err
	}
	out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	switch out.Mode {
	case "replace":
		// replace mode
	case "merge":
		// merge mode
	case "":
		// resolved from command flag
	default:
		return out, nil, fmt.Errorf("unsupported patch mode %q; supported: replace, merge", out.Mode)
	}
	return out, nil, nil
}

func validateVerifierPatchIndices(patch verifierPatchSpec) error {
	dexes := map[int]struct{}{}
	for _, d := range patch.Dexes {
		if d.DexIndex < 0 {
			return fmt.Errorf("invalid dex_index %d", d.DexIndex)
		}
		if _, exists := dexes[d.DexIndex]; exists {
			return fmt.Errorf("duplicate patch dex_index %d", d.DexIndex)
		}
		dexes[d.DexIndex] = struct{}{}

		classes := map[int]struct{}{}
		for _, c := range d.Classes {
			if c.ClassIndex < 0 {
				return fmt.Errorf("invalid class_index %d for dex %d", c.ClassIndex, d.DexIndex)
			}
			if _, exists := classes[c.ClassIndex]; exists {
				return fmt.Errorf("duplicate class_index %d for dex %d", c.ClassIndex, d.DexIndex)
			}
			classes[c.ClassIndex] = struct{}{}
		}
	}
	return nil
}

func buildVerifierSectionReplacement(dexes []dexReport, checksums []uint32, patch verifierPatchSpec) ([]byte, []string, error) {
	warnings := []string{}
	patchByDex := map[int]verifierPatchDex{}
	for _, d := range patch.Dexes {
		if _, exists := patchByDex[d.DexIndex]; exists {
			return nil, warnings, fmt.Errorf("duplicate patch dex_index %d", d.DexIndex)
		}
		if d.DexIndex < 0 {
			return nil, warnings, fmt.Errorf("invalid dex_index %d", d.DexIndex)
		}
		patchByDex[d.DexIndex] = d
	}

	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	if dexCount == 0 {
		return nil, warnings, fmt.Errorf("cannot infer dex count from input, no dex or checksum section parsed")
	}
	for dexIdx := range patchByDex {
		if dexIdx >= dexCount {
			return nil, warnings, fmt.Errorf("patch dex_index %d exceeds dex count %d", dexIdx, dexCount)
		}
		if len(patchByDex[dexIdx].Classes) > 0 && dexIdx >= len(dexes) {
			return nil, warnings, fmt.Errorf("cannot patch dex %d classes: class count is unknown (dex section not parsed)", dexIdx)
		}
		if len(patchByDex[dexIdx].ExtraStrings) > 0 && dexIdx >= len(dexes) {
			warnings = append(warnings, fmt.Sprintf("dex %d extra strings provided but dex section missing, offsets for existing base strings cannot be validated", dexIdx))
		}
	}

	sectionPayload := make([]byte, dexCount*4)
	cursor := dexCount * 4

	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		classCount := uint32(0)
		if dexIdx < len(dexes) {
			classCount = dexes[dexIdx].ClassDefs
		}
		dexPatch, hasPatch := patchByDex[dexIdx]
		if !hasPatch {
			dexPatch = verifierPatchDex{
				DexIndex:     dexIdx,
				Classes:      nil,
				ExtraStrings: nil,
			}
		}
		baseStringCount := 0
		if dexIdx < len(dexes) {
			baseStringCount = int(dexes[dexIdx].StringIds)
		}
		d, buildWarn, err := buildVerifierDexFromPatch(int(classCount), baseStringCount, dexPatch, uint32(cursor))
		warnings = append(warnings, buildWarn...)
		if err != nil {
			return nil, warnings, err
		}

		binary.LittleEndian.PutUint32(sectionPayload[dexIdx*4:], uint32(cursor))
		sectionPayload = append(sectionPayload, d...)
		cursor += len(d)
	}

	return sectionPayload, warnings, nil
}

func buildVerifierSectionMerge(dexes []dexReport, checksums []uint32, section vdexSection, raw []byte, patch verifierPatchSpec) ([]byte, []string, error) {
	warnings := []string{}
	if len(dexes) == 0 {
		warnings = append(warnings, "merge mode running without dex section class-count context; class patches will require explicit dex class info in input")
	}
	existing, parseWarn, err := parseVerifierSectionForMerge(raw, section, dexes, checksums)
	warnings = append(warnings, parseWarn...)
	if err != nil {
		return nil, warnings, err
	}

	patchByDex := map[int]verifierPatchDex{}
	for _, d := range patch.Dexes {
		if _, exists := patchByDex[d.DexIndex]; exists {
			return nil, warnings, fmt.Errorf("duplicate patch dex_index %d", d.DexIndex)
		}
		if d.DexIndex < 0 {
			return nil, warnings, fmt.Errorf("invalid dex_index %d", d.DexIndex)
		}
		patchByDex[d.DexIndex] = d
	}

	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	if dexCount == 0 {
		return nil, warnings, fmt.Errorf("cannot infer dex count from input, no dex or checksum section parsed")
	}
	for dexIdx := range patchByDex {
		if dexIdx >= dexCount {
			return nil, warnings, fmt.Errorf("patch dex_index %d exceeds dex count %d", dexIdx, dexCount)
		}
		if len(patchByDex[dexIdx].Classes) > 0 && dexIdx >= len(dexes) {
			return nil, warnings, fmt.Errorf("cannot patch dex %d classes in merge mode: class count is unknown (dex section not parsed)", dexIdx)
		}
	}

	sectionPayload := make([]byte, dexCount*4)
	cursor := dexCount * 4

	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		old := existing[dexIdx]
		classCount := old.ClassCount
		if dexIdx < len(dexes) {
			classCount = int(dexes[dexIdx].ClassDefs)
		}
		baseStringCount := 0
		if dexIdx < len(dexes) {
			baseStringCount = int(dexes[dexIdx].StringIds)
		}
		if classCount < 0 {
			return nil, warnings, fmt.Errorf("invalid class count %d for dex %d", classCount, dexIdx)
		}

		classVerified := make([]bool, classCount)
		classPairs := make([][]verifierPatchPair, classCount)
		for i, c := range old.Classes {
			if i >= classCount {
				break
			}
			classVerified[i] = c.Verified
			classPairs[i] = append(classPairs[i], c.Pairs...)
		}

		dexPatch := patchByDex[dexIdx]
		seenClass := map[int]bool{}
		for _, c := range dexPatch.Classes {
			if c.ClassIndex < 0 || c.ClassIndex >= classCount {
				return nil, warnings, fmt.Errorf("invalid class_index %d for class_count %d", c.ClassIndex, classCount)
			}
			if seenClass[c.ClassIndex] {
				return nil, warnings, fmt.Errorf("duplicate class_index %d in patch", c.ClassIndex)
			}
			seenClass[c.ClassIndex] = true
			verified := true
			if c.Verified != nil {
				verified = *c.Verified
			} else if len(c.Pairs) == 0 {
				verified = false
			}
			classVerified[c.ClassIndex] = verified
			if verified {
				classPairs[c.ClassIndex] = append([]verifierPatchPair{}, c.Pairs...)
			} else {
				classPairs[c.ClassIndex] = nil
			}
		}

		extraStrings := append([]string{}, old.ExtraString...)
		extraStrings = append(extraStrings, dexPatch.ExtraStrings...)
		if dexIdx >= len(dexes) && len(extraStrings) > 0 {
			warnings = append(warnings, fmt.Sprintf("merged extra_strings for dex %d without dex section context; base string validation skipped", dexIdx))
		}

		d, buildWarn, err := buildVerifierDexBlock(classCount, baseStringCount, classVerified, classPairs, extraStrings, uint32(cursor))
		warnings = append(warnings, buildWarn...)
		if err != nil {
			return nil, warnings, err
		}

		binary.LittleEndian.PutUint32(sectionPayload[dexIdx*4:], uint32(cursor))
		sectionPayload = append(sectionPayload, d...)
		cursor += len(d)
	}

	return sectionPayload, warnings, nil
}

func buildVerifierDexFromPatch(classCount int, baseStringCount int, patch verifierPatchDex, blockOffset uint32) ([]byte, []string, error) {
	warnings := []string{}
	classVerified := make([]bool, classCount)
	classPairs := make([][]verifierPatchPair, classCount)
	seenClass := map[int]bool{}
	for _, c := range patch.Classes {
		if c.ClassIndex < 0 || c.ClassIndex >= classCount {
			return nil, warnings, fmt.Errorf("invalid class_index %d for class_count %d", c.ClassIndex, classCount)
		}
		if seenClass[c.ClassIndex] {
			return nil, warnings, fmt.Errorf("duplicate class_index %d in patch", c.ClassIndex)
		}
		seenClass[c.ClassIndex] = true
		verified := true
		if c.Verified != nil {
			verified = *c.Verified
		} else if len(c.Pairs) == 0 {
			verified = false
		}
		classVerified[c.ClassIndex] = verified
		if verified {
			classPairs[c.ClassIndex] = append([]verifierPatchPair{}, c.Pairs...)
		}
	}
	return buildVerifierDexBlock(classCount, baseStringCount, classVerified, classPairs, patch.ExtraStrings, blockOffset)
}

type verifierSectionClass struct {
	Verified bool
	Pairs    []verifierPatchPair
}

type verifierSectionDex struct {
	ClassCount int
	Classes    []verifierSectionClass
	ExtraString []string
}

func parseVerifierSectionForMerge(raw []byte, s vdexSection, dexes []dexReport, checksums []uint32) (map[int]verifierSectionDex, []string, error) {
	warnings := []string{}
	out := map[int]verifierSectionDex{}
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end < start || end > len(raw) {
		return out, append(warnings, "verifier section out of file range"), fmt.Errorf("verifier section out of file range")
	}
	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	if dexCount == 0 {
		return out, warnings, fmt.Errorf("cannot infer dex count from input, no dex or checksum section parsed")
	}

	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		indexOff := start + dexIdx*4
		if indexOff+4 > end {
			warnings = append(warnings, fmt.Sprintf("verifier section index table truncated at dex %d", dexIdx))
			out[dexIdx] = verifierSectionDex{
				ClassCount: 0,
			}
			continue
		}
		relative := int(readU32(raw, indexOff))
		blockStart := start + relative
		if blockStart < start || blockStart >= end {
			warnings = append(warnings, fmt.Sprintf("verifier block %d offset %#x outside section", dexIdx, relative))
			out[dexIdx] = verifierSectionDex{
				ClassCount: 0,
			}
			continue
		}
		blockEnd := end
		if dexIdx+1 < dexCount {
			nextIdx := start + (dexIdx+1)*4
			if nextIdx+4 <= end {
				nextRel := int(readU32(raw, nextIdx))
				if nextRel >= 0 && nextRel <= int(s.Size) {
					blockEnd = start + nextRel
				}
			} else {
				warnings = append(warnings, fmt.Sprintf("verifier section index table truncated when determining block end for dex %d", dexIdx))
			}
			if blockEnd < blockStart {
				blockEnd = end
			}
		}
		if blockEnd > end {
			blockEnd = end
		}

		classCount := 0
		if dexIdx < len(dexes) {
			classCount = int(dexes[dexIdx].ClassDefs)
		}
		dexData, parseWarn, parseErr := parseVerifierDexForMerge(raw, start, blockStart, blockEnd, dexIdx, classCount)
		warnings = append(warnings, parseWarn...)
		if parseErr != nil {
			return out, warnings, parseErr
		}
		out[dexIdx] = dexData
	}

	return out, warnings, nil
}

func compareVerifierSectionDiff(raw []byte, section vdexSection, dexes []dexReport, checksums []uint32, patchedPayload []byte) (verifierSectionDiff, []modifyDexDiff, []string, error) {
	diff := verifierSectionDiff{}
	warnings := []string{}
	dexDiffs := make([]modifyDexDiff, 0)

	oldData, oldWarn, oldErr := parseVerifierSectionForMerge(raw, section, dexes, checksums)
	warnings = append(warnings, oldWarn...)

	patchedSection := vdexSection{
		Offset: 0,
		Size:   uint32(len(patchedPayload)),
	}
	newData, newWarn, newErr := parseVerifierSectionForMerge(patchedPayload, patchedSection, dexes, checksums)
	warnings = append(warnings, newWarn...)

	if oldErr != nil || newErr != nil {
		if oldErr != nil {
			warnings = append(warnings, fmt.Sprintf("cannot compare verifier diff against original: %v", oldErr))
		}
		if newErr != nil {
			warnings = append(warnings, fmt.Sprintf("cannot compare verifier diff against patched payload: %v", newErr))
		}
		if oldErr != nil {
			return diff, nil, warnings, oldErr
		}
		return diff, nil, warnings, newErr
	}

	dexCount := len(dexes)
	if dexCount == 0 {
		dexCount = len(checksums)
	}
	for dexIdx := 0; dexIdx < dexCount; dexIdx++ {
		oldDex := oldData[dexIdx]
		newDex := newData[dexIdx]
		classCount := oldDex.ClassCount
		if newDex.ClassCount > classCount {
			classCount = newDex.ClassCount
		}
		dexDiff := modifyDexDiff{
			DexIndex: dexIdx,
		}
		if classCount < 0 {
			continue
		}
		for classIdx := 0; classIdx < classCount; classIdx++ {
			var oldClass verifierSectionClass
			var newClass verifierSectionClass
			if classIdx < len(oldDex.Classes) {
				oldClass = oldDex.Classes[classIdx]
			}
			if classIdx < len(newDex.Classes) {
				newClass = newDex.Classes[classIdx]
			}

			diff.TotalClasses++
			dexDiff.TotalClasses++
		if verifierSectionClassEqual(oldClass, newClass) {
			diff.UnmodifiedClasses++
			dexDiff.UnmodifiedClasses++
		} else {
			diff.ModifiedClasses++
			dexDiff.ModifiedClasses++
			if len(dexDiff.ChangedClassIdxs) < maxModifyClassSamples {
				dexDiff.ChangedClassIdxs = append(dexDiff.ChangedClassIdxs, classIdx)
			}
		}
	}
		dexDiffs = append(dexDiffs, dexDiff)
	}
	return diff, dexDiffs, warnings, nil
}

func verifierSectionClassEqual(a verifierSectionClass, b verifierSectionClass) bool {
	if a.Verified != b.Verified {
		return false
	}
	if len(a.Pairs) != len(b.Pairs) {
		return false
	}
	for i := range a.Pairs {
		if a.Pairs[i].Dest != b.Pairs[i].Dest || a.Pairs[i].Src != b.Pairs[i].Src {
			return false
		}
	}
	return true
}

func parseVerifierDexForMerge(raw []byte, sectionStart int, blockStart int, sectionEnd int, dexIdx int, classCount int) (verifierSectionDex, []string, error) {
	out := verifierSectionDex{
		ClassCount: classCount,
		Classes:    make([]verifierSectionClass, classCount),
	}
	warnings := []string{}
	if blockStart+4*(classCount+1) > sectionEnd {
		return out, append(warnings, fmt.Sprintf("dex %d verifier block truncated", dexIdx)), fmt.Errorf("dex %d verifier block truncated", dexIdx)
	}

	offsets := make([]uint32, classCount+1)
	for i := 0; i <= classCount; i++ {
		offsets[i] = readU32(raw, blockStart+i*4)
	}

	maxSetEnd := blockStart + 4*(classCount+1)
	nextValid := 1
	for classIdx := 0; classIdx < classCount; classIdx++ {
		o := offsets[classIdx]
		if o == notVerifiedMarker {
			out.Classes[classIdx] = verifierSectionClass{Verified: false}
			continue
		}
		out.Classes[classIdx].Verified = true
		for nextValid <= classIdx || (nextValid <= classCount && offsets[nextValid] == notVerifiedMarker) {
			nextValid++
			if nextValid > classCount {
				return out, append(warnings, fmt.Sprintf("dex %d class %d malformed class offset chain", dexIdx, classIdx)), fmt.Errorf("dex %d class %d malformed class offset chain", dexIdx, classIdx)
			}
		}
		// Section-absolute offsets: base is sectionStart, not blockStart.
		setStart := sectionStart + int(o)
		setEnd := sectionStart + int(offsets[nextValid])
		if setStart < blockStart || setEnd > sectionEnd || setEnd < setStart {
			return out, append(warnings, fmt.Sprintf("dex %d class %d malformed set bounds", dexIdx, classIdx)), fmt.Errorf("dex %d class %d malformed set bounds", dexIdx, classIdx)
		}
		if setEnd > maxSetEnd {
			maxSetEnd = setEnd
		}
		cursor := setStart
		for cursor < setEnd {
			dest, n, err := readULEB128(raw, cursor)
			if err != nil {
				return out, append(warnings, fmt.Sprintf("dex %d class %d invalid destination leb128", dexIdx, classIdx)), err
			}
			cursor += n
			src, n, err := readULEB128(raw, cursor)
			if err != nil {
				return out, append(warnings, fmt.Sprintf("dex %d class %d invalid source leb128", dexIdx, classIdx)), err
			}
			cursor += n
			out.Classes[classIdx].Pairs = append(out.Classes[classIdx].Pairs, verifierPatchPair{Dest: dest, Src: src})
		}
	}

	cursor := align4(maxSetEnd)
	if cursor+4 > sectionEnd {
		return out, warnings, nil
	}
	numStrings := int(readU32(raw, cursor))
	cursor += 4
	if cursor+numStrings*4 > sectionEnd {
		warnings = append(warnings, fmt.Sprintf("dex %d verifier extra strings table truncated", dexIdx))
		return out, warnings, nil
	}
	extras := make([]string, numStrings)
	for i := 0; i < numStrings; i++ {
		// Extra string offsets are section-absolute.
		rel := int(readU32(raw, cursor+i*4))
		abs := sectionStart + rel
		if abs < blockStart || abs >= sectionEnd {
			extras[i] = fmt.Sprintf("invalid_%d", i)
			warnings = append(warnings, fmt.Sprintf("dex %d extra string %d offset %#x invalid", dexIdx, i, rel))
			continue
		}
		extras[i] = readCString(raw[abs:sectionEnd])
	}
	out.ExtraString = extras
	return out, warnings, nil
}

func buildVerifierDexBlock(classCount int, baseStringCount int, classVerified []bool, classPairs [][]verifierPatchPair, extraStrings []string, blockOffset uint32) ([]byte, []string, error) {
	warnings := []string{}
	if classCount < 0 {
		return nil, warnings, fmt.Errorf("invalid classCount %d", classCount)
	}
	if len(classVerified) < classCount {
		return nil, warnings, fmt.Errorf("class verified array shorter than class count %d", classCount)
	}
	if len(classPairs) < classCount {
		return nil, warnings, fmt.Errorf("class pairs array shorter than class count %d", classCount)
	}

	// Offsets stored in the class-def table must be section-absolute (relative
	// to the verifier-deps section start), matching the ART runtime encoding.
	// blockOffset is this block's position within the section.
	localOffsetBase := uint32(4 * (classCount + 1))
	offsets := make([]uint32, classCount+1)
	for i := 0; i < classCount; i++ {
		offsets[i] = notVerifiedMarker
	}
	offsets[classCount] = blockOffset + localOffsetBase
	body := make([]byte, 0, 64)
	currentLocalOffset := localOffsetBase
	for i := 0; i < classCount; i++ {
		if !classVerified[i] {
			continue
		}
		offsets[i] = blockOffset + currentLocalOffset
		for _, p := range classPairs[i] {
			if p.Dest >= uint32(baseStringCount)+uint32(len(extraStrings)) {
				warnings = append(warnings, fmt.Sprintf("class %d pair dest id %d exceeds string_ids+extras bound %d (unresolved mapping)", i, p.Dest, uint32(baseStringCount)+uint32(len(extraStrings))))
			}
			if p.Src >= uint32(baseStringCount)+uint32(len(extraStrings)) {
				warnings = append(warnings, fmt.Sprintf("class %d pair src id %d exceeds string_ids+extras bound %d (unresolved mapping)", i, p.Src, uint32(baseStringCount)+uint32(len(extraStrings))))
			}
			body = encodeULEB128(body, p.Dest)
			body = encodeULEB128(body, p.Src)
		}
		currentLocalOffset = localOffsetBase + uint32(len(body))
	}
	offsets[classCount] = blockOffset + currentLocalOffset

	block := make([]byte, 0, len(body)+256)
	for _, off := range offsets {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], off)
		block = append(block, n[:]...)
	}
	block = append(block, body...)
	if aligned := align4(len(block)); aligned > len(block) {
		block = append(block, make([]byte, aligned-len(block))...)
	}

	strCount := len(extraStrings)
	block = appendUint32LE(block, uint32(strCount))
	offsetPos := len(block)
	for i := 0; i < strCount; i++ {
		block = appendUint32LE(block, 0)
	}
	stringBlob := make([]byte, 0)
	dataStart := len(block)
	for i, s := range extraStrings {
		// Extra string offsets are section-absolute.
		stringBlobOffsets := int(blockOffset) + dataStart + len(stringBlob)
		binary.LittleEndian.PutUint32(block[offsetPos+i*4:], uint32(stringBlobOffsets))
		stringBlob = append(stringBlob, []byte(s)...)
		stringBlob = append(stringBlob, 0)
	}
	block = append(block, stringBlob...)
	return block, warnings, nil
}

func appendUint32LE(out []byte, v uint32) []byte {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], v)
	return append(out, n[:]...)
}

func writeOutputFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()

	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}

	if err = os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func encodeULEB128(out []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

func strictMatchingWarnings(warnings []string, filter string) ([]string, []string) {
	if len(warnings) == 0 {
		return nil, nil
	}
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return append([]string(nil), warnings...), nil
	}
	raw := strings.Split(filter, ",")
	containsPatterns := make([]string, 0, len(raw))
	regexPatterns := make([]*regexp.Regexp, 0, len(raw))
	filterWarnings := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			lower := strings.ToLower(p)
			if strings.HasPrefix(lower, "re:") {
				reSrc := strings.TrimSpace(p[3:])
				if reSrc == "" {
					filterWarnings = append(filterWarnings, `invalid --strict-warn regex pattern "re:" has empty expression`)
					continue
				}
				re, err := regexp.Compile("(?i)" + reSrc)
				if err == nil {
					regexPatterns = append(regexPatterns, re)
					continue
				}
				filterWarnings = append(filterWarnings, fmt.Sprintf("invalid --strict-warn regex %q: %v", reSrc, err))
				containsPatterns = append(containsPatterns, strings.ToLower(reSrc))
				continue
			}
			containsPatterns = append(containsPatterns, lower)
		}
	}
	if len(containsPatterns) == 0 && len(regexPatterns) == 0 {
		return nil, filterWarnings
	}

	out := make([]string, 0, len(warnings))
	for _, w := range warnings {
		lw := strings.ToLower(w)
		matched := false
		for _, p := range containsPatterns {
			if strings.Contains(lw, p) {
				matched = true
				break
			}
		}
		if !matched {
			for _, re := range regexPatterns {
				if re.MatchString(w) {
					matched = true
					break
				}
			}
		}
		if matched {
			out = append(out, w)
			continue
		}
	}
	return out, filterWarnings
}

func newParserMeanings() *parserMeanings {
	return &parserMeanings{
		VdexFile: struct {
			Magic              string `json:"magic"`
			Version            string `json:"version"`
			Sections           string `json:"sections"`
			Checksums          string `json:"checksums"`
			DexFiles           string `json:"dex_files"`
			Verifier           string `json:"verifier_deps"`
			TypeLookup         string `json:"type_lookup"`
			Warnings           string `json:"warnings"`
			WarningsByCategory string `json:"warnings_by_category"`
			Errors             string `json:"errors"`
			SchemaVer          string `json:"schema_version"`
		}{
			Magic:              "Vdex header magic (must be 'vdex')",
			Version:            "Vdex format version, currently '027' expected",
			Sections:           "Section table entries for checksum, dex, verifier_deps, type_lookup",
			Checksums:          "Concatenated checksum array, one entry per embedded dex",
			DexFiles:           "Parsed DEX payload metadata and preview classes",
			Verifier:           "Verifier dependency section summary per dex",
			TypeLookup:         "Type lookup table section summary per dex",
			Warnings:           "Non-fatal parse anomalies collected during analysis",
			WarningsByCategory: "Warnings grouped by parser-defined categories",
			Errors:             "Fatal parse errors",
			SchemaVer:          "CLI output schema version",
		},
		SectionKind: map[string]string{
			"0":  "kChecksumSection",
			"1":  "kDexFileSection",
			"2":  "kVerifierDepsSection",
			"3":  "kTypeLookupTableSection",
			"8":  "kDebugInfoSection (ART variants)",
			"9":  "kProfilingInfoSection (ART variants)",
			"10": "kClassInfoSection (ART variants)",
		},
		DexHeader: struct {
			Magic        string `json:"magic"`
			Version      string `json:"version"`
			Checksum     string `json:"checksum_field"`
			Signature    string `json:"signature"`
			FileSize     string `json:"file_size"`
			HeaderSize   string `json:"header_size"`
			Endian       string `json:"endian"`
			StringIds    string `json:"string_ids_size"`
			StringIdsOff string `json:"string_ids_off"`
			TypeIds      string `json:"type_ids_size"`
			TypeIdsOff   string `json:"type_ids_off"`
			ProtoIds     string `json:"proto_ids_size"`
			ProtoIdsOff  string `json:"proto_ids_off"`
			FieldIds     string `json:"field_ids_size"`
			FieldIdsOff  string `json:"field_ids_off"`
			MethodIds    string `json:"method_ids_size"`
			MethodIdsOff string `json:"method_ids_off"`
			ClassDefs    string `json:"class_defs_size"`
			ClassDefsOff string `json:"class_defs_off"`
			DataSize     string `json:"data_size"`
			DataOffset   string `json:"data_offset"`
			ClassPreview string `json:"class_def_preview"`
		}{
			Magic:        "DEX magic header 'dex\\n'",
			Version:      "DEX format version",
			Checksum:     "adler-style checksum from DEX header (checksum_field)",
			Signature:    "SHA-1 signature of the DEX file (20 bytes at offset 0x0C)",
			FileSize:     "Total DEX file size in bytes",
			HeaderSize:   "Size of dex header",
			Endian:       "Byte order indicated by endian_tag",
			StringIds:    "Number of string_ids entries",
			StringIdsOff: "Offset of string_ids table in DEX",
			TypeIds:      "Number of type_ids entries",
			TypeIdsOff:   "Offset of type_ids table in DEX",
			ProtoIds:     "Number of proto_ids entries",
			ProtoIdsOff:  "Offset of proto_ids table in DEX",
			FieldIds:     "Number of field_ids entries",
			FieldIdsOff:  "Offset of field_ids table in DEX",
			MethodIds:    "Number of method_ids entries",
			MethodIdsOff: "Offset of method_ids table in DEX",
			ClassDefs:    "Number of class_defs entries",
			ClassDefsOff: "Offset of class_defs table in DEX",
			DataSize:     "Size of data section",
			DataOffset:   "Offset of data section",
			ClassPreview: "Top class_def descriptors preview (for human inspection)",
		},
		VerifierDeps: struct {
			Offset            string `json:"offset"`
			Size              string `json:"size"`
			VerifiedClasses   string `json:"verified_classes"`
			UnverifiedClasses string `json:"unverified_classes"`
			AssignabilityPair string `json:"assignability_pairs"`
			ExtraStringCount  string `json:"extra_string_count"`
			FirstPairs        string `json:"first_pairs"`
		}{
			Offset:            "Offset of per-dex verifier section blob",
			Size:              "Size of per-dex verifier section blob",
			VerifiedClasses:   "Number of classes verified by verifier",
			UnverifiedClasses: "Number of classes with 'not verified' marker",
			AssignabilityPair: "Pairs linking class definitions and source type ids",
			ExtraStringCount:  "Number of extra strings for verifier IDs resolution",
			FirstPairs:        "Preview of assignability pair entries",
		},
		TypeLookup: struct {
			Offset          string `json:"offset"`
			Size            string `json:"size"`
			RawSize         string `json:"raw_size"`
			BucketCount     string `json:"bucket_count"`
			EntryCount      string `json:"entry_count"`
			NonEmptyBuckets string `json:"non_empty_buckets"`
			MaxChainLen     string `json:"max_chain_len"`
			AvgChainLen     string `json:"avg_chain_len"`
			SampleEntries   string `json:"sample_entries"`
		}{
			Offset:          "Offset for this dex type_lookup block",
			Size:            "Size for this dex type_lookup block",
			RawSize:         "Raw payload size",
			BucketCount:     "Number of buckets in table",
			EntryCount:      "How many entries were parsed",
			NonEmptyBuckets: "Buckets containing at least one descriptor entry",
			MaxChainLen:     "Maximum chain traverse length while decoding linked slots",
			AvgChainLen:     "Average chain length for visited chains",
			SampleEntries:   "Descriptor samples for quick inspection",
		},
	}
}

func parseVdex(path string) (*vdexReport, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	r := &vdexReport{
		File:          filepath.Clean(path),
		Size:          len(raw),
		SchemaVersion: vdexSchemaVersion,
	}
	if showMeanings {
		r.Meanings = newParserMeanings()
	}

	if len(raw) < 12 {
		r.Errors = append(r.Errors, "file shorter than VDEX header")
		return r, raw, fmt.Errorf("file too small")
	}

	r.Header = vdexHeader{
		Magic:       string(raw[0:4]),
		Version:     string(bytes.TrimRight(raw[4:8], "\x00")),
		NumSections: binary.LittleEndian.Uint32(raw[8:12]),
	}
	if r.Header.Magic != "vdex" {
		r.Errors = append(r.Errors, fmt.Sprintf("invalid magic: %q", r.Header.Magic))
	}
	if r.Header.Version != vdexCurrentVersion {
		r.Warnings = append(r.Warnings, fmt.Sprintf("expected version %q, got %q", vdexCurrentVersion, r.Header.Version))
	}

	headerEnd := int(12 + r.Header.NumSections*12)
	if len(raw) < headerEnd {
		r.Errors = append(r.Errors, "file too small for section header table")
		return r, raw, fmt.Errorf("bad header table size")
	}

	sections, secIndex, err := parseSections(raw[12:headerEnd], r.Header.NumSections)
	if err != nil {
		r.Warnings = append(r.Warnings, err.Error())
	}
	r.Sections = sections
	r.Warnings = append(r.Warnings, validateSections(len(raw), sections)...)

	// Checksum section
	if idx, ok := secIndex[sectionChecksum]; ok {
		s := sections[idx]
		if s.Offset+s.Size > uint32(len(raw)) {
			r.Errors = append(r.Errors, "checksum section exceeds file")
		} else {
			if s.Size%4 != 0 {
				r.Warnings = append(r.Warnings, "checksum section size is not multiple of 4")
			}
			for i := 0; i < int(s.Size)/4; i++ {
				o := int(s.Offset) + i*4
				r.Checksums = append(r.Checksums, binary.LittleEndian.Uint32(raw[o:o+4]))
			}
		}
	}

	// Dex section
	var dexContexts []*dexContext
	var dexWarnings []string
	if idx, ok := secIndex[sectionDex]; ok {
		dexContexts, dexWarnings = parseDexSection(raw, sections[idx], len(r.Checksums))
		r.Warnings = append(r.Warnings, dexWarnings...)
	}
	for _, d := range dexContexts {
		rep := d.rep
		if rep.Index < len(r.Checksums) {
			rep.Checksum = r.Checksums[rep.Index]
		}
		r.Dexes = append(r.Dexes, rep)
	}

	if len(r.Checksums) == 0 {
		r.Warnings = append(r.Warnings, "no checksum section; infer dex count from parsed dex section")
	}

	expected := len(r.Checksums)
	if expected == 0 {
		expected = len(dexContexts)
	}
	if idx, ok := secIndex[sectionVerifierDeps]; ok {
		rep, ws := parseVerifierSection(raw, sections[idx], dexContexts, expected)
		r.Verifier = rep
		r.Warnings = append(r.Warnings, ws...)
	}
	if idx, ok := secIndex[sectionTypeLookup]; ok {
		rep, ws := parseTypeLookupSection(raw, sections[idx], dexContexts, expected)
		r.TypeLookup = rep
		r.Warnings = append(r.Warnings, ws...)
	}

	// Byte coverage
	r.Coverage = computeByteCoverage(len(raw), r.Header, r.Sections, r.Dexes)

	if len(r.Errors) > 0 {
		return r, raw, fmt.Errorf("parse ended with errors")
	}
	return r, raw, nil
}

func parseSections(buf []byte, count uint32) ([]vdexSection, map[uint32]int, error) {
	sections := make([]vdexSection, 0, count)
	index := map[uint32]int{}
	var err error
	for i := uint32(0); i < count; i++ {
		base := int(i) * 12
		kind := binary.LittleEndian.Uint32(buf[base : base+4])
		offset := binary.LittleEndian.Uint32(buf[base+4 : base+8])
		size := binary.LittleEndian.Uint32(buf[base+8 : base+12])
		item := vdexSection{
			Kind:    kind,
			Offset:  offset,
			Size:    size,
			Name:    sectionName[kind],
			Meaning: sectionMeaning[kind],
		}
		if item.Name == "" {
			item.Name = fmt.Sprintf("unknown(%d)", kind)
			item.Meaning = "unknown section kind"
		}
		if _, exists := index[kind]; exists && err == nil {
			err = fmt.Errorf("duplicate section kind %d (only first occurrence used)", kind)
		}
		if _, exists := index[kind]; !exists {
			index[kind] = int(i)
		}
		sections = append(sections, item)
	}
	return sections, index, err
}

func validateSections(fileSize int, sections []vdexSection) []string {
	warnings := []string{}
	for i, s := range sections {
		start := int(s.Offset)
		end := int(uint64(s.Offset) + uint64(s.Size))
		if start < 0 || start > fileSize {
			warnings = append(warnings, fmt.Sprintf("section kind %d starts beyond file size: %#x", s.Kind, s.Offset))
			continue
		}
		if end > fileSize {
			warnings = append(warnings, fmt.Sprintf("section kind %d exceeds file size: off=%#x size=%#x", s.Kind, s.Offset, s.Size))
			continue
		}
		if s.Size == 0 {
			warnings = append(warnings, fmt.Sprintf("section kind %d has zero size", s.Kind))
		}
		for j := 0; j < i; j++ {
			other := sections[j]
			otherStart := int(other.Offset)
			otherEnd := int(uint64(other.Offset) + uint64(other.Size))
			if other.Size == 0 || s.Size == 0 {
				continue
			}
			if start < otherEnd && otherStart < end {
				warnings = append(warnings, fmt.Sprintf("section kind %d overlaps section kind %d", s.Kind, other.Kind))
			}
		}
	}
	return warnings
}

func parseDexSection(raw []byte, s vdexSection, expected int) ([]*dexContext, []string) {
	out := []*dexContext{}
	warnings := []string{}
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end > len(raw) || start >= end {
		warnings = append(warnings, "dex section out of file range")
		return out, warnings
	}

	cursor := start
	for (expected == 0 && cursor < end) || (expected > 0 && len(out) < expected) {
		if cursor+0x70 > end {
			warnings = append(warnings, "truncated dex header in dex section")
			break
		}
		nextIdx := len(out)
		ctx, used, err := parseDex(raw[cursor:end], cursor)
		if ctx != nil {
			ctx.rep.Index = nextIdx
			if int(ctx.rep.Offset)+int(ctx.rep.Size) > end {
				ctx.rep.Size = uint32(end - int(ctx.rep.Offset))
				used = end - int(ctx.rep.Offset)
				warnings = append(warnings, fmt.Sprintf("dex[%d]: file_size exceeds dex section, truncated to %#x", nextIdx, ctx.rep.Size))
			}
			out = append(out, ctx)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("dex[%d]: %v", nextIdx, err))
		}
		if used <= 0 {
			break
		}
		cursor += used
		cursor = align4(cursor)
		if cursor > end {
			break
		}
	}
	return out, warnings
}

func parseDex(raw []byte, fileOffset int) (*dexContext, int, error) {
	if len(raw) < 0x70 {
		return nil, 0, fmt.Errorf("dex tail shorter than header")
	}
	if !bytes.Equal(raw[0:4], []byte("dex\n")) {
		return nil, 0, fmt.Errorf("invalid magic %q", string(raw[0:4]))
	}

	fileSize := readU32(raw, 0x20)
	if fileSize < 0x70 {
		return nil, 0, fmt.Errorf("invalid file_size %d", fileSize)
	}
	declaredFileSize := fileSize
	effectiveFileSize := fileSize
	if int(effectiveFileSize) > len(raw) {
		effectiveFileSize = uint32(len(raw))
	}

	// SHA-1 signature: 20 bytes at offset 0x0C
	sig := fmt.Sprintf("%x", raw[0x0C:0x20])

	stringIdsOff := readU32(raw, 0x3C)
	typeIdsOff := readU32(raw, 0x44)
	protoIdsOff := readU32(raw, 0x4C)
	fieldIdsOff := readU32(raw, 0x54)
	methodIdsOff := readU32(raw, 0x5C)
	classDefsOff := readU32(raw, 0x64)

	dex := &dexContext{
		rep: dexReport{
			Offset:       uint32(fileOffset),
			Size:         effectiveFileSize,
			Magic:        string(raw[0:4]),
			Version:      string(bytes.TrimRight(raw[4:8], "\x00")),
			ChecksumId:   readU32(raw, 0x08),
			Signature:    sig,
			FileSize:     effectiveFileSize,
			HeaderSize:   readU32(raw, 0x24),
			Endian:       "big-endian",
			LinkSize:     readU32(raw, 0x2C),
			LinkOffset:   readU32(raw, 0x30),
			MapOffset:    readU32(raw, 0x34),
			StringIds:    readU32(raw, 0x38),
			StringIdsOff: stringIdsOff,
			TypeIds:      readU32(raw, 0x40),
			TypeIdsOff:   typeIdsOff,
			ProtoIds:     readU32(raw, 0x48),
			ProtoIdsOff:  protoIdsOff,
			FieldIds:     readU32(raw, 0x50),
			FieldIdsOff:  fieldIdsOff,
			MethodIds:    readU32(raw, 0x58),
			MethodIdsOff: methodIdsOff,
			ClassDefs:    readU32(raw, 0x60),
			ClassDefsOff: classDefsOff,
			DataSize:     readU32(raw, 0x68),
			DataOffset:   readU32(raw, 0x6C),
		},
		stringOffsetToName: map[uint32]string{},
	}
	dexEndianTag := readU32(raw, 0x28)
	if dexEndianTag == 0x12345678 {
		dex.rep.Endian = "little-endian"
	} else if dexEndianTag == 0x78563412 {
		dex.rep.Endian = "big-endian"
	}

	stringIds := int(dex.rep.StringIds)
	strings, m, serr := parseDexStrings(raw[:effectiveFileSize], stringIds, int(stringIdsOff))
	dex.strings = strings
	dex.stringOffsetToName = m
	if serr != nil {
		return dex, int(effectiveFileSize), serr
	}

	typeIds := int(dex.rep.TypeIds)
	classDefsSize := int(dex.rep.ClassDefs)
	classes, cErr := parseDexClassDefs(raw[:effectiveFileSize], strings, typeIds, int(typeIdsOff), int(classDefsOff), classDefsSize)
	dex.rep.Classes = classes
	if cErr != nil {
		return dex, int(effectiveFileSize), cErr
	}

	if declaredFileSize != effectiveFileSize {
		return dex, int(effectiveFileSize), fmt.Errorf("declared file_size %#x exceeds available bytes", declaredFileSize)
	}
	if int(dex.rep.HeaderSize) > int(effectiveFileSize) {
		return dex, int(effectiveFileSize), fmt.Errorf("header_size %#x exceeds file_size", dex.rep.HeaderSize)
	}
	return dex, int(effectiveFileSize), nil
}

func parseDexStrings(raw []byte, stringCount int, stringIdOff int) ([]string, map[uint32]string, error) {
	if stringCount == 0 {
		return []string{}, map[uint32]string{}, nil
	}
	if stringIdOff < 0 || stringIdOff+stringCount*4 > len(raw) {
		return nil, nil, fmt.Errorf("invalid string_ids table range")
	}
	out := make([]string, stringCount)
	offsetMap := make(map[uint32]string, stringCount)
	for i := 0; i < stringCount; i++ {
		off := int(readU32(raw, stringIdOff+i*4))
		if off < 0 || off >= len(raw) {
			return out, offsetMap, fmt.Errorf("string_id[%d] points to invalid offset %#x", i, off)
		}
		s, _, err := parseModifiedUtf8(raw, off)
		if err != nil {
			return out, offsetMap, fmt.Errorf("string_id[%d]: %w", i, err)
		}
		out[i] = s
		offsetMap[uint32(off)] = s
	}
	return out, offsetMap, nil
}

func parseModifiedUtf8(raw []byte, off int) (string, int, error) {
	if off < 0 || off >= len(raw) {
		return "", 0, fmt.Errorf("string offset invalid")
	}
	_, l, err := readULEB128(raw, off)
	if err != nil {
		return "", 0, err
	}
	start := off + l
	if start >= len(raw) {
		return "", 0, fmt.Errorf("malformed modified UTF-8")
	}
	n := bytes.IndexByte(raw[start:], 0)
	if n < 0 {
		return "", 0, fmt.Errorf("unterminated string")
	}
	return string(raw[start : start+n]), l + n + 1, nil
}

func parseDexClassDefs(raw []byte, strings []string, typeIds int, typeIdsOff int, classDefsOff int, classDefsSize int) ([]string, error) {
	if classDefsSize == 0 {
		return nil, nil
	}
	if typeIdsOff < 0 || typeIdsOff+typeIds*4 > len(raw) {
		return nil, fmt.Errorf("invalid type_ids range")
	}
	if classDefsOff < 0 || classDefsOff+classDefsSize*32 > len(raw) {
		return nil, fmt.Errorf("invalid class_defs range")
	}

	out := make([]string, 0, minInt(classDefsSize, maxClassPreview))
	for i := 0; i < classDefsSize; i++ {
		base := classDefsOff + i*32
		classTypeIdx := int(readU32(raw, base))
		desc := fmt.Sprintf("<invalid class_idx=%d>", classTypeIdx)
		if classTypeIdx >= 0 && classTypeIdx < typeIds {
			typeIdxOff := typeIdsOff + classTypeIdx*4
			stringIdx := int(readU32(raw, typeIdxOff))
			if stringIdx >= 0 && stringIdx < len(strings) {
				desc = strings[stringIdx]
			}
		}
		if i < maxClassPreview {
			out = append(out, desc)
		}
	}
	return out, nil
}

func parseVerifierSection(raw []byte, s vdexSection, dexes []*dexContext, expected int) (*verifierReport, []string) {
	out := &verifierReport{
		Offset: s.Offset,
		Size:   s.Size,
	}
	warnings := []string{}
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end > len(raw) {
		warnings = append(warnings, "verifier-deps section out of file range")
		return out, warnings
	}
	if expected == 0 {
		expected = len(dexes)
	}

	for i := 0; i < expected; i++ {
		indexOff := start + i*4
		if indexOff+4 > end {
			warnings = append(warnings, fmt.Sprintf("verifier section index table truncated at dex %d", i))
			break
		}
		relative := int(readU32(raw, indexOff))
		blockOff := start + relative
		if blockOff < start || blockOff >= end {
			warnings = append(warnings, fmt.Sprintf("verifier block %d offset %#x outside section", i, relative))
			continue
		}
		rep, ws := parseVerifierDex(raw, start, blockOff, end, i, dexes)
		out.Dexes = append(out.Dexes, rep)
		warnings = append(warnings, ws...)
	}
	return out, warnings
}

func parseVerifierDex(raw []byte, sectionStart int, blockStart int, sectionEnd int, dexIdx int, dexes []*dexContext) (verifierDexReport, []string) {
	out := verifierDexReport{DexIndex: dexIdx}
	warnings := []string{}

	numClass := 0
	var baseStrings []string
	if dexIdx < len(dexes) {
		numClass = int(dexes[dexIdx].rep.ClassDefs)
		baseStrings = dexes[dexIdx].strings
	}

	if blockStart+4*(numClass+1) > sectionEnd {
		warnings = append(warnings, fmt.Sprintf("dex %d verifier block truncated", dexIdx))
		return out, warnings
	}

	offsets := make([]uint32, numClass+1)
	for i := 0; i <= numClass; i++ {
		offsets[i] = readU32(raw, blockStart+i*4)
	}

	type rawPair struct {
		class uint32
		dest  uint32
		src   uint32
	}
	pairs := make([]rawPair, 0, 64)
	// Offsets in the class-def table are section-absolute (relative to verifier
	// section start), matching the ART runtime encoding in EncodeSetVector /
	// DecodeSetVector.  Initialize maxSetEnd to the first byte after the
	// class-offset table so that alignment for extra-strings is at least past
	// that table.
	maxSetEnd := blockStart + 4*(numClass+1)
	nextValid := 1

	for classIdx := 0; classIdx < numClass; classIdx++ {
		o := offsets[classIdx]
		if o == notVerifiedMarker {
			out.UnverifiedClasses++
			continue
		}
		out.VerifiedClasses++

		for nextValid <= classIdx || (nextValid <= numClass && offsets[nextValid] == notVerifiedMarker) {
			nextValid++
			if nextValid > numClass {
				warnings = append(warnings, fmt.Sprintf("dex %d class %d malformed class offset chain", dexIdx, classIdx))
				return out, warnings
			}
		}
		// Section-absolute offsets: base is sectionStart, not blockStart.
		setStart := sectionStart + int(o)
		setEnd := sectionStart + int(offsets[nextValid])
		if setStart < blockStart || setEnd > sectionEnd || setEnd < setStart {
			warnings = append(warnings, fmt.Sprintf("dex %d class %d malformed set bounds", dexIdx, classIdx))
			continue
		}
		cursor := setStart
		if cursor > maxSetEnd {
			maxSetEnd = cursor
		}
		for cursor < setEnd {
			dest, n, err := readULEB128(raw, cursor)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("dex %d class %d invalid destination leb128", dexIdx, classIdx))
				break
			}
			cursor += n
			src, n, err := readULEB128(raw, cursor)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("dex %d class %d invalid source leb128", dexIdx, classIdx))
				break
			}
			cursor += n
			pairs = append(pairs, rawPair{class: uint32(classIdx), dest: dest, src: src})
			out.AssignabilityPairs++
		}
		if setEnd > maxSetEnd {
			maxSetEnd = setEnd
		}
	}

	cursor := align4(maxSetEnd)
	if cursor+4 > sectionEnd {
		out.ExtraStringCount = 0
		return out, warnings
	}
	numStrings := int(readU32(raw, cursor))
	cursor += 4
	if cursor+numStrings*4 > sectionEnd {
		warnings = append(warnings, fmt.Sprintf("dex %d verifier extra strings table truncated", dexIdx))
		out.ExtraStringCount = 0
		return out, warnings
	}

	extras := make([]string, numStrings)
	for i := 0; i < numStrings; i++ {
		// Extra string offsets are section-absolute (relative to verifier
		// section start), matching ART's EncodeStringVector / DecodeStringVector.
		rel := int(readU32(raw, cursor+i*4))
		abs := sectionStart + rel
		if abs < blockStart || abs >= sectionEnd {
			extras[i] = fmt.Sprintf("invalid_%d", i)
			warnings = append(warnings, fmt.Sprintf("dex %d extra string %d offset %#x invalid", dexIdx, i, rel))
			continue
		}
		extras[i] = readCString(raw[abs:sectionEnd])
	}
	out.ExtraStringCount = len(extras)

	extraBase := uint32(len(baseStrings))
	for i := 0; i < len(pairs) && i < maxVerifierPairs; i++ {
		p := pairs[i]
		out.FirstPairs = append(out.FirstPairs, verifierPair{
			ClassDefIndex: p.class,
			DestID:        p.dest,
			Dest:          resolveVerifierString(baseStrings, extras, extraBase, p.dest),
			SrcID:         p.src,
			Src:           resolveVerifierString(baseStrings, extras, extraBase, p.src),
		})
	}

	return out, warnings
}

func resolveVerifierString(dexStrings []string, extras []string, extraBase uint32, id uint32) string {
	if int(id) < len(dexStrings) {
		return dexStrings[id]
	}
	rel := int(id - extraBase)
	if id >= extraBase && rel >= 0 && rel < len(extras) {
		return extras[rel]
	}
	return fmt.Sprintf("string_%d", id)
}

func parseTypeLookupSection(raw []byte, s vdexSection, dexes []*dexContext, expected int) (*typeLookupReport, []string) {
	out := &typeLookupReport{
		Offset: s.Offset,
		Size:   s.Size,
	}
	warnings := []string{}
	start := int(s.Offset)
	end := start + int(s.Size)
	if start < 0 || end > len(raw) {
		warnings = append(warnings, "type-lookup section out of file range")
		return out, warnings
	}
	if expected == 0 {
		expected = len(dexes)
	}

	cursor := start
	for i := 0; i < expected; i++ {
		if cursor+4 > end {
			warnings = append(warnings, fmt.Sprintf("type-lookup section truncated before dex %d", i))
			break
		}
		size := int(readU32(raw, cursor))
		cursor += 4
		if cursor+size > end {
			warnings = append(warnings, fmt.Sprintf("type-lookup dex %d size %d exceeds section", i, size))
			break
		}
		var d *dexContext
		if i < len(dexes) {
			d = dexes[i]
		}
		rep := parseTypeLookupDex(raw[cursor:cursor+size], d)
		rep.DexIndex = i
		out.Dexes = append(out.Dexes, rep)
		cursor += size
	}
	return out, warnings
}

func parseTypeLookupDex(raw []byte, dex *dexContext) typeLookupDexReport {
	out := typeLookupDexReport{
		RawSize: uint32(len(raw)),
	}
	if len(raw) == 0 {
		out.Warnings = append(out.Warnings, "empty payload")
		return out
	}
	if len(raw)%8 != 0 {
		out.Warnings = append(out.Warnings, "payload size is not aligned to 8-byte entries; last entry may be truncated")
		raw = raw[:len(raw)-(len(raw)%8)]
	}

	buckets := len(raw) / 8
	out.BucketCount = buckets
	if buckets == 0 {
		out.Warnings = append(out.Warnings, "empty table")
		return out
	}

	classDefs := uint32(0)
	if dex != nil {
		classDefs = dex.rep.ClassDefs
	}
	if classDefs == 0 {
		out.Warnings = append(out.Warnings, "class_defs_size is 0; decode limited")
	}
	if classDefs > maxTypeLookupClasses {
		out.Warnings = append(out.Warnings, fmt.Sprintf("unsupported class_defs_size=%d", classDefs))
	}
	maskBits := uint32(0)
	rawBits := uint32(0)
	if classDefs > 0 {
		capped := classDefs
		if capped > maxTypeLookupClasses {
			capped = maxTypeLookupClasses
		}
		rawBits = minimumBitsToStore(capped - 1)
		maskBits = rawBits
	}
	if maskBits > 30 {
		maskBits = 30
		out.Warnings = append(out.Warnings, fmt.Sprintf("clamped type_lookup mask bits from %d to 30 for safety", rawBits))
	}
	out.MaskBits = maskBits
	mask := (uint32(1) << maskBits) - 1
	if maskBits == 0 {
		mask = 0
	}

	samples := make([]typeLookupSample, 0, minInt(buckets, maxTypeLookupSamples))
	maxChain := 0
	totalChain := 0
	chainCount := 0
	for i := 0; i < buckets; i++ {
		base := i * 8
		offset := readU32(raw, base)
		packed := readU32(raw, base+4)

		if offset == 0 {
			continue
		}
		out.NonEmptyBuckets++
		classIdx := uint32(0)
		if maskBits > 0 {
			classIdx = (packed >> maskBits) & mask
		}
		nextDelta := packed & mask
		desc := ""
		if dex != nil {
			desc = dex.stringOffsetToName[offset]
		}
		if desc == "" {
			desc = fmt.Sprintf("<string_off_%#x>", offset)
		}
		out.EntryCount++
		if len(samples) < maxTypeLookupSamples {
			samples = append(samples, typeLookupSample{
				Bucket:       uint32(i),
				ClassDef:     classIdx,
				StringOffset: offset,
				NextDelta:    nextDelta,
				HashBits:     packed >> (2 * maskBits),
				Descriptor:   desc,
			})
		}

		// Chain stats
		pos := i
		chainLen := 0
		visited := make([]bool, buckets)
		for j := 0; j < buckets+1; j++ {
			if visited[pos] {
				out.Warnings = append(out.Warnings, "cycle detected in lookup chain")
				break
			}
			visited[pos] = true
			eOffset := readU32(raw, pos*8)
			if eOffset == 0 {
				break
			}
			ePacked := readU32(raw, pos*8+4)
			next := uint32(0)
			if maskBits == 0 {
				next = 0
			} else {
				next = ePacked & mask
			}
			chainLen++
			if next == 0 {
				break
			}
			pos = (pos + int(next)) % buckets
		}
		if chainLen > maxChain {
			maxChain = chainLen
		}
		totalChain += chainLen
		chainCount++
	}
	out.Samples = samples
	out.MaxChainLen = maxChain
	if chainCount > 0 {
		out.AvgChainLen = float64(totalChain) / float64(chainCount)
	}
	return out
}

func readULEB128(raw []byte, off int) (uint32, int, error) {
	var value uint32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(raw) {
			return 0, 0, fmt.Errorf("uleb128 out of bounds")
		}
		b := raw[off+i]
		value |= uint32(b&0x7f) << shift
		if (b & 0x80) == 0 {
			return value, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("uleb128 overflow")
}

func readCString(raw []byte) string {
	n := bytes.IndexByte(raw, 0)
	if n < 0 {
		return string(raw)
	}
	return string(raw[:n])
}

func readU32(raw []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(raw[off : off+4])
}

func minimumBitsToStore(v uint32) uint32 {
	if v == 0 {
		return 0
	}
	return uint32(bits.Len32(v))
}

func appendModifyLog(path string, summary modifySummary, strictMatched []string, failureReason string, failureCategory string) error {
	modifiedDexes := make([]int, 0)
	topSamples := make([]string, 0)
	for _, d := range summary.DexDiffs {
		if d.ModifiedClasses > 0 {
			modifiedDexes = append(modifiedDexes, d.DexIndex)
			if len(topSamples) < 4 {
				topSamples = append(topSamples, fmt.Sprintf("dex=%d classes=%v", d.DexIndex, d.ChangedClassIdxs))
			}
		}
	}
	entry := modifyLogEntry{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Cmd:       os.Args,
		Summary:   summary,
		Args: map[string]string{
			"verifier_json": modifyVerifierPatch,
			"mode":          modifyMode,
			"dry_run":       fmt.Sprintf("%v", modifyDryRun),
			"quiet":         fmt.Sprintf("%v", modifyQuiet),
			"force":         fmt.Sprintf("%v", modifyForce),
			"strict":        fmt.Sprintf("%v", strictMode),
			"strict_warn":   strictWarn,
			"verify":        fmt.Sprintf("%v", modifyVerify),
			"log_file":      modifyLogPath,
		},
		ModifiedDexes:    modifiedDexes,
		TopSamples:       topSamples,
		ModifiedClassCount: summary.ModifiedClasses,
		StrictMatched: strictMatched,
		FailureReason: failureReason,
		FailureCategory: failureCategory,
		FailureCategoryCounts: summary.FailureCategoryCounts,
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(raw)
	return err
}

func computeByteCoverage(fileSize int, header vdexHeader, sections []vdexSection, dexes []dexReport) *byteCoverageReport {
	type rangeEntry struct {
		offset int
		size   int
		label  string
	}
	ranges := []rangeEntry{}

	// VDEX file header: 12 bytes
	headerSize := 12
	ranges = append(ranges, rangeEntry{0, headerSize, "vdex_header"})

	// Section header table
	sectionTableSize := int(header.NumSections) * 12
	ranges = append(ranges, rangeEntry{headerSize, sectionTableSize, "section_headers"})

	// Each section
	for _, s := range sections {
		if s.Size == 0 {
			continue
		}
		name := s.Name
		if name == "" {
			name = fmt.Sprintf("section_%d", s.Kind)
		}
		ranges = append(ranges, rangeEntry{int(s.Offset), int(s.Size), name})
	}

	// Sort by offset
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].offset < ranges[j].offset
	})

	// Remove overlaps (keep first)
	merged := make([]rangeEntry, 0, len(ranges))
	for _, r := range ranges {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			lastEnd := last.offset + last.size
			if r.offset < lastEnd {
				// Overlap: trim the new range
				overlap := lastEnd - r.offset
				if overlap >= r.size {
					continue // fully covered
				}
				r.offset = lastEnd
				r.size -= overlap
			}
		}
		merged = append(merged, r)
	}

	// Compute parsed bytes
	parsedBytes := 0
	outRanges := make([]byteCoverageRange, 0, len(merged))
	for _, r := range merged {
		parsedBytes += r.size
		outRanges = append(outRanges, byteCoverageRange{
			Offset: r.offset,
			Size:   r.size,
			Label:  r.label,
		})
	}

	// Find gaps
	gaps := []byteCoverageRange{}
	cursor := 0
	for _, r := range merged {
		if r.offset > cursor {
			gapSize := r.offset - cursor
			gaps = append(gaps, byteCoverageRange{
				Offset: cursor,
				Size:   gapSize,
				Label:  "gap/padding",
			})
		}
		end := r.offset + r.size
		if end > cursor {
			cursor = end
		}
	}
	if cursor < fileSize {
		gaps = append(gaps, byteCoverageRange{
			Offset: cursor,
			Size:   fileSize - cursor,
			Label:  "trailing_bytes",
		})
	}

	unparsed := fileSize - parsedBytes
	pct := 0.0
	if fileSize > 0 {
		pct = float64(parsedBytes) / float64(fileSize) * 100.0
	}

	return &byteCoverageReport{
		FileSize:        fileSize,
		ParsedBytes:     parsedBytes,
		UnparsedBytes:   unparsed,
		CoveragePercent: pct,
		Ranges:          outRanges,
		Gaps:            gaps,
	}
}

func calcPercent(v int, total int) float64 {
	if total <= 0 {
		return 0
	}
	return (float64(v) / float64(total)) * 100
}

func align4(v int) int {
	return (v + 3) &^ 3
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func uniquePath(baseDir, name string, used map[string]struct{}) string {
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	ext := filepath.Ext(name)
	candidate := name
	for idx := 1; ; idx++ {
		path := filepath.Join(baseDir, candidate)
		if _, existsUsed := used[path]; !existsUsed {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				used[path] = struct{}{}
				return path
			}
		}
		candidate = fmt.Sprintf("%s_%d%s", stem, idx, ext)
	}
}

func extractDex(vdexPath string, raw []byte, report *vdexReport, outDir string, nameTemplate string) (int, int, error) {
	if report == nil || len(report.Dexes) == 0 {
		return 0, 0, nil
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, len(report.Dexes), err
	}
	extracted := 0
	failed := 0
	usedPaths := map[string]struct{}{}
	base := filepath.Base(vdexPath)
	for _, d := range report.Dexes {
		start := int(d.Offset)
		end := start + int(d.Size)
		if start < 0 || end > len(raw) || end <= start {
			err := fmt.Errorf("dex[%d] invalid range %#x-%#x", d.Index, start, end)
			failed++
			if extractContinueOnError {
				fmt.Fprintf(os.Stderr, "warning: %v\n", err)
				continue
			}
			return extracted, failed, err
		}
		name, warnMsg, err := renderExtractName(nameTemplate, base, d)
		if err != nil {
			failed++
			if extractContinueOnError {
				fmt.Fprintf(os.Stderr, "warning: %v\n", err)
				continue
			}
			return extracted, failed, err
		}
		if warnMsg != "" {
			report.Warnings = append(report.Warnings, warnMsg)
		}
		path := uniquePath(outDir, name, usedPaths)
		if err := os.WriteFile(path, raw[start:end], 0o644); err != nil {
			if extractContinueOnError {
				failed++
				fmt.Fprintf(os.Stderr, "warning: failed to write dex[%d] -> %s: %v\n", d.Index, path, err)
				continue
			}
			return extracted, failed, err
		}
		extracted++
	}
	failed = len(report.Dexes) - extracted
	return extracted, failed, nil
}

func renderExtractName(template string, base string, d dexReport) (string, string, error) {
	if template == "" {
		template = defaultNameTemplate
	}
	repl := map[string]string{
		"base":        sanitizeFileToken(base),
		"index":       fmt.Sprintf("%d", d.Index),
		"checksum":    fmt.Sprintf("%d", d.Checksum),
		"checksum_hex": fmt.Sprintf("%#x", d.Checksum),
		"offset":      fmt.Sprintf("%#x", d.Offset),
		"size":        fmt.Sprintf("%#x", d.Size),
	}

	name := ""
	unknown := []string{}
	unknownSet := map[string]bool{}
	for i := 0; i < len(template); {
		if template[i] != '{' {
			name += string(template[i])
			i++
			continue
		}
		end := strings.IndexByte(template[i+1:], '}')
		if end < 0 {
			name += template[i:]
			break
		}
		end = i + 1 + end
		key := template[i+1 : end]
		if val, ok := repl[key]; ok {
			name += val
		} else {
			name += "{" + key + "}"
			if !unknownSet[key] {
				unknownSet[key] = true
				unknown = append(unknown, key)
			}
		}
		i = end + 1
	}

	if len(unknown) > 0 {
		fallback, _, _ := renderExtractName(defaultNameTemplate, base, d)
		warnMsg := fmt.Sprintf("unsupported --extract-name-template tokens %s; falling back to default template %q", strings.Join(unknown, ", "), defaultNameTemplate)
		warnOnce := false
		if !extractTemplateWarned {
			fmt.Fprintf(os.Stderr, "warning: %s\n", warnMsg)
			extractTemplateWarned = true
			warnOnce = true
		}
		if warnOnce {
			return fallback, warnMsg, nil
		}
		return fallback, "", nil
	}
	return name, "", nil
}

func sanitizeFileToken(v string) string {
	v = strings.ReplaceAll(v, string(filepath.Separator), "_")
	v = strings.ReplaceAll(v, "/", "_")
	v = strings.ReplaceAll(v, "\\", "_")
	return strings.TrimSpace(v)
}

func printText(r *vdexReport) {
	if r == nil {
		return
	}
	fmt.Printf("file: %s\nsize: %d bytes\n", r.File, r.Size)
	fmt.Printf("vdex magic=%q version=%q sections=%d\n", r.Header.Magic, r.Header.Version, r.Header.NumSections)
	if r.Meanings != nil {
		printTextMeanings(r.Meanings)
	}

	fmt.Println("sections:")
	for _, s := range r.Sections {
		fmt.Printf("  kind=%s (%d) off=%#x size=%#x\n", s.Name, s.Kind, s.Offset, s.Size)
		fmt.Printf("    %s\n", s.Meaning)
	}

	fmt.Printf("checksums: %d\n", len(r.Checksums))
	for i, v := range r.Checksums {
		fmt.Printf("  [%d]=%#x\n", i, v)
	}

	fmt.Printf("dex files: %d\n", len(r.Dexes))
	for _, d := range r.Dexes {
		fmt.Printf("  [%d] off=%#x size=%#x magic=%q ver=%q endian=%s file_size=%d header=%d\n",
			d.Index, d.Offset, d.Size, d.Magic, d.Version, d.Endian, d.FileSize, d.HeaderSize)
		fmt.Printf("     sha1=%s checksum=%#x\n", d.Signature, d.ChecksumId)
		fmt.Printf("     strings=%d(@%#x) types=%d(@%#x) protos=%d(@%#x) fields=%d(@%#x) methods=%d(@%#x) class_defs=%d(@%#x)\n",
			d.StringIds, d.StringIdsOff, d.TypeIds, d.TypeIdsOff,
			d.ProtoIds, d.ProtoIdsOff, d.FieldIds, d.FieldIdsOff,
			d.MethodIds, d.MethodIdsOff, d.ClassDefs, d.ClassDefsOff)
		if len(d.Classes) > 0 {
			fmt.Printf("     class preview: ")
			for _, c := range d.Classes {
				fmt.Printf("%s ", c)
			}
			if d.ClassDefs > uint32(len(d.Classes)) {
				fmt.Printf("...")
			}
			fmt.Println()
		}
	}

	if r.Verifier != nil {
		fmt.Printf("verifier_deps: off=%#x size=%#x\n", r.Verifier.Offset, r.Verifier.Size)
		for _, d := range r.Verifier.Dexes {
			fmt.Printf("  [dex %d] verified=%d unverified=%d pairs=%d extra_strings=%d\n",
				d.DexIndex, d.VerifiedClasses, d.UnverifiedClasses, d.AssignabilityPairs, d.ExtraStringCount)
			for _, p := range d.FirstPairs {
				fmt.Printf("    class %d: %s(%d) -> %s(%d)\n", p.ClassDefIndex, p.Dest, p.DestID, p.Src, p.SrcID)
			}
		}
	}

	if r.TypeLookup != nil {
		fmt.Printf("type_lookup: off=%#x size=%#x\n", r.TypeLookup.Offset, r.TypeLookup.Size)
		for _, d := range r.TypeLookup.Dexes {
			fmt.Printf("  [dex %d] raw=%d buckets=%d entries=%d non_empty=%d max_chain=%d avg_chain=%.2f\n",
				d.DexIndex, d.RawSize, d.BucketCount, d.EntryCount, d.NonEmptyBuckets, d.MaxChainLen, d.AvgChainLen)
			for _, s := range d.Samples {
				fmt.Printf("    bucket=%d class=%d desc=%s next=%d hashbits=%d\n", s.Bucket, s.ClassDef, s.Descriptor, s.NextDelta, s.HashBits)
			}
			for _, w := range d.Warnings {
				fmt.Printf("    warn: %s\n", w)
			}
		}
	}

	if r.Coverage != nil {
		c := r.Coverage
		fmt.Printf("byte_coverage: %d/%d bytes (%.1f%%)\n", c.ParsedBytes, c.FileSize, c.CoveragePercent)
		for _, rng := range c.Ranges {
			fmt.Printf("  %#08x..%#08x  %6d bytes  %s\n", rng.Offset, rng.Offset+rng.Size, rng.Size, rng.Label)
		}
		if len(c.Gaps) > 0 {
			fmt.Println("  gaps:")
			for _, g := range c.Gaps {
				fmt.Printf("    %#08x..%#08x  %6d bytes  %s\n", g.Offset, g.Offset+g.Size, g.Size, g.Label)
			}
		}
	}

	if len(r.Warnings) > 0 {
		printGroupedWarnings(r.Warnings)
	}
	if len(r.Errors) > 0 {
		fmt.Println("errors:")
		for _, e := range r.Errors {
			fmt.Printf("  ! %s\n", e)
		}
	}
}

func printTextMeanings(m *parserMeanings) {
	if m == nil {
		return
	}
	fmt.Println("meanings:")
	fmt.Println("  vdex_file:")
	fmt.Printf("    magic: %s\n", m.VdexFile.Magic)
	fmt.Printf("    version: %s\n", m.VdexFile.Version)
	fmt.Printf("    sections: %s\n", m.VdexFile.Sections)
	fmt.Printf("    checksums: %s\n", m.VdexFile.Checksums)
	fmt.Printf("    dex_files: %s\n", m.VdexFile.DexFiles)
	fmt.Printf("    verifier_deps: %s\n", m.VdexFile.Verifier)
	fmt.Printf("    type_lookup: %s\n", m.VdexFile.TypeLookup)
	fmt.Printf("    warnings: %s\n", m.VdexFile.Warnings)
	fmt.Printf("    warnings_by_category: %s\n", m.VdexFile.WarningsByCategory)
	fmt.Printf("    errors: %s\n", m.VdexFile.Errors)
	fmt.Printf("    schema_version: %s\n", m.VdexFile.SchemaVer)
	fmt.Println("    section_kind:")
	fmt.Printf("      0: %s\n", m.SectionKind["0"])
	fmt.Printf("      1: %s\n", m.SectionKind["1"])
	fmt.Printf("      2: %s\n", m.SectionKind["2"])
	fmt.Printf("      3: %s\n", m.SectionKind["3"])
	fmt.Printf("      8: %s\n", m.SectionKind["8"])
	fmt.Printf("      9: %s\n", m.SectionKind["9"])
	fmt.Printf("      10: %s\n", m.SectionKind["10"])
	fmt.Println("  dex_header:")
	fmt.Printf("    magic: %s\n", m.DexHeader.Magic)
	fmt.Printf("    version: %s\n", m.DexHeader.Version)
	fmt.Printf("    checksum_field: %s\n", m.DexHeader.Checksum)
	fmt.Printf("    file_size: %s\n", m.DexHeader.FileSize)
	fmt.Printf("    header_size: %s\n", m.DexHeader.HeaderSize)
	fmt.Printf("    endian: %s\n", m.DexHeader.Endian)
	fmt.Printf("    string_ids_size: %s\n", m.DexHeader.StringIds)
	fmt.Printf("    type_ids_size: %s\n", m.DexHeader.TypeIds)
	fmt.Printf("    proto_ids_size: %s\n", m.DexHeader.ProtoIds)
	fmt.Printf("    field_ids_size: %s\n", m.DexHeader.FieldIds)
	fmt.Printf("    method_ids_size: %s\n", m.DexHeader.MethodIds)
	fmt.Printf("    class_defs_size: %s\n", m.DexHeader.ClassDefs)
	fmt.Printf("    data_size: %s\n", m.DexHeader.DataSize)
	fmt.Printf("    data_offset: %s\n", m.DexHeader.DataOffset)
	fmt.Printf("    class_def_preview: %s\n", m.DexHeader.ClassPreview)
	fmt.Println("  verifier_deps:")
	fmt.Printf("    offset: %s\n", m.VerifierDeps.Offset)
	fmt.Printf("    size: %s\n", m.VerifierDeps.Size)
	fmt.Printf("    verified_classes: %s\n", m.VerifierDeps.VerifiedClasses)
	fmt.Printf("    unverified_classes: %s\n", m.VerifierDeps.UnverifiedClasses)
	fmt.Printf("    assignability_pairs: %s\n", m.VerifierDeps.AssignabilityPair)
	fmt.Printf("    extra_string_count: %s\n", m.VerifierDeps.ExtraStringCount)
	fmt.Printf("    first_pairs: %s\n", m.VerifierDeps.FirstPairs)
	fmt.Println("  type_lookup:")
	fmt.Printf("    offset: %s\n", m.TypeLookup.Offset)
	fmt.Printf("    size: %s\n", m.TypeLookup.Size)
	fmt.Printf("    raw_size: %s\n", m.TypeLookup.RawSize)
	fmt.Printf("    bucket_count: %s\n", m.TypeLookup.BucketCount)
	fmt.Printf("    entry_count: %s\n", m.TypeLookup.EntryCount)
	fmt.Printf("    non_empty_buckets: %s\n", m.TypeLookup.NonEmptyBuckets)
	fmt.Printf("    max_chain_len: %s\n", m.TypeLookup.MaxChainLen)
	fmt.Printf("    avg_chain_len: %s\n", m.TypeLookup.AvgChainLen)
	fmt.Printf("    sample_entries: %s\n", m.TypeLookup.SampleEntries)
}

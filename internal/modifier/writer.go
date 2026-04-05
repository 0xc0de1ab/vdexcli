package modifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/lo"

	"github.com/0xc0de1ab/vdexcli/internal/binutil"
	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// WriteOutputFileAtomic writes data to path via temp file + rename.
func WriteOutputFileAtomic(path string, data []byte) error {
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

// AppendModifyLog appends a structured NDJSON log entry for a modify operation.
func AppendModifyLog(path string, summary model.ModifySummary, cliArgs map[string]string, strictMatched []string, failureReason string, failureCategory string) error {
	changed := lo.Filter(summary.DexDiffs, func(d model.ModifyDexDiff, _ int) bool {
		return d.ModifiedClasses > 0
	})
	modifiedDexes := lo.Map(changed, func(d model.ModifyDexDiff, _ int) int { return d.DexIndex })
	topSamples := lo.Map(changed[:binutil.MinInt(len(changed), 4)], func(d model.ModifyDexDiff, _ int) string {
		return fmt.Sprintf("dex=%d classes=%v", d.DexIndex, d.ChangedClassIdxs)
	})
	entry := model.ModifyLogEntry{
		Timestamp:             time.Now().Format(time.RFC3339Nano),
		Cmd:                   os.Args,
		Summary:               summary,
		Args:                  cliArgs,
		ModifiedDexes:         modifiedDexes,
		TopSamples:            topSamples,
		ModifiedClassCount:    summary.ModifiedClasses,
		StrictMatched:         strictMatched,
		FailureReason:         failureReason,
		FailureCategory:       failureCategory,
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

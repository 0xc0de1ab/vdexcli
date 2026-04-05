package modifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// ParseVerifierPatch reads and validates a verifier patch from a file (or stdin with "-").
func ParseVerifierPatch(path string) (model.VerifierPatchSpec, []string, error) {
	out := model.VerifierPatchSpec{}
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
	if err := ValidateVerifierPatchIndices(out); err != nil {
		return out, nil, err
	}
	out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	switch out.Mode {
	case "replace", "merge", "":
	default:
		return out, nil, fmt.Errorf("unsupported patch mode %q; supported: replace, merge", out.Mode)
	}
	return out, nil, nil
}

// ValidateVerifierPatchIndices checks for negative or duplicate dex/class indices.
func ValidateVerifierPatchIndices(patch model.VerifierPatchSpec) error {
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

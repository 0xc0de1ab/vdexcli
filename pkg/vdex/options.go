package vdex

// Option configures parser behavior.
// Use functional option constructors (WithMeanings, WithDexPreview) to build
// an option set, then pass them to ParseBytes or ParseFile.
type Option func(*parseConfig)

type parseConfig struct {
	includeMeanings bool
	maxDexPreview   int
}

// WithMeanings enables human-readable field descriptions in the parsed Report.
// When set, Report.Meanings is populated with a field-meaning dictionary.
func WithMeanings() Option {
	return func(c *parseConfig) { c.includeMeanings = true }
}

// WithDexPreview limits how many DEX files are included in the report preview.
// Default is 5 (the first 5 DEX files). Pass -1 to include all.
func WithDexPreview(n int) Option {
	return func(c *parseConfig) { c.maxDexPreview = n }
}

func applyOptions(opts []Option) parseConfig {
	cfg := parseConfig{maxDexPreview: 5}
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

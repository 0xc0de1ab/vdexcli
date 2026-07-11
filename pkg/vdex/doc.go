// Package vdex provides a stable public API for parsing and explaining VDEX files.
//
// VDEX (Verified DEX) files are produced by the Android Runtime (ART) as a
// companion to APK/DEX files. They contain pre-verified class information,
// verifier dependency data, and type-lookup tables that accelerate class loading.
//
// # Quick Start
//
// Explain every byte of a VDEX file (WASM-compatible):
//
//	fm, err := vdex.ExplainBytes(data)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, f := range fm.Fields {
//	    fmt.Printf("%08x  %-14s  %s\n", f.Offset, f.Type, f.LogicalPath)
//	}
//
// Parse VDEX structure (non-WASM, filesystem):
//
//	report, err := vdex.ParseFile("/path/to/app.vdex", vdex.WithMeanings())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("version=%s dexes=%d\n", report.Header.Version, len(report.Dexes))
//
// # Stability
//
// This package follows semantic versioning. The API is currently at v0.x and
// may change before a stable v1.0 release. The underlying type aliases point
// to internal/model types; see types.go for the mapping.
package vdex

//go:build js

package presenter

// No-op color initializer for WASM/js builds.
// golang.org/x/term requires syscall support not available under GOOS=js.
// ANSI color codes are meaningless in JavaScript contexts anyway.
func init() {
	colorEnabled = false
}

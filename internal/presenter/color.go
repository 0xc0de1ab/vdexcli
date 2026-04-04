package presenter

import (
	"os"

	"golang.org/x/term"
)

// ANSI color codes. Only applied when output is a terminal.
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	cyan    = "\033[36m"
	white   = "\033[37m"
	boldRed = "\033[1;31m"
	boldGrn = "\033[1;32m"
	boldYlw = "\033[1;33m"
	boldCyn = "\033[1;36m"
	dimWht  = "\033[2;37m"
)

var colorEnabled bool

func init() {
	colorEnabled = term.IsTerminal(int(os.Stdout.Fd()))
}

// SetColor overrides auto-detection (for --color=always/never).
func SetColor(enabled bool) {
	colorEnabled = enabled
}

func c(code, text string) string {
	if !colorEnabled {
		return text
	}
	return code + text + reset
}

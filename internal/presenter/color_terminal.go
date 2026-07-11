//go:build !js

package presenter

import (
	"os"

	"golang.org/x/term"
)

func init() {
	colorEnabled = term.IsTerminal(int(os.Stdout.Fd()))
}

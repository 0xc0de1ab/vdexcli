package presenter

import "strconv"

// TerminalSafe preserves graphic Unicode while escaping control bytes and
// invalid UTF-8 so parsed input cannot emit terminal control sequences.
func TerminalSafe(value string) string {
	quoted := strconv.QuoteToGraphic(value)
	return quoted[1 : len(quoted)-1]
}

func terminalSafe(value string) string {
	return TerminalSafe(value)
}

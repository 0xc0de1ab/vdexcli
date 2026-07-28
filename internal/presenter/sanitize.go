package presenter

import "strconv"

// terminalSafe preserves graphic Unicode while escaping control bytes and
// invalid UTF-8 so parsed input cannot emit terminal control sequences.
func terminalSafe(value string) string {
	quoted := strconv.QuoteToGraphic(value)
	return quoted[1 : len(quoted)-1]
}

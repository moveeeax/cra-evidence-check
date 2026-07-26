package checks

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// maxDetailLines caps how many per-item lines a check emits, so that a repo
// with 400 unlocked manifests produces a readable report rather than a wall.
const maxDetailLines = 20

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func lower(s string) string { return strings.ToLower(s) }

// bullets renders items as detail lines, truncating with a count.
func bullets(items []string) []string {
	sort.Strings(items)
	if len(items) <= maxDetailLines {
		return items
	}
	out := append([]string(nil), items[:maxDetailLines]...)
	return append(out, fmt.Sprintf("... and %d more", len(items)-maxDetailLines))
}

// plural returns "1 thing" / "3 things".
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

// names joins artefact names for a summary line.
func names(in []string) string {
	sort.Strings(in)
	if len(in) > 5 {
		return strings.Join(in[:5], ", ") + fmt.Sprintf(" (+%d more)", len(in)-5)
	}
	return strings.Join(in, ", ")
}

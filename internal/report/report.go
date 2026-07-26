// Package report renders an evidence.Report as text, GitHub-flavoured
// markdown or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
)

// Format is an output encoding.
type Format string

const (
	FormatText     Format = "text"
	FormatMarkdown Format = "markdown"
	FormatJSON     Format = "json"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatText:
		return FormatText, nil
	case FormatMarkdown, "md":
		return FormatMarkdown, nil
	case FormatJSON:
		return FormatJSON, nil
	}
	return "", fmt.Errorf("unknown format %q (want text, markdown or json)", s)
}

// Write renders the report in the given format.
func Write(w io.Writer, r evidence.Report, f Format) error {
	switch f {
	case FormatJSON:
		return writeJSON(w, r)
	case FormatMarkdown:
		return writeMarkdown(w, r)
	default:
		return writeText(w, r)
	}
}

func writeJSON(w io.Writer, r evidence.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func statusText(s evidence.Status) string {
	switch s {
	case evidence.StatusPass:
		return "PASS"
	case evidence.StatusFail:
		return "FAIL"
	default:
		return "SKIP"
	}
}

func statusEmoji(s evidence.Status) string {
	switch s {
	case evidence.StatusPass:
		return "✅"
	case evidence.StatusFail:
		return "❌"
	default:
		return "⚪"
	}
}

func writeText(w io.Writer, r evidence.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "cra-evidence-check %s\n", r.Version)
	fmt.Fprintf(&b, "repo:    %s\n", r.Repo)
	if r.ReleaseDir != "" {
		fmt.Fprintf(&b, "release: %s\n", r.ReleaseDir)
	}
	if r.Domain != "" {
		fmt.Fprintf(&b, "domain:  %s\n", r.Domain)
	}
	b.WriteString("\n")
	for _, res := range r.Results {
		fmt.Fprintf(&b, "[%s] %s  %s\n", statusText(res.Status), res.ID, res.Title)
		fmt.Fprintf(&b, "       %s\n", res.Summary)
		for _, d := range res.Details {
			fmt.Fprintf(&b, "       - %s\n", d)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%s\n", r.Headline())
	fmt.Fprintf(&b, "\n%s\n", r.Disclaimer)
	_, err := io.WriteString(w, b.String())
	return err
}

func writeMarkdown(w io.Writer, r evidence.Report) error {
	var b strings.Builder
	b.WriteString("## CRA evidence check\n\n")
	fmt.Fprintf(&b, "**%s** — `%s`", r.Headline(), r.Repo)
	if r.ReleaseDir != "" {
		fmt.Fprintf(&b, ", release `%s`", r.ReleaseDir)
	}
	if r.Domain != "" {
		fmt.Fprintf(&b, ", domain `%s`", r.Domain)
	}
	fmt.Fprintf(&b, "\n\nGenerated %s by `cra-evidence-check %s`.\n\n",
		r.GeneratedAt.UTC().Format("2006-01-02 15:04:05 MST"), r.Version)

	b.WriteString("| | Check | Result |\n|---|---|---|\n")
	for _, res := range r.Results {
		fmt.Fprintf(&b, "| %s | `%s` %s | %s |\n",
			statusEmoji(res.Status), res.ID, escapePipes(res.Title), escapePipes(res.Summary))
	}
	b.WriteString("\n")

	for _, res := range r.Results {
		if res.Status == evidence.StatusPass && len(res.Details) == 0 {
			continue
		}
		fmt.Fprintf(&b, "<details><summary>%s <code>%s</code> %s</summary>\n\n",
			statusEmoji(res.Status), res.ID, escapeHTML(res.Title))
		fmt.Fprintf(&b, "_%s_\n\n", escapeHTML(res.Reference))
		fmt.Fprintf(&b, "%s\n\n", escapeHTML(res.Summary))
		for _, d := range res.Details {
			fmt.Fprintf(&b, "- %s\n", escapeHTML(d))
		}
		b.WriteString("\n</details>\n\n")
	}

	fmt.Fprintf(&b, "> %s\n", r.Disclaimer)
	_, err := io.WriteString(w, b.String())
	return err
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func escapeHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

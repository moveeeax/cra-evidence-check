package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
)

func sample() evidence.Report {
	r := evidence.Report{
		Tool:        "cra-evidence-check",
		Version:     "v0.1.0",
		GeneratedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		Repo:        ".",
		ReleaseDir:  "dist",
		Disclaimer:  evidence.Disclaimer,
		Results: []evidence.Result{
			evidence.Pass("CRA-01", "An SBOM ships with the release", "ref", "1 SBOM file", "bom.json"),
			evidence.Fail("CRA-03", "The SBOM covers the shipped artefacts", "ref",
				"1 of 2 shipped artefacts have no SBOM entry", "app.exe <not> covered & unlisted"),
			evidence.Skip("CRA-04", "security.txt is present", "ref", "no domain supplied"),
		},
	}
	r.Tally()
	return r
}

func TestParseFormat(t *testing.T) {
	for _, in := range []string{"text", "TEXT", "markdown", "md", "json"} {
		if _, err := ParseFormat(in); err != nil {
			t.Errorf("ParseFormat(%q): %v", in, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("ParseFormat(\"yaml\") should fail")
	}
}

func TestWriteText(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), FormatText); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"[PASS] CRA-01", "[FAIL] CRA-03", "[SKIP] CRA-04",
		"1 passed, 1 failed, 1 skipped", evidence.Disclaimer} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteMarkdownEscapes(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), FormatMarkdown); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "| ✅ | `CRA-01`") {
		t.Errorf("missing table row:\n%s", out)
	}
	if !strings.Contains(out, "&lt;not&gt;") || !strings.Contains(out, "&amp;") {
		t.Errorf("detail text must be HTML-escaped inside <details>:\n%s", out)
	}
	if strings.Contains(out, "\n# ") {
		t.Error("the summary must start at h2 so it nests inside a GitHub step summary")
	}
	// A passing check with details still gets a collapsible section.
	if strings.Count(out, "<details>") != 3 {
		t.Errorf("expected one <details> block per result, got %d:\n%s", strings.Count(out, "<details>"), out)
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	var back evidence.Report
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if len(back.Results) != 3 || back.Counts.Fail != 1 {
		t.Errorf("round trip lost data: %+v", back)
	}
	if back.Results[1].Status != evidence.StatusFail {
		t.Errorf("status = %q", back.Results[1].Status)
	}
}

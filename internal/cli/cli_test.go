package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
)

var refTime = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

func fixture(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

type result struct {
	code   int
	stdout string
	stderr string
}

func exec(t *testing.T, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Main(context.Background(), args, Options{Stdout: &out, Stderr: &errOut, Now: refTime})
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

func TestScanCompliantExitsZero(t *testing.T) {
	r := exec(t, "scan", "--repo", fixture("repo", "compliant"), "--release-dir", fixture("release", "complete"))
	if r.code != ExitOK {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, ExitOK, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "8 passed, 0 failed, 0 skipped") {
		t.Errorf("missing headline:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "not a conformity assessment") {
		t.Error("every report must carry the disclaimer")
	}
}

func TestScanWithFindingsExitsOne(t *testing.T) {
	r := exec(t, "scan", "--repo", fixture("repo", "gaps"), "--release-dir", fixture("release", "no-sbom"))
	if r.code != ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", r.code, ExitFindings, r.stdout)
	}
	if !strings.Contains(r.stdout, "[FAIL] CRA-01") {
		t.Errorf("expected CRA-01 to fail:\n%s", r.stdout)
	}
}

func TestStrictTurnsSkipsIntoFailures(t *testing.T) {
	args := []string{"scan", "--repo", fixture("repo", "compliant")}
	if r := exec(t, args...); r.code != ExitOK {
		t.Fatalf("without --strict, skips must not fail the run: exit=%d\n%s", r.code, r.stdout)
	}
	if r := exec(t, append(args, "--strict")...); r.code != ExitFindings {
		t.Fatalf("with --strict, skips must fail the run: exit=%d\n%s", r.code, r.stdout)
	}
}

func TestJSONOutputIsValidAndComplete(t *testing.T) {
	r := exec(t, "scan",
		"--repo", fixture("repo", "compliant"),
		"--release-dir", fixture("release", "spdx"),
		"--format", "json")
	if r.code != ExitOK {
		t.Fatalf("exit = %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	var rep evidence.Report
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, r.stdout)
	}
	if len(rep.Results) != 8 {
		t.Errorf("got %d results, want 8", len(rep.Results))
	}
	if rep.Counts.Pass != 8 {
		t.Errorf("counts = %+v", rep.Counts)
	}
	if rep.Disclaimer == "" || rep.Tool != "cra-evidence-check" {
		t.Errorf("report envelope incomplete: %+v", rep)
	}
	if !rep.GeneratedAt.Equal(refTime) {
		t.Errorf("GeneratedAt = %v, want the injected clock", rep.GeneratedAt)
	}
}

func TestMarkdownOutputToFileIsAppended(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(path, []byte("## earlier step\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := exec(t, "scan",
		"--repo", fixture("repo", "gaps"),
		"--release-dir", fixture("release", "uncovered"),
		"--format", "markdown", "--output", path)
	if r.code != ExitFindings {
		t.Fatalf("exit = %d\n%s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("--output must divert the report away from stdout, got %q", r.stdout)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.HasPrefix(text, "## earlier step") {
		t.Error("the file must be appended to, not truncated ($GITHUB_STEP_SUMMARY is shared)")
	}
	for _, want := range []string{"## CRA evidence check", "| `CRA-03`", "❌", "<details>"} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown is missing %q:\n%s", want, text)
		}
	}
}

func TestOnlySelectsChecks(t *testing.T) {
	r := exec(t, "scan", "--repo", fixture("repo", "compliant"), "--only", "CRA-05")
	if r.code != ExitOK {
		t.Fatalf("exit = %d\n%s", r.code, r.stdout)
	}
	if strings.Contains(r.stdout, "CRA-01") {
		t.Errorf("--only should have excluded CRA-01:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "CRA-05") {
		t.Errorf("--only CRA-05 produced no CRA-05 result:\n%s", r.stdout)
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	cases := [][]string{
		{"scan", "--only", "CRA-99", "--repo", fixture("repo", "compliant")},
		{"scan", "--format", "yaml", "--repo", fixture("repo", "compliant")},
		{"scan", "--repo", fixture("repo", "does-not-exist")},
		{"scan", "stray-argument"},
		{"not-a-command"},
		{},
	}
	for _, args := range cases {
		if r := exec(t, args...); r.code != ExitError {
			t.Errorf("%v: exit = %d, want %d", args, r.code, ExitError)
		}
	}
}

func TestChecksAndVersionCommands(t *testing.T) {
	r := exec(t, "checks")
	if r.code != ExitOK {
		t.Fatalf("exit = %d", r.code)
	}
	for _, id := range []string{"CRA-01", "CRA-04", "CRA-08"} {
		if !strings.Contains(r.stdout, id) {
			t.Errorf("`checks` should list %s:\n%s", id, r.stdout)
		}
	}
	if v := exec(t, "version"); v.code != ExitOK || !strings.Contains(v.stdout, "cra-evidence-check") {
		t.Errorf("version = %q (exit %d)", v.stdout, v.code)
	}
}

// TestSecurityTxtOverHTTP exercises the --domain path end to end against a
// local server: the canonical location 404s, the fallback serves the file.
func TestSecurityTxtOverHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/security.txt" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Contact: https://example.invalid/report\nExpires: 2030-01-01T00:00:00Z\nPolicy: https://example.invalid/policy\n"))
	}))
	defer srv.Close()

	r := exec(t, "scan", "--repo", fixture("repo", "gaps"), "--domain", srv.URL, "--only", "CRA-04")
	if r.code != ExitOK {
		t.Fatalf("exit = %d, want 0\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "/.well-known/security.txt: HTTP 404") {
		t.Errorf("the failed canonical attempt should be reported:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "Expires: 2030-01-01") {
		t.Errorf("the served file was not used:\n%s", r.stdout)
	}
}

func TestSecurityTxtOverHTTPWhenNothingIsServed(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	r := exec(t, "scan", "--repo", fixture("repo", "compliant"), "--domain", srv.URL, "--only", "CRA-04")
	if r.code != ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", r.code, ExitFindings, r.stdout)
	}
	// The in-repo copy must not rescue a domain that serves nothing.
	if !strings.Contains(r.stdout, "no security.txt served by") {
		t.Errorf("unexpected report:\n%s", r.stdout)
	}
}

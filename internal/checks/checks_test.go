package checks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
)

// refTime is a fixed clock so that the "Expires" fixtures behave the same in
// 2026 as they will in 2029.
var refTime = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

func fixture(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

// run executes every check and returns the results keyed by ID.
func run(t *testing.T, in *Input) map[string]evidence.Result {
	t.Helper()
	if in.Now.IsZero() {
		in.Now = refTime
	}
	out := map[string]evidence.Result{}
	for _, r := range Run(context.Background(), in, All()) {
		out[r.ID] = r
	}
	return out
}

func assertStatuses(t *testing.T, got map[string]evidence.Result, want map[string]evidence.Status) {
	t.Helper()
	for id, wantStatus := range want {
		res, ok := got[id]
		if !ok {
			t.Errorf("%s: no result", id)
			continue
		}
		if res.Status != wantStatus {
			t.Errorf("%s (%s): status = %s, want %s\n  summary: %s\n  details: %s",
				id, res.Title, res.Status, wantStatus, res.Summary, strings.Join(res.Details, "\n           "))
		}
	}
}

func TestAllChecksHaveDistinctIDsAndReferences(t *testing.T) {
	all := All()
	if len(all) != 8 {
		t.Fatalf("got %d checks, want the documented 8", len(all))
	}
	seen := map[string]bool{}
	for _, c := range all {
		if seen[c.ID] {
			t.Errorf("duplicate check ID %s", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" || c.Reference == "" {
			t.Errorf("%s: every check needs a title and a CRA reference", c.ID)
		}
		if !strings.HasPrefix(c.ID, "CRA-") {
			t.Errorf("unexpected ID format %q", c.ID)
		}
	}
}

func TestCompliantRepoAndReleasePassEverything(t *testing.T) {
	got := run(t, &Input{
		RepoDir:    fixture("repo", "compliant"),
		ReleaseDir: fixture("release", "complete"),
	})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-01": evidence.StatusPass,
		"CRA-02": evidence.StatusPass,
		"CRA-03": evidence.StatusPass,
		"CRA-04": evidence.StatusPass,
		"CRA-05": evidence.StatusPass,
		"CRA-06": evidence.StatusPass,
		"CRA-07": evidence.StatusPass,
		"CRA-08": evidence.StatusPass,
	})
}

func TestGapsRepoFailsTheRightChecks(t *testing.T) {
	got := run(t, &Input{
		RepoDir:    fixture("repo", "gaps"),
		ReleaseDir: fixture("release", "no-sbom"),
	})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-01": evidence.StatusFail, // no SBOM in the bundle
		"CRA-02": evidence.StatusFail, // nothing to parse
		"CRA-03": evidence.StatusFail, // nothing to check coverage against
		"CRA-04": evidence.StatusFail, // security.txt expired in 2024
		"CRA-05": evidence.StatusFail, // no SECURITY.md at all
		"CRA-06": evidence.StatusPass, // the checksum manifest is still correct
		"CRA-07": evidence.StatusFail, // package.json without a lock, unpinned requirements
		"CRA-08": evidence.StatusFail, // the checksum manifest itself is unsigned
	})
	if !strings.Contains(got["CRA-04"].Summary+strings.Join(got["CRA-04"].Details, " "), "2024-06-30") {
		t.Errorf("CRA-04 should name the expiry date: %+v", got["CRA-04"])
	}
	deps := strings.Join(got["CRA-07"].Details, "\n")
	for _, want := range []string{"package.json", "scripts/requirements.txt"} {
		if !strings.Contains(deps, want) {
			t.Errorf("CRA-07 details should name %s:\n%s", want, deps)
		}
	}
}

func TestSBOMCoverageDetectsAnUncoveredArtefact(t *testing.T) {
	got := run(t, &Input{
		RepoDir:    fixture("repo", "compliant"),
		ReleaseDir: fixture("release", "uncovered"),
	})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-01": evidence.StatusPass,
		"CRA-02": evidence.StatusPass,
		"CRA-03": evidence.StatusFail,
		"CRA-06": evidence.StatusPass,
		"CRA-08": evidence.StatusPass,
	})
	d := strings.Join(got["CRA-03"].Details, "\n")
	if !strings.Contains(d, "controller_3.2.0_windows_amd64.exe") {
		t.Errorf("CRA-03 must name the uncovered artefact:\n%s", d)
	}
	if !strings.Contains(d, "matched in controller.cdx.json by SHA-256") {
		t.Errorf("CRA-03 must say how the covered artefact matched:\n%s", d)
	}
}

func TestTamperedChecksumIsCaught(t *testing.T) {
	got := run(t, &Input{
		RepoDir:    fixture("repo", "compliant"),
		ReleaseDir: fixture("release", "tampered"),
	})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-03": evidence.StatusPass, // the SBOM still describes the rebuilt file
		"CRA-06": evidence.StatusFail, // but the manifest does not
	})
	if !strings.Contains(strings.Join(got["CRA-06"].Details, "\n"), "digest mismatch for vault-bridge_5.0.0_linux_amd64") {
		t.Errorf("CRA-06 must report the mismatching artefact: %+v", got["CRA-06"].Details)
	}
}

func TestBrokenSBOMFailsParsingButNotPresence(t *testing.T) {
	got := run(t, &Input{
		RepoDir:    fixture("repo", "compliant"),
		ReleaseDir: fixture("release", "broken-sbom"),
	})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-01": evidence.StatusPass,
		"CRA-02": evidence.StatusFail,
		"CRA-03": evidence.StatusFail,
		"CRA-06": evidence.StatusPass,
	})
	if !strings.Contains(strings.Join(got["CRA-02"].Details, " "), "bom.json") {
		t.Errorf("CRA-02 must name the unparseable file: %+v", got["CRA-02"])
	}
}

func TestSPDXReleasePasses(t *testing.T) {
	got := run(t, &Input{
		RepoDir:    fixture("repo", "compliant"),
		ReleaseDir: fixture("release", "spdx"),
	})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-01": evidence.StatusPass,
		"CRA-02": evidence.StatusPass,
		"CRA-03": evidence.StatusPass,
		"CRA-06": evidence.StatusPass,
		"CRA-08": evidence.StatusPass,
	})
	if !strings.Contains(got["CRA-02"].Details[0], "spdx-json") {
		t.Errorf("CRA-02 should report the detected format: %v", got["CRA-02"].Details)
	}
}

func TestReleaseChecksSkipWithoutAReleaseDir(t *testing.T) {
	got := run(t, &Input{RepoDir: fixture("repo", "compliant")})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-01": evidence.StatusSkip,
		"CRA-02": evidence.StatusSkip,
		"CRA-03": evidence.StatusSkip,
		"CRA-06": evidence.StatusSkip,
		"CRA-08": evidence.StatusSkip,
		"CRA-04": evidence.StatusPass,
		"CRA-05": evidence.StatusPass,
		"CRA-07": evidence.StatusPass,
	})
}

func TestMissingReleaseDirFailsRatherThanSkips(t *testing.T) {
	got := run(t, &Input{
		RepoDir:    fixture("repo", "compliant"),
		ReleaseDir: fixture("release", "no-such-directory"),
	})
	assertStatuses(t, got, map[string]evidence.Status{
		"CRA-01": evidence.StatusFail,
		"CRA-06": evidence.StatusFail,
		"CRA-08": evidence.StatusFail,
	})
}

func TestSelect(t *testing.T) {
	got, err := Select([]string{"cra-02", " CRA-01 "})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(got) != 2 || got[0].ID != "CRA-01" || got[1].ID != "CRA-02" {
		t.Errorf("Select should normalise case and sort by ID, got %+v", got)
	}
	if _, err := Select([]string{"CRA-99"}); err == nil {
		t.Error("an unknown ID must be an error, not a silent no-op")
	}
	all, err := Select(nil)
	if err != nil || len(all) != 8 {
		t.Errorf("Select(nil) = %d checks, %v", len(all), err)
	}
}

func TestGoModWithoutRequiresNeedsNoSum(t *testing.T) {
	ok, why := goModNeedsNoSum("module example.invalid/x\n\ngo 1.24\n")
	if !ok || why == "" {
		t.Errorf("a dependency-free go.mod should not need a go.sum, got %v %q", ok, why)
	}
	if ok, _ := goModNeedsNoSum("module x\n\nrequire (\n\tgithub.com/a/b v1.0.0\n)\n"); ok {
		t.Error("a go.mod with a require block needs a go.sum")
	}
	if ok, _ := goModNeedsNoSum("module x\n\nrequire github.com/a/b v1.0.0\n"); ok {
		t.Error("a single-line require also needs a go.sum")
	}
}

func TestRequirementsFullyPinned(t *testing.T) {
	if ok, _ := requirementsFullyPinned("# c\nrequests==2.32.3\nurllib3==2.2.2  # transitive\n"); !ok {
		t.Error("fully pinned requirements should count as a lock")
	}
	if ok, _ := requirementsFullyPinned("requests==2.32.3\nclick>=8\n"); ok {
		t.Error("a range must not count as pinned")
	}
	if ok, _ := requirementsFullyPinned("-r base.txt\n"); !ok {
		t.Error("a file with only includes has nothing unpinned to report")
	}
}

func TestHasContact(t *testing.T) {
	yes := []string{
		"Mail security@example.invalid please",
		"Report at https://example.invalid/advisories",
		"<mailto:sec@example.invalid>",
	}
	for _, s := range yes {
		if !hasContact(s) {
			t.Errorf("hasContact(%q) = false", s)
		}
	}
	no := []string{"We take security seriously.", "Contact the team", "user@localhost"}
	for _, s := range no {
		if hasContact(s) {
			t.Errorf("hasContact(%q) = true", s)
		}
	}
}

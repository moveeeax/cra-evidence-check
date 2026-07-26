// Package checks implements the eight machine-checkable CRA evidence checks.
//
// Scope discipline: every check answers "is this artefact present, parseable
// and internally consistent?". None of them scores, grades, or infers whether
// a product is compliant.
package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
	"github.com/moveeeax/cra-evidence-check/internal/sbom"
	"github.com/moveeeax/cra-evidence-check/internal/securitytxt"
)

// Input is everything a check may look at.
type Input struct {
	// RepoDir is the repository root.
	RepoDir string
	// ReleaseDir is the directory holding the built release artefacts. Empty
	// means "not supplied", which makes the release-scoped checks skip.
	ReleaseDir string
	// Domain, if set, makes the security.txt check fetch over HTTP instead of
	// looking in the repository. A scheme may be included.
	Domain string
	// Now is the reference time for expiry comparisons.
	Now time.Time
	// Excludes are directory base names pruned when walking the repository.
	Excludes []string
	// Fetch retrieves URLs; nil means use the default HTTP client.
	Fetch securitytxt.Fetcher

	// Populated by Prepare.
	Release  *evidence.Release
	SBOMs    []ParsedSBOM
	scanErr  error
	prepared bool
}

// ParsedSBOM pairs a release file with its parse outcome.
type ParsedSBOM struct {
	File     evidence.Artifact
	Document *sbom.Document
	Err      error
}

// Prepare does the shared I/O once: scanning the release directory, hashing
// every file and parsing every SBOM found there.
func (in *Input) Prepare() {
	if in.prepared {
		return
	}
	in.prepared = true
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	if len(in.Excludes) == 0 {
		in.Excludes = evidence.DefaultExcludes
	}
	if in.Fetch == nil {
		in.Fetch = securitytxt.HTTPFetcher(nil)
	}
	if in.ReleaseDir == "" {
		return
	}
	rel, err := evidence.ScanRelease(in.ReleaseDir)
	if err != nil {
		in.scanErr = err
		return
	}
	in.Release = rel
	for _, f := range rel.ByKind(evidence.KindSBOM) {
		data, err := readFile(f.Path)
		if err != nil {
			in.SBOMs = append(in.SBOMs, ParsedSBOM{File: f, Err: err})
			continue
		}
		doc, err := sbom.Parse(data)
		in.SBOMs = append(in.SBOMs, ParsedSBOM{File: f, Document: doc, Err: err})
	}
}

// releaseUnavailable returns a Result when the release directory is missing or
// unreadable, or nil when the release-scoped checks can proceed.
func (in *Input) releaseUnavailable(id, title, ref string) *evidence.Result {
	if in.ReleaseDir == "" {
		r := evidence.Skip(id, title, ref,
			"no release directory supplied",
			"Pass --release-dir pointing at the built release artefacts to run this check.")
		return &r
	}
	if in.scanErr != nil {
		r := evidence.Fail(id, title, ref,
			fmt.Sprintf("release directory %q could not be read", in.ReleaseDir),
			in.scanErr.Error())
		return &r
	}
	return nil
}

// Check is one evidence check.
type Check struct {
	ID        string
	Title     string
	Reference string
	Run       func(ctx context.Context, in *Input) evidence.Result
}

// All returns the eight checks in stable ID order.
func All() []Check {
	c := []Check{
		checkSBOMPresent,
		checkSBOMValid,
		checkSBOMCoversArtifact,
		checkSecurityTxt,
		checkCVDPolicy,
		checkReleaseEvidenceRetained,
		checkLockfilesCommitted,
		checkSignedReleases,
	}
	sort.Slice(c, func(i, j int) bool { return c[i].ID < c[j].ID })
	return c
}

// Select filters All() by ID. An unknown ID is an error — a typo in CI must not
// silently reduce the check set.
func Select(ids []string) ([]Check, error) {
	if len(ids) == 0 {
		return All(), nil
	}
	byID := map[string]Check{}
	for _, c := range All() {
		byID[c.ID] = c
	}
	var out []Check
	for _, raw := range ids {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		c, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("unknown check %q", raw)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return All(), nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Run prepares the input and executes the selected checks.
func Run(ctx context.Context, in *Input, selected []Check) []evidence.Result {
	in.Prepare()
	results := make([]evidence.Result, 0, len(selected))
	for _, c := range selected {
		results = append(results, c.Run(ctx, in))
	}
	return results
}

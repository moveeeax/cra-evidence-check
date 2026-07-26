// Package evidence holds the data model shared by the checks and the
// reporters: the result of a single check, the report as a whole, and the
// on-disk release bundle a check is run against.
package evidence

import (
	"fmt"
	"time"
)

// Status is the outcome of a single check. There are deliberately only three
// values: the tool reports observable facts, it does not score or grade.
type Status string

const (
	// StatusPass means the evidence the check looks for was found.
	StatusPass Status = "pass"
	// StatusFail means the evidence was missing, unparseable or inconsistent.
	StatusFail Status = "fail"
	// StatusSkip means the check could not run because its input was not
	// supplied (for example: no release directory was given).
	StatusSkip Status = "skip"
)

// Result is the outcome of one check.
type Result struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Reference string   `json:"reference"`
	Status    Status   `json:"status"`
	Summary   string   `json:"summary"`
	Details   []string `json:"details,omitempty"`
}

// Pass builds a passing Result.
func Pass(id, title, ref, summary string, details ...string) Result {
	return Result{ID: id, Title: title, Reference: ref, Status: StatusPass, Summary: summary, Details: details}
}

// Fail builds a failing Result.
func Fail(id, title, ref, summary string, details ...string) Result {
	return Result{ID: id, Title: title, Reference: ref, Status: StatusFail, Summary: summary, Details: details}
}

// Skip builds a skipped Result.
func Skip(id, title, ref, summary string, details ...string) Result {
	return Result{ID: id, Title: title, Reference: ref, Status: StatusSkip, Summary: summary, Details: details}
}

// Counts is the tally of results by status.
type Counts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// Report is the full output of one run.
type Report struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Repo        string    `json:"repo"`
	ReleaseDir  string    `json:"release_dir,omitempty"`
	Domain      string    `json:"domain,omitempty"`
	Strict      bool      `json:"strict"`
	Results     []Result  `json:"results"`
	Counts      Counts    `json:"counts"`
	Disclaimer  string    `json:"disclaimer"`
}

// Disclaimer is attached to every report and rendered by every reporter. It is
// not decoration: the whole point of this tool is that it reports evidence and
// says nothing about conformity.
const Disclaimer = "This report lists machine-checkable engineering evidence only. " +
	"It is not a conformity assessment, a certification, an audit or legal advice."

// Tally recomputes Counts from Results and stores it on the report.
func (r *Report) Tally() {
	var c Counts
	for _, res := range r.Results {
		switch res.Status {
		case StatusPass:
			c.Pass++
		case StatusFail:
			c.Fail++
		case StatusSkip:
			c.Skip++
		}
	}
	r.Counts = c
}

// OK reports whether the run should be treated as successful. Skipped checks
// only count against the run in strict mode.
func (r Report) OK() bool {
	if r.Counts.Fail > 0 {
		return false
	}
	return !(r.Strict && r.Counts.Skip > 0)
}

// Headline is a one-line summary of the run, e.g. "6 passed, 1 failed, 1 skipped".
func (r Report) Headline() string {
	return fmt.Sprintf("%d passed, %d failed, %d skipped", r.Counts.Pass, r.Counts.Fail, r.Counts.Skip)
}

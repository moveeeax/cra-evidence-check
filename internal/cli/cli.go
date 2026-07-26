// Package cli implements the command line interface. It is a separate package
// from main so that the whole command can be exercised in tests.
package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moveeeax/cra-evidence-check/internal/checks"
	"github.com/moveeeax/cra-evidence-check/internal/evidence"
	"github.com/moveeeax/cra-evidence-check/internal/report"
	"github.com/moveeeax/cra-evidence-check/internal/securitytxt"
)

// Exit codes. They are part of the contract with CI, so they are documented in
// the README and must not be renumbered casually.
const (
	ExitOK       = 0 // every selected check passed
	ExitFindings = 1 // at least one check failed (or was skipped, under --strict)
	ExitError    = 2 // the tool could not run: bad flags, unreadable paths
)

// Version is set at build time with -ldflags "-X .../internal/cli.Version=v0.1.0".
var Version = "dev"

const usage = `cra-evidence-check %s — machine-checkable CRA engineering evidence

Usage:
  cra-evidence-check scan [flags]
  cra-evidence-check checks
  cra-evidence-check version

Commands:
  scan     run the evidence checks against a repository and a release directory
  checks   list the checks and their references
  version  print the version

Exit codes:
  0  all selected checks passed
  1  at least one check failed (or was skipped, with --strict)
  2  the tool could not run

Run "cra-evidence-check scan -h" for the scan flags.
`

// Options are the injectable seams tests use.
type Options struct {
	Stdout io.Writer
	Stderr io.Writer
	// Now overrides the clock (expiry checks).
	Now time.Time
	// Fetch overrides the security.txt HTTP fetcher.
	Fetch securitytxt.Fetcher
}

// Main runs the command and returns the process exit code.
func Main(ctx context.Context, args []string, opt Options) int {
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if len(args) == 0 {
		fmt.Fprintf(opt.Stderr, usage, Version)
		return ExitError
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], opt)
	case "checks":
		return listChecks(opt)
	case "version", "--version", "-version":
		fmt.Fprintf(opt.Stdout, "cra-evidence-check %s\n", Version)
		return ExitOK
	case "help", "-h", "--help":
		fmt.Fprintf(opt.Stdout, usage, Version)
		return ExitOK
	default:
		fmt.Fprintf(opt.Stderr, "unknown command %q\n\n", args[0])
		fmt.Fprintf(opt.Stderr, usage, Version)
		return ExitError
	}
}

func listChecks(opt Options) int {
	for _, c := range checks.All() {
		fmt.Fprintf(opt.Stdout, "%s  %s\n        %s\n", c.ID, c.Title, c.Reference)
	}
	fmt.Fprintf(opt.Stdout, "\n%s\n", evidence.Disclaimer)
	return ExitOK
}

func runScan(ctx context.Context, args []string, opt Options) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(opt.Stderr)
	var (
		repoDir    = fs.String("repo", ".", "path to the repository root")
		releaseDir = fs.String("release-dir", "", "directory holding the built release artefacts (SBOM, binaries, checksums, signatures)")
		domain     = fs.String("domain", "", "public domain to fetch security.txt from, e.g. example.com (default: look in the repository)")
		format     = fs.String("format", "text", "output format: text, markdown or json")
		output     = fs.String("output", "-", "write the report to this file ('-' is stdout)")
		only       = fs.String("only", "", "comma-separated check IDs to run, e.g. CRA-01,CRA-02")
		exclude    = fs.String("exclude", strings.Join(evidence.DefaultExcludes, ","), "comma-separated directory names to skip when walking the repository")
		strict     = fs.Bool("strict", false, "treat skipped checks as failures")
	)
	fs.Usage = func() {
		fmt.Fprintf(opt.Stderr, "Usage: cra-evidence-check scan [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(opt.Stderr, "unexpected argument %q\n", fs.Arg(0))
		return ExitError
	}

	outFormat, err := report.ParseFormat(*format)
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return ExitError
	}

	repoAbs, err := filepath.Abs(*repoDir)
	if err != nil {
		fmt.Fprintf(opt.Stderr, "resolve --repo: %v\n", err)
		return ExitError
	}
	if info, err := os.Stat(repoAbs); err != nil || !info.IsDir() {
		fmt.Fprintf(opt.Stderr, "--repo %s is not a directory\n", *repoDir)
		return ExitError
	}

	selected, err := checks.Select(splitList(*only))
	if err != nil {
		fmt.Fprintf(opt.Stderr, "%v (run \"cra-evidence-check checks\" for the list)\n", err)
		return ExitError
	}

	now := opt.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	in := &checks.Input{
		RepoDir:    repoAbs,
		ReleaseDir: *releaseDir,
		Domain:     *domain,
		Now:        now,
		Excludes:   splitList(*exclude),
		Fetch:      opt.Fetch,
	}

	rep := evidence.Report{
		Tool:        "cra-evidence-check",
		Version:     Version,
		GeneratedAt: now,
		Repo:        *repoDir,
		ReleaseDir:  *releaseDir,
		Domain:      *domain,
		Strict:      *strict,
		Results:     checks.Run(ctx, in, selected),
		Disclaimer:  evidence.Disclaimer,
	}
	rep.Tally()

	var buf bytes.Buffer
	if err := report.Write(&buf, rep, outFormat); err != nil {
		fmt.Fprintf(opt.Stderr, "render report: %v\n", err)
		return ExitError
	}
	if *output == "-" || *output == "" {
		if _, err := opt.Stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(opt.Stderr, "write report: %v\n", err)
			return ExitError
		}
	} else if err := appendFile(*output, buf.Bytes()); err != nil {
		fmt.Fprintf(opt.Stderr, "write %s: %v\n", *output, err)
		return ExitError
	}

	if rep.OK() {
		return ExitOK
	}
	return ExitFindings
}

// appendFile appends rather than truncates: the common target is
// $GITHUB_STEP_SUMMARY, which other steps also write to.
func appendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

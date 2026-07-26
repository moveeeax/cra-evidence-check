package checks

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
)

const depsRef = "CRA Annex I, Part II(1) — identify and document components and dependencies"

// ecosystem ties a dependency manifest to the lockfiles that pin it.
type ecosystem struct {
	Name     string
	Manifest string
	Lockfile []string // any one of these, in the same directory, satisfies the manifest
	// SelfPinned lets an ecosystem declare that the manifest itself can be the
	// lock (a fully pinned requirements.txt), via Pinned.
	Pinned func(manifestContent string) (bool, string)
}

var ecosystems = []ecosystem{
	{Name: "Go", Manifest: "go.mod", Lockfile: []string{"go.sum"}, Pinned: goModNeedsNoSum},
	{Name: "npm/yarn/pnpm", Manifest: "package.json", Lockfile: []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}},
	{Name: "Python (PEP 621)", Manifest: "pyproject.toml", Lockfile: []string{"poetry.lock", "uv.lock", "pdm.lock", "requirements.lock", "requirements.txt"}},
	{Name: "Python (pip)", Manifest: "requirements.txt", Lockfile: []string{"requirements.lock"}, Pinned: requirementsFullyPinned},
	{Name: "Rust", Manifest: "Cargo.toml", Lockfile: []string{"Cargo.lock"}},
	{Name: "Ruby", Manifest: "Gemfile", Lockfile: []string{"Gemfile.lock"}},
	{Name: "PHP", Manifest: "composer.json", Lockfile: []string{"composer.lock"}},
	{Name: "Swift", Manifest: "Package.swift", Lockfile: []string{"Package.resolved"}},
}

// goModNeedsNoSum: a go.mod with no external requirements legitimately has no
// go.sum. Flagging those would train people to ignore the check.
func goModNeedsNoSum(content string) (bool, string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.HasSuffix(line, "(") {
			return false, ""
		}
		if line == "require (" {
			return false, ""
		}
	}
	return true, "no external module requirements, so no go.sum is expected"
}

// requirementsFullyPinned: every requirement uses '==' or a hash.
func requirementsFullyPinned(content string) (bool, string) {
	count := 0
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		count++
		if !strings.Contains(line, "==") && !strings.Contains(line, "--hash=") {
			return false, ""
		}
	}
	if count == 0 {
		return true, "no requirements listed"
	}
	return true, fmt.Sprintf("all %d requirements pinned with '=='", count)
}

var checkLockfilesCommitted = Check{
	ID:        "CRA-07",
	Title:     "Dependency manifests have a committed lockfile",
	Reference: depsRef,
	Run: func(_ context.Context, in *Input) evidence.Result {
		const id, title = "CRA-07", "Dependency manifests have a committed lockfile"

		var wanted []string
		for _, e := range ecosystems {
			wanted = append(wanted, e.Manifest)
		}
		manifests, err := evidence.FindFiles(in.RepoDir, wanted, in.Excludes)
		if err != nil {
			return evidence.Fail(id, title, depsRef, "the repository could not be walked", err.Error())
		}
		if len(manifests) == 0 {
			return evidence.Skip(id, title, depsRef,
				"no dependency manifests found in the repository",
				"Looked for: "+strings.Join(wanted, ", "),
				"Excluded directories: "+strings.Join(in.Excludes, ", "))
		}

		byManifest := map[string]ecosystem{}
		for _, e := range ecosystems {
			byManifest[e.Manifest] = e
		}

		var locked, unlocked []string
		for _, m := range manifests {
			eco, ok := byManifest[path.Base(m)]
			if !ok {
				continue
			}
			dir := path.Dir(m)
			found := ""
			for _, lf := range eco.Lockfile {
				candidate := path.Join(dir, lf)
				if candidate == m {
					continue
				}
				if _, ok := evidence.FirstExisting(in.RepoDir, candidate); !ok {
					continue
				}
				// A requirements.txt only counts as a lock when it is pinned.
				if path.Base(candidate) == "requirements.txt" {
					body, err := evidence.ReadRepoFile(in.RepoDir, candidate)
					if err != nil {
						continue
					}
					if pinned, _ := requirementsFullyPinned(string(body)); !pinned {
						continue
					}
				}
				found = candidate
				break
			}
			if found != "" {
				locked = append(locked, fmt.Sprintf("%s (%s) -> %s", m, eco.Name, found))
				continue
			}
			if eco.Pinned != nil {
				if body, err := evidence.ReadRepoFile(in.RepoDir, m); err == nil {
					if ok, why := eco.Pinned(string(body)); ok {
						locked = append(locked, fmt.Sprintf("%s (%s) -> %s", m, eco.Name, why))
						continue
					}
				}
			}
			unlocked = append(unlocked, fmt.Sprintf("%s (%s) has no lockfile; expected one of: %s",
				m, eco.Name, strings.Join(eco.Lockfile, ", ")))
		}

		if len(unlocked) > 0 {
			return evidence.Fail(id, title, depsRef,
				fmt.Sprintf("%d of %d dependency manifests are not pinned by a committed lockfile", len(unlocked), len(unlocked)+len(locked)),
				bullets(append(unlocked, locked...))...)
		}
		return evidence.Pass(id, title, depsRef,
			fmt.Sprintf("all %s pinned by a committed lockfile", plural(len(locked), "dependency manifest is", "dependency manifests are")),
			bullets(locked)...)
	},
}

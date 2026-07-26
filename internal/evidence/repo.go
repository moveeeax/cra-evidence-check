package evidence

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultExcludes are directories never walked when looking for dependency
// manifests: build output, vendored trees and VCS metadata.
var DefaultExcludes = []string{".git", "node_modules", "vendor", "dist", "build", "target", ".terraform", ".venv", "venv"}

// FirstExisting returns the first of the given repo-relative paths that exists
// as a regular file, along with true. Paths are tried in order, so callers
// should list the canonical location first.
func FirstExisting(root string, candidates ...string) (string, bool) {
	for _, c := range candidates {
		p := filepath.Join(root, filepath.FromSlash(c))
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return c, true
		}
	}
	return "", false
}

// ReadRepoFile reads a repo-relative file.
func ReadRepoFile(root, rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
}

// FindFiles walks the repository and returns the repo-relative slash-separated
// paths of every regular file whose base name is in names. Directories listed
// in excludes (matched by base name) are pruned.
func FindFiles(root string, names []string, excludes []string) ([]string, error) {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	skip := make(map[string]bool, len(excludes))
	for _, e := range excludes {
		skip[strings.ToLower(strings.TrimSpace(e))] = true
	}

	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is not a reason to abort the whole scan.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if skip[strings.ToLower(d.Name())] {
				return fs.SkipDir
			}
			return nil
		}
		if !want[strings.ToLower(d.Name())] {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

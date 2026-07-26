package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Kind classifies a file found in a release directory.
type Kind string

const (
	// KindArtifact is a shipped artefact: the thing the customer downloads.
	KindArtifact Kind = "artifact"
	// KindSBOM is a software bill of materials accompanying the release.
	KindSBOM Kind = "sbom"
	// KindSignature is a detached signature, certificate or in-toto attestation.
	KindSignature Kind = "signature"
	// KindChecksums is a checksum manifest (checksums.txt, SHA256SUMS, *.sha256).
	KindChecksums Kind = "checksums"
)

// Artifact is one file in the release directory, with its recomputed digest.
type Artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Kind   Kind   `json:"kind"`
}

// Release is the on-disk release bundle under inspection.
type Release struct {
	Dir   string
	Files []Artifact
}

// ByKind returns the files of the given kind, in name order.
func (r *Release) ByKind(k Kind) []Artifact {
	var out []Artifact
	for _, f := range r.Files {
		if f.Kind == k {
			out = append(out, f)
		}
	}
	return out
}

var signatureSuffixes = []string{
	".sig", ".asc", ".sign", ".signature",
	".sigstore", ".sigstore.json", ".bundle",
	".intoto.jsonl", ".att", ".pem", ".crt", ".cert",
}

var checksumNames = map[string]bool{
	"checksums.txt": true, "checksum.txt": true,
	"sha256sums": true, "sha256sums.txt": true,
	"sha256sum.txt": true, "sha512sums": true,
	"sha512sums.txt": true, "digests.txt": true,
}

var sbomNames = map[string]bool{
	"bom.json": true, "sbom.json": true, "bom.xml": true, "sbom.xml": true,
}

// ClassifyFile decides what role a release file plays, from its name alone.
// Signature suffixes win over everything so that "checksums.txt.asc" is a
// signature and not a second checksum manifest.
func ClassifyFile(name string) Kind {
	lower := strings.ToLower(name)
	for _, s := range signatureSuffixes {
		if strings.HasSuffix(lower, s) {
			return KindSignature
		}
	}
	if checksumNames[lower] ||
		strings.HasSuffix(lower, "_checksums.txt") ||
		strings.HasSuffix(lower, "-checksums.txt") ||
		strings.HasSuffix(lower, ".sha256") ||
		strings.HasSuffix(lower, ".sha512") {
		return KindChecksums
	}
	if sbomNames[lower] ||
		strings.HasSuffix(lower, ".cdx.json") ||
		strings.HasSuffix(lower, ".cdx.xml") ||
		strings.HasSuffix(lower, ".spdx.json") ||
		strings.HasSuffix(lower, ".spdx") ||
		(strings.Contains(lower, "sbom") && (strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".xml"))) ||
		(strings.Contains(lower, "spdx") && strings.HasSuffix(lower, ".json")) {
		return KindSBOM
	}
	return KindArtifact
}

// ScanRelease reads a release directory (non-recursively — a release bundle is
// flat by convention) and returns every file with its SHA-256 digest.
func ScanRelease(dir string) (*Release, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rel := &Release{Dir: dir}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", path, err)
		}
		sum, err := SHA256File(path)
		if err != nil {
			return nil, err
		}
		rel.Files = append(rel.Files, Artifact{
			Name:   e.Name(),
			Path:   path,
			Size:   info.Size(),
			SHA256: sum,
			Kind:   ClassifyFile(e.Name()),
		})
	}
	sort.Slice(rel.Files, func(i, j int) bool { return rel.Files[i].Name < rel.Files[j].Name })
	return rel, nil
}

// SHA256File returns the lowercase hex SHA-256 digest of a file.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ChecksumEntry is one line of a checksum manifest.
type ChecksumEntry struct {
	Digest string
	Name   string
}

// ParseChecksums parses the sha256sum(1) / goreleaser "checksums.txt" format:
//
//	<hex digest><space><space-or-asterisk><file name>
//
// Blank lines and '#' comments are ignored. Names are reduced to their base so
// that "./dist/app" and "app" compare equal.
func ParseChecksums(data []byte) ([]ChecksumEntry, error) {
	var out []ChecksumEntry
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: expected '<digest>  <name>', got %q", i+1, line)
		}
		digest := strings.ToLower(fields[0])
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("line %d: %q is not a hex digest", i+1, fields[0])
		}
		name := strings.TrimPrefix(strings.Join(fields[1:], " "), "*")
		out = append(out, ChecksumEntry{Digest: digest, Name: filepath.Base(name)})
	}
	return out, nil
}

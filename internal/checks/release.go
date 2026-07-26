package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
)

const (
	retentionRef = "CRA Article 13 — technical documentation kept at the disposal of market surveillance authorities"
	updateRef    = "CRA Annex I, Part II — secure dissemination of updates"
)

var checkReleaseEvidenceRetained = Check{
	ID:        "CRA-06",
	Title:     "Release artefacts are retained with a verifiable checksum manifest",
	Reference: retentionRef,
	Run: func(_ context.Context, in *Input) evidence.Result {
		const id, title = "CRA-06", "Release artefacts are retained with a verifiable checksum manifest"
		if r := in.releaseUnavailable(id, title, retentionRef); r != nil {
			return *r
		}
		manifests := in.Release.ByKind(evidence.KindChecksums)
		if len(manifests) == 0 {
			return evidence.Fail(id, title, retentionRef,
				fmt.Sprintf("no checksum manifest in %s", in.ReleaseDir),
				"Expected checksums.txt, SHA256SUMS or per-artefact .sha256 files.",
				"Without one there is no way to show later that the retained bundle is the one that was placed on the market.")
		}

		// Everything that is not itself evidence must be listed.
		shipped := map[string]evidence.Artifact{}
		for _, a := range in.Release.Files {
			if a.Kind == evidence.KindArtifact || a.Kind == evidence.KindSBOM {
				shipped[a.Name] = a
			}
		}

		listed := map[string]string{} // name -> digest
		var problems, details []string
		for _, m := range manifests {
			data, err := readFile(m.Path)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s could not be read: %v", m.Name, err))
				continue
			}
			entries, err := evidence.ParseChecksums(data)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s is not a valid checksum manifest: %v", m.Name, err))
				continue
			}
			if len(entries) == 0 {
				problems = append(problems, fmt.Sprintf("%s is empty", m.Name))
				continue
			}
			details = append(details, fmt.Sprintf("%s lists %s", m.Name, plural(len(entries), "artefact", "artefacts")))
			for _, e := range entries {
				listed[e.Name] = e.Digest
				actual, ok := shipped[e.Name]
				if !ok {
					// It may be a signature or another manifest, which is fine;
					// it may be nothing at all, which is not.
					if _, present := lookup(in.Release, e.Name); !present {
						problems = append(problems, fmt.Sprintf("%s lists %q, which is not present in the release directory", m.Name, e.Name))
					}
					continue
				}
				if len(e.Digest) != 64 {
					// Not SHA-256 (SHA-512 manifests are legal but we only recompute SHA-256).
					details = append(details, fmt.Sprintf("%s: digest for %s is %d hex chars, not SHA-256 — not recomputed", m.Name, e.Name, len(e.Digest)))
					continue
				}
				if e.Digest != actual.SHA256 {
					problems = append(problems, fmt.Sprintf("digest mismatch for %s: manifest says %s, file is %s", e.Name, e.Digest, actual.SHA256))
					continue
				}
				details = append(details, fmt.Sprintf("%s: SHA-256 verified", e.Name))
			}
		}

		for name := range shipped {
			if _, ok := listed[name]; !ok {
				problems = append(problems, fmt.Sprintf("%s is shipped but not listed in any checksum manifest", name))
			}
		}

		if len(problems) > 0 {
			return evidence.Fail(id, title, retentionRef,
				fmt.Sprintf("the checksum manifest does not account for the release (%s)", plural(len(problems), "problem", "problems")),
				bullets(append(problems, details...))...)
		}
		return evidence.Pass(id, title, retentionRef,
			fmt.Sprintf("all %s listed, SHA-256 digests match", plural(len(shipped), "retained file is", "retained files are")),
			bullets(details)...)
	},
}

// lookup finds a file in the release by name.
func lookup(rel *evidence.Release, name string) (evidence.Artifact, bool) {
	for _, f := range rel.Files {
		if f.Name == name {
			return f, true
		}
	}
	return evidence.Artifact{}, false
}

var checkSignedReleases = Check{
	ID:        "CRA-08",
	Title:     "Release artefacts carry a signature or attestation",
	Reference: updateRef,
	Run: func(_ context.Context, in *Input) evidence.Result {
		const id, title = "CRA-08", "Release artefacts carry a signature or attestation"
		if r := in.releaseUnavailable(id, title, updateRef); r != nil {
			return *r
		}
		sigs := in.Release.ByKind(evidence.KindSignature)
		if len(sigs) == 0 {
			return evidence.Fail(id, title, updateRef,
				fmt.Sprintf("no signature or attestation in %s", in.ReleaseDir),
				"Expected detached signatures (.sig, .asc), a Sigstore bundle (.sigstore.json) or an in-toto attestation (.intoto.jsonl).")
		}

		// A signature over the checksum manifest transitively covers everything
		// the manifest lists — that is the goreleaser/cosign convention.
		manifestSigned := map[string]bool{}
		for _, s := range sigs {
			for _, m := range in.Release.ByKind(evidence.KindChecksums) {
				if strings.HasPrefix(s.Name, m.Name+".") {
					manifestSigned[m.Name] = true
				}
			}
		}
		var manifestCovers map[string]bool
		var manifestNames []string
		for m := range manifestSigned {
			manifestNames = append(manifestNames, m)
			if manifestCovers == nil {
				manifestCovers = map[string]bool{}
			}
			if f, ok := lookup(in.Release, m); ok {
				if data, err := readFile(f.Path); err == nil {
					if entries, err := evidence.ParseChecksums(data); err == nil {
						for _, e := range entries {
							manifestCovers[e.Name] = true
						}
					}
				}
			}
		}

		direct := map[string]bool{}
		for _, s := range sigs {
			for _, f := range in.Release.Files {
				if f.Kind == evidence.KindSignature {
					continue
				}
				if strings.HasPrefix(s.Name, f.Name+".") {
					direct[f.Name] = true
				}
			}
		}

		var signed, unsigned []string
		for _, f := range in.Release.Files {
			if f.Kind == evidence.KindSignature {
				continue
			}
			switch {
			case direct[f.Name]:
				signed = append(signed, f.Name+": detached signature present")
			case manifestCovers[f.Name]:
				signed = append(signed, fmt.Sprintf("%s: covered by the signed checksum manifest (%s)", f.Name, strings.Join(manifestNames, ", ")))
			default:
				unsigned = append(unsigned, f.Name+": no signature and not covered by a signed checksum manifest")
			}
		}

		note := "Presence only: this tool does not verify signatures, which needs the publisher's trust root (cosign key or certificate chain, or the GPG public key)."
		if len(unsigned) > 0 {
			return evidence.Fail(id, title, updateRef,
				fmt.Sprintf("%d of %d files have no signature and are not covered by a signed manifest", len(unsigned), len(unsigned)+len(signed)),
				bullets(append(unsigned, append(signed, note)...))...)
		}
		return evidence.Pass(id, title, updateRef,
			fmt.Sprintf("all %s signed or covered by a signed manifest", plural(len(signed), "file is", "files are")),
			bullets(append(signed, note))...)
	},
}

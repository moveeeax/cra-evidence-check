package checks

import (
	"context"
	"fmt"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
)

const sbomRef = "CRA Annex I, Part II(1) — software bill of materials"

var checkSBOMPresent = Check{
	ID:        "CRA-01",
	Title:     "An SBOM ships with the release",
	Reference: sbomRef,
	Run: func(_ context.Context, in *Input) evidence.Result {
		const id, title = "CRA-01", "An SBOM ships with the release"
		if r := in.releaseUnavailable(id, title, sbomRef); r != nil {
			return *r
		}
		sboms := in.Release.ByKind(evidence.KindSBOM)
		if len(sboms) == 0 {
			var found []string
			for _, f := range in.Release.Files {
				found = append(found, f.Name)
			}
			return evidence.Fail(id, title, sbomRef,
				fmt.Sprintf("no SBOM file in %s", in.ReleaseDir),
				append([]string{
					"Expected a file named bom.json / sbom.json, or ending in .cdx.json, .spdx.json or .spdx.",
				}, bullets(found)...)...)
		}
		var found []string
		for _, f := range sboms {
			found = append(found, fmt.Sprintf("%s (%d bytes, sha256:%s)", f.Name, f.Size, f.SHA256[:16]))
		}
		return evidence.Pass(id, title, sbomRef,
			fmt.Sprintf("%s alongside the release artefacts", plural(len(sboms), "SBOM file", "SBOM files")),
			bullets(found)...)
	},
}

var checkSBOMValid = Check{
	ID:        "CRA-02",
	Title:     "Every SBOM parses as CycloneDX or SPDX",
	Reference: sbomRef,
	Run: func(_ context.Context, in *Input) evidence.Result {
		const id, title = "CRA-02", "Every SBOM parses as CycloneDX or SPDX"
		if r := in.releaseUnavailable(id, title, sbomRef); r != nil {
			return *r
		}
		if len(in.SBOMs) == 0 {
			return evidence.Fail(id, title, sbomRef,
				"no SBOM to parse", "See CRA-01: no SBOM file was found in the release directory.")
		}
		var bad, good []string
		for _, s := range in.SBOMs {
			switch {
			case s.Err != nil:
				bad = append(bad, fmt.Sprintf("%s: %v", s.File.Name, s.Err))
			case len(s.Document.Components) == 0:
				bad = append(bad, fmt.Sprintf("%s: parses as %s %s but declares no components",
					s.File.Name, s.Document.Format, s.Document.SpecVersion))
			default:
				good = append(good, fmt.Sprintf("%s: %s %s, %s",
					s.File.Name, s.Document.Format, s.Document.SpecVersion,
					plural(len(s.Document.Components), "component", "components")))
			}
		}
		if len(bad) > 0 {
			return evidence.Fail(id, title, sbomRef,
				fmt.Sprintf("%s did not parse as a usable CycloneDX or SPDX document", plural(len(bad), "SBOM", "SBOMs")),
				bullets(append(bad, good...))...)
		}
		return evidence.Pass(id, title, sbomRef,
			fmt.Sprintf("%s parsed", plural(len(good), "SBOM", "SBOMs")), bullets(good)...)
	},
}

var checkSBOMCoversArtifact = Check{
	ID:        "CRA-03",
	Title:     "The SBOM covers the shipped artefacts",
	Reference: sbomRef,
	Run: func(_ context.Context, in *Input) evidence.Result {
		const id, title = "CRA-03", "The SBOM covers the shipped artefacts"
		if r := in.releaseUnavailable(id, title, sbomRef); r != nil {
			return *r
		}
		artifacts := in.Release.ByKind(evidence.KindArtifact)
		if len(artifacts) == 0 {
			return evidence.Skip(id, title, sbomRef,
				fmt.Sprintf("no shipped artefacts in %s", in.ReleaseDir),
				"Only SBOMs, signatures and checksum manifests were found; there is nothing to cover.")
		}

		type index struct {
			file   string
			byHash map[string]string // sha256 -> component label
			byName map[string]string // base name -> component label
		}
		var indexes []index
		for _, s := range in.SBOMs {
			if s.Document == nil {
				continue
			}
			ix := index{file: s.File.Name, byHash: map[string]string{}, byName: map[string]string{}}
			for h, c := range s.Document.SHA256Index() {
				ix.byHash[h] = label(c.Name, c.Version)
			}
			for n, c := range s.Document.NameIndex() {
				ix.byName[n] = label(c.Name, c.Version)
			}
			indexes = append(indexes, ix)
		}
		if len(indexes) == 0 {
			return evidence.Fail(id, title, sbomRef,
				"no parseable SBOM to check coverage against",
				"See CRA-01 and CRA-02.")
		}

		var covered, uncovered []string
		for _, a := range artifacts {
			matched := ""
			for _, ix := range indexes {
				if l, ok := ix.byHash[a.SHA256]; ok {
					matched = fmt.Sprintf("%s: matched in %s by SHA-256 (%s)", a.Name, ix.file, l)
					break
				}
			}
			if matched == "" {
				for _, ix := range indexes {
					if l, ok := ix.byName[lower(a.Name)]; ok {
						matched = fmt.Sprintf("%s: matched in %s by name only (%s) — no SHA-256 in the SBOM", a.Name, ix.file, l)
						break
					}
				}
			}
			if matched == "" {
				uncovered = append(uncovered, fmt.Sprintf("%s (sha256:%s) is not referenced by any SBOM", a.Name, a.SHA256))
				continue
			}
			covered = append(covered, matched)
		}

		if len(uncovered) > 0 {
			return evidence.Fail(id, title, sbomRef,
				fmt.Sprintf("%d of %d shipped artefacts have no SBOM entry", len(uncovered), len(artifacts)),
				bullets(append(uncovered, covered...))...)
		}
		return evidence.Pass(id, title, sbomRef,
			fmt.Sprintf("all %s described by an SBOM", plural(len(artifacts), "shipped artefact is", "shipped artefacts are")),
			bullets(covered)...)
	},
}

func label(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

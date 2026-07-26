// Package sbom parses the two SBOM formats the Cyber Resilience Act ecosystem
// has actually standardised on: CycloneDX JSON and SPDX (JSON and tag-value).
//
// The parser is deliberately shallow. It extracts only what an evidence check
// needs — format, spec version, component identity and component digests —
// and does not attempt schema validation or licence analysis.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Format identifies the SBOM encoding.
type Format string

const (
	FormatCycloneDXJSON Format = "cyclonedx-json"
	FormatSPDXJSON      Format = "spdx-json"
	FormatSPDXTagValue  Format = "spdx-tag-value"
)

// Component is one entry in an SBOM.
type Component struct {
	Name     string            `json:"name"`
	Version  string            `json:"version,omitempty"`
	FileName string            `json:"file_name,omitempty"`
	Hashes   map[string]string `json:"hashes,omitempty"` // normalised algorithm -> lowercase hex
	Primary  bool              `json:"primary,omitempty"`
}

// Document is a parsed SBOM.
type Document struct {
	Format      Format      `json:"format"`
	SpecVersion string      `json:"spec_version"`
	Name        string      `json:"name,omitempty"`
	Components  []Component `json:"components"`
}

// ErrUnknownFormat is returned when the payload is neither CycloneDX nor SPDX.
var ErrUnknownFormat = errors.New("not a recognised CycloneDX or SPDX document")

// Parse detects the format and decodes the document.
func Parse(data []byte) (*Document, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		var probe struct {
			BOMFormat   string `json:"bomFormat"`
			SpecVersion string `json:"specVersion"`
			SPDXVersion string `json:"spdxVersion"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		switch {
		case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
			return parseCycloneDX(data)
		case probe.SPDXVersion != "":
			return parseSPDXJSON(data)
		}
		return nil, ErrUnknownFormat
	}
	if strings.Contains(trimmed, "SPDXVersion:") {
		return parseSPDXTagValue(trimmed)
	}
	return nil, ErrUnknownFormat
}

// normaliseAlg maps the algorithm spellings used by CycloneDX ("SHA-256") and
// SPDX ("SHA256") onto one form.
func normaliseAlg(alg string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(alg), "-", ""))
}

// --- CycloneDX ---------------------------------------------------------------

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxComponent struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Type    string    `json:"type"`
	Hashes  []cdxHash `json:"hashes"`
	// Nested components are flattened; assemblies are common in firmware BOMs.
	Components []cdxComponent `json:"components"`
}

type cdxDoc struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Component *cdxComponent `json:"component"`
	} `json:"metadata"`
	Components []cdxComponent `json:"components"`
}

func toComponent(c cdxComponent, primary bool) Component {
	out := Component{Name: c.Name, Version: c.Version, Primary: primary}
	for _, h := range c.Hashes {
		if h.Content == "" {
			continue
		}
		if out.Hashes == nil {
			out.Hashes = map[string]string{}
		}
		out.Hashes[normaliseAlg(h.Alg)] = strings.ToLower(h.Content)
	}
	return out
}

func flattenCDX(in []cdxComponent, primary bool, out *[]Component) {
	for _, c := range in {
		*out = append(*out, toComponent(c, primary))
		flattenCDX(c.Components, false, out)
	}
}

func parseCycloneDX(data []byte) (*Document, error) {
	var doc cdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid CycloneDX JSON: %w", err)
	}
	if doc.SpecVersion == "" {
		return nil, errors.New("CycloneDX document has no specVersion")
	}
	out := &Document{Format: FormatCycloneDXJSON, SpecVersion: doc.SpecVersion}
	if doc.Metadata.Component != nil {
		out.Name = doc.Metadata.Component.Name
		out.Components = append(out.Components, toComponent(*doc.Metadata.Component, true))
		flattenCDX(doc.Metadata.Component.Components, false, &out.Components)
	}
	flattenCDX(doc.Components, false, &out.Components)
	return out, nil
}

// --- SPDX JSON ---------------------------------------------------------------

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxPackage struct {
	SPDXID          string         `json:"SPDXID"`
	Name            string         `json:"name"`
	VersionInfo     string         `json:"versionInfo"`
	PackageFileName string         `json:"packageFileName"`
	Checksums       []spdxChecksum `json:"checksums"`
}

type spdxFile struct {
	SPDXID    string         `json:"SPDXID"`
	FileName  string         `json:"fileName"`
	Checksums []spdxChecksum `json:"checksums"`
}

type spdxDoc struct {
	SPDXVersion       string        `json:"spdxVersion"`
	Name              string        `json:"name"`
	DocumentDescribes []string      `json:"documentDescribes"`
	Packages          []spdxPackage `json:"packages"`
	Files             []spdxFile    `json:"files"`
	Relationships     []struct {
		SPDXElementID      string `json:"spdxElementId"`
		RelationshipType   string `json:"relationshipType"`
		RelatedSPDXElement string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

func spdxHashes(cs []spdxChecksum) map[string]string {
	var m map[string]string
	for _, c := range cs {
		if c.ChecksumValue == "" {
			continue
		}
		if m == nil {
			m = map[string]string{}
		}
		m[normaliseAlg(c.Algorithm)] = strings.ToLower(c.ChecksumValue)
	}
	return m
}

func parseSPDXJSON(data []byte) (*Document, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid SPDX JSON: %w", err)
	}
	described := map[string]bool{}
	for _, id := range doc.DocumentDescribes {
		described[id] = true
	}
	for _, r := range doc.Relationships {
		if strings.EqualFold(r.RelationshipType, "DESCRIBES") {
			described[r.RelatedSPDXElement] = true
		}
	}

	out := &Document{Format: FormatSPDXJSON, SpecVersion: doc.SPDXVersion, Name: doc.Name}
	for _, p := range doc.Packages {
		out.Components = append(out.Components, Component{
			Name:     p.Name,
			Version:  p.VersionInfo,
			FileName: p.PackageFileName,
			Hashes:   spdxHashes(p.Checksums),
			Primary:  described[p.SPDXID],
		})
	}
	for _, f := range doc.Files {
		out.Components = append(out.Components, Component{
			Name:     f.FileName,
			FileName: f.FileName,
			Hashes:   spdxHashes(f.Checksums),
			Primary:  described[f.SPDXID],
		})
	}
	return out, nil
}

// --- SPDX tag-value ----------------------------------------------------------

// parseSPDXTagValue understands the subset of the tag-value grammar that
// carries component identity: PackageName, PackageVersion, PackageFileName,
// PackageChecksum and FileName / FileChecksum.
func parseSPDXTagValue(text string) (*Document, error) {
	out := &Document{Format: FormatSPDXTagValue}
	var cur *Component
	flush := func() {
		if cur != nil {
			out.Components = append(out.Components, *cur)
			cur = nil
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tag, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		tag = strings.TrimSpace(tag)
		value = strings.TrimSpace(value)
		switch tag {
		case "SPDXVersion":
			out.SpecVersion = value
		case "DocumentName":
			out.Name = value
		case "PackageName", "FileName":
			flush()
			cur = &Component{Name: value}
			if tag == "FileName" {
				cur.FileName = value
			}
		case "PackageVersion":
			if cur != nil {
				cur.Version = value
			}
		case "PackageFileName":
			if cur != nil {
				cur.FileName = value
			}
		case "PackageChecksum", "FileChecksum":
			if cur == nil {
				continue
			}
			alg, digest, ok := strings.Cut(value, ":")
			if !ok {
				continue
			}
			if cur.Hashes == nil {
				cur.Hashes = map[string]string{}
			}
			cur.Hashes[normaliseAlg(alg)] = strings.ToLower(strings.TrimSpace(digest))
		}
	}
	flush()
	if out.SpecVersion == "" {
		return nil, errors.New("SPDX tag-value document has no SPDXVersion")
	}
	return out, nil
}

// SHA256Index maps every SHA-256 digest declared anywhere in the document to
// the component that declared it.
func (d *Document) SHA256Index() map[string]Component {
	idx := make(map[string]Component)
	for _, c := range d.Components {
		if h, ok := c.Hashes["SHA256"]; ok && h != "" {
			idx[h] = c
		}
	}
	return idx
}

// NameIndex maps component names and package file names (base names, lowercased)
// to the declaring component.
func (d *Document) NameIndex() map[string]Component {
	idx := make(map[string]Component)
	add := func(k string, c Component) {
		k = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(k), "./"))
		if i := strings.LastIndex(k, "/"); i >= 0 {
			k = k[i+1:]
		}
		if k != "" {
			idx[k] = c
		}
	}
	for _, c := range d.Components {
		add(c.Name, c)
		add(c.FileName, c)
	}
	return idx
}

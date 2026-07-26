package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return data
}

func TestParseCycloneDXFixture(t *testing.T) {
	doc, err := Parse(readFixture(t, "release/complete/acme-gateway.cdx.json"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Format != FormatCycloneDXJSON {
		t.Errorf("format = %q, want %q", doc.Format, FormatCycloneDXJSON)
	}
	if doc.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want 1.5", doc.SpecVersion)
	}
	// 1 metadata component + 3 libraries.
	if len(doc.Components) != 4 {
		t.Fatalf("got %d components, want 4", len(doc.Components))
	}
	if !doc.Components[0].Primary {
		t.Error("the metadata component should be marked primary")
	}
	if len(doc.SHA256Index()) != 1 {
		t.Errorf("SHA256Index has %d entries, want 1", len(doc.SHA256Index()))
	}
	if _, ok := doc.NameIndex()["acme-gateway_1.4.0_linux_amd64.tar.gz"]; !ok {
		t.Errorf("NameIndex is missing the primary component; keys: %v", keys(doc.NameIndex()))
	}
}

func TestParseSPDXJSONFixture(t *testing.T) {
	doc, err := Parse(readFixture(t, "release/spdx/sensor-fw.spdx.json"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Format != FormatSPDXJSON || doc.SpecVersion != "SPDX-2.3" {
		t.Fatalf("got %s %s, want spdx-json SPDX-2.3", doc.Format, doc.SpecVersion)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2", len(doc.Components))
	}
	var primary *Component
	for i := range doc.Components {
		if doc.Components[i].Primary {
			primary = &doc.Components[i]
		}
	}
	if primary == nil {
		t.Fatal("documentDescribes did not mark any package primary")
	}
	if primary.FileName != "sensor-fw_1.1.0.bin" {
		t.Errorf("primary packageFileName = %q", primary.FileName)
	}
	// SPDX spells it SHA256, CycloneDX SHA-256; both must normalise.
	if _, ok := primary.Hashes["SHA256"]; !ok {
		t.Errorf("primary hashes = %v, want a normalised SHA256 key", primary.Hashes)
	}
	if _, ok := doc.NameIndex()["sensor-fw_1.1.0.bin"]; !ok {
		t.Error("NameIndex should index packageFileName")
	}
}

func TestParseSPDXTagValue(t *testing.T) {
	in := `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
DocumentName: relay-1.0.0

PackageName: relay
PackageVersion: 1.0.0
PackageFileName: relay_1.0.0_linux_amd64
PackageChecksum: SHA256: 3fa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f

PackageName: libexpat
PackageVersion: 2.6.2
`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Format != FormatSPDXTagValue {
		t.Fatalf("format = %q", doc.Format)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2: %+v", len(doc.Components), doc.Components)
	}
	got := doc.Components[0]
	if got.Name != "relay" || got.Version != "1.0.0" || got.FileName != "relay_1.0.0_linux_amd64" {
		t.Errorf("first component = %+v", got)
	}
	if got.Hashes["SHA256"] != "3fa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f" {
		t.Errorf("checksum not parsed: %v", got.Hashes)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"truncated json", `{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [`, "invalid JSON"},
		{"json but neither format", `{"hello": "world"}`, "not a recognised"},
		{"plain text", "this is a changelog, not an SBOM", "not a recognised"},
		{"cyclonedx without specVersion", `{"bomFormat":"CycloneDX"}`, "no specVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseBrokenFixture(t *testing.T) {
	if _, err := Parse(readFixture(t, "release/broken-sbom/bom.json")); err == nil {
		t.Fatal("the truncated fixture must not parse")
	}
}

func TestNameIndexNormalisesPaths(t *testing.T) {
	doc := &Document{Components: []Component{{Name: "./dist/App.BIN", FileName: "dist/App.BIN"}}}
	if _, ok := doc.NameIndex()["app.bin"]; !ok {
		t.Errorf("NameIndex should lower-case and take the base name; got %v", keys(doc.NameIndex()))
	}
}

func keys(m map[string]Component) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

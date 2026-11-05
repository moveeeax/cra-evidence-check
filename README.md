# cra-evidence-check

A Go CLI and GitHub Action that reports **machine-checkable engineering evidence**
relevant to the EU Cyber Resilience Act (Regulation (EU) 2024/2847).

Eight checks. Exit code plus a markdown or JSON report. **No score, no maturity
model, no advice.** It answers one question per check — *is this artefact
present, parseable and internally consistent?* — and nothing else.

> This tool is not a conformity assessment, a certification, an audit or legal
> advice. It does not decide whether a product is in scope of the CRA, and it
> cannot tell you whether you are compliant. The CRA references next to each
> check are indicative pointers to the obligation the evidence relates to, not a
> legal mapping.

## The eight checks

| ID | Check | Evidence it looks at |
|---|---|---|
| `CRA-01` | An SBOM ships with the release | a `bom.json` / `*.cdx.json` / `*.spdx.json` / `*.spdx` in the release directory |
| `CRA-02` | Every SBOM parses as CycloneDX or SPDX | CycloneDX JSON, SPDX JSON and SPDX tag-value are decoded; a document with zero components fails |
| `CRA-03` | The SBOM covers the shipped artefacts | each shipped file is matched against the SBOM by SHA-256, falling back to file name |
| `CRA-04` | `security.txt` is present, complete and unexpired | RFC 9116 `Contact` and `Expires`; read from the repo, or fetched over HTTPS with `--domain` |
| `CRA-05` | A disclosure policy exists and is linked | `SECURITY.md` with a reporting address, referenced from the README or from a `security.txt` `Policy` field |
| `CRA-06` | Release artefacts are retained with a verifiable manifest | every shipped file is listed in `checksums.txt` / `SHA256SUMS`, and every SHA-256 is **recomputed and compared** |
| `CRA-07` | Dependency manifests have a committed lockfile | Go, npm/yarn/pnpm, Python, Rust, Ruby, PHP, Swift — including "a `go.mod` with no external requires needs no `go.sum`" and "an unpinned `requirements.txt` is not a lock" |
| `CRA-08` | Release artefacts carry a signature or attestation | `.sig` / `.asc` / `.sigstore.json` / `.intoto.jsonl`, or coverage by a **signed** checksum manifest |

`CRA-08` checks presence, not cryptographic validity: verifying a signature needs
the publisher's trust root, which is not something a linter can assume.

## Install

```sh
go install github.com/moveeeax/cra-evidence-check/cmd/cra-evidence-check@latest
```

Or build from a checkout:

```sh
git clone https://github.com/moveeeax/cra-evidence-check.git
cd cra-evidence-check
make build          # -> bin/cra-evidence-check
```

Requires Go 1.26 or newer. The tool has no dependencies outside the Go
standard library.

## Usage example

Every command below runs against fixtures committed in this repository, so you
can paste them straight after `make build`.

A complete evidence bundle:

```sh
./bin/cra-evidence-check scan \
  --repo testdata/repo/compliant \
  --release-dir testdata/release/complete
```

```
[PASS] CRA-01  An SBOM ships with the release
       1 SBOM file alongside the release artefacts
       - acme-gateway.cdx.json (964 bytes, sha256:06c03af468b87c0b)

[PASS] CRA-03  The SBOM covers the shipped artefacts
       all 1 shipped artefact is described by an SBOM
       - acme-gateway_1.4.0_linux_amd64.tar.gz: matched in acme-gateway.cdx.json by SHA-256 (acme-gateway_1.4.0_linux_amd64.tar.gz@1.4.0)

[PASS] CRA-06  Release artefacts are retained with a verifiable checksum manifest
       all 2 retained files are listed, SHA-256 digests match
       ...

8 passed, 0 failed, 0 skipped
```

Exit code `0`.

A bundle with real gaps:

```sh
./bin/cra-evidence-check scan \
  --repo testdata/repo/gaps \
  --release-dir testdata/release/uncovered \
  --only CRA-03,CRA-05,CRA-07
```

```
[FAIL] CRA-03  The SBOM covers the shipped artefacts
       1 of 2 shipped artefacts have no SBOM entry
       - controller_3.2.0_linux_amd64: matched in controller.cdx.json by SHA-256 (controller_3.2.0_linux_amd64@3.2.0)
       - controller_3.2.0_windows_amd64.exe (sha256:cb0debc8...) is not referenced by any SBOM

[FAIL] CRA-05  A coordinated vulnerability disclosure policy exists and is linked
       no disclosure policy file in the repository
       - Looked for: SECURITY.md, .github/SECURITY.md, docs/SECURITY.md, ...

[FAIL] CRA-07  Dependency manifests have a committed lockfile
       2 of 2 dependency manifests are not pinned by a committed lockfile
       - package.json (npm/yarn/pnpm) has no lockfile; expected one of: package-lock.json, ...
       - scripts/requirements.txt (Python (pip)) has no lockfile; expected one of: requirements.lock

0 passed, 3 failed, 0 skipped
```

Exit code `1`.

Both of these are wired into `make demo`.

### Flags

```
cra-evidence-check scan [flags]

  --repo string          path to the repository root (default ".")
  --release-dir string   directory holding the built release artefacts
  --domain string        public domain to fetch security.txt from, e.g. example.com
  --format string        text, markdown or json (default "text")
  --output string        write the report to this file ('-' is stdout, default "-")
  --only string          comma-separated check IDs, e.g. CRA-01,CRA-02
  --exclude string       directory names to skip when walking the repository
  --strict               treat skipped checks as failures
```

`cra-evidence-check checks` lists the checks and their references.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | every selected check passed |
| `1` | at least one check failed (or was skipped, with `--strict`) |
| `2` | the tool could not run: bad flags, unreadable paths |

Release-scoped checks (`CRA-01`, `-02`, `-03`, `-06`, `-08`) **skip** when
`--release-dir` is not given, and **fail** when it is given but missing. Skips
do not fail the run unless you pass `--strict`.

## GitHub Action

```yaml
- uses: actions/checkout@v7

- name: Build the release
  run: make release        # produces dist/ with artefacts, SBOM, checksums, signatures

- name: CRA evidence check
  uses: moveeeax/cra-evidence-check@v0.1.0
  with:
    repo: "."
    release-dir: dist
    domain: example.com
```

Pin the action to a release tag (as above) or a commit SHA rather than a
branch. The markdown report is appended to the job summary. Inputs: `repo`,
`release-dir`, `domain`, `only`, `exclude`, `strict`, `fail-on-findings`,
`step-summary`. Outputs: `report-path` (JSON report) and `outcome`
(`pass` / `findings`).

To report without blocking a pipeline, set `fail-on-findings: "false"`.

## Machine-readable output

`--format json` emits the whole report, including per-check details, for
archiving next to the release:

```sh
./bin/cra-evidence-check scan \
  --repo testdata/repo/compliant \
  --release-dir testdata/release/spdx \
  --format json --output evidence-report.json
```

## What this deliberately does not do

- It does not decide whether a product is in scope of the CRA (pure SaaS is not).
- It does not score, grade or produce a maturity level.
- It does not generate Annex VII technical documentation.
- It does not verify signatures, submit anything to ENISA, or talk to any
  external service other than the optional `security.txt` fetch.

## Development

```sh
make check     # go vet, go test -race, gofmt check
make test
make demo
```

Fixtures live in `testdata/`:

- `testdata/release/complete` — a clean bundle (CycloneDX, signed manifest)
- `testdata/release/spdx` — the same shape with an SPDX SBOM
- `testdata/release/uncovered` — an artefact missing from the SBOM
- `testdata/release/tampered` — a manifest digest that no longer matches the file
- `testdata/release/broken-sbom` — a truncated SBOM
- `testdata/release/no-sbom` — no SBOM, unsigned manifest
- `testdata/repo/compliant`, `testdata/repo/gaps` — source trees

The digests inside the release fixtures are real: `testdata/**` is marked
`-text` in `.gitattributes` so a checkout cannot rewrite a byte.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Status

v0.1 — the eight checks above, and nothing more.

## License

[MIT](LICENSE) © 2026 Michael Tarassov

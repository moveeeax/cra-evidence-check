# Security policy

## Supported versions

`cra-evidence-check` is pre-1.0. Only the latest tagged release receives fixes.

## Reporting a vulnerability

Report privately through GitHub Security Advisories:

https://github.com/moveeeax/cra-evidence-check/security/advisories/new

Please do not open a public issue for a security report. Include the version
(`cra-evidence-check version`), the command line you ran, and — if the problem
involves a specific input — a minimal SBOM, checksum manifest or `security.txt`
that reproduces it. Do not attach customer material.

## What to expect

- Acknowledgement within five working days.
- An assessment and a remediation plan within fifteen working days.
- A published advisory once a fix is available, crediting the reporter unless
  they ask otherwise.

## Threat model

This tool reads files from a repository and a release directory, and — only
when `--domain` is passed — makes one outbound HTTPS request per well-known
`security.txt` location. It writes nothing except the report. Reports of
path traversal, resource exhaustion on hostile input, or the tool reporting a
`pass` where the evidence is absent are all in scope.

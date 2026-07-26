package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/moveeeax/cra-evidence-check/internal/evidence"
	"github.com/moveeeax/cra-evidence-check/internal/securitytxt"
)

const cvdRef = "CRA Annex I, Part II(5) — coordinated vulnerability disclosure policy and contact address"

// securityTxtRepoPaths are the in-repo locations that commonly get published to
// /.well-known/security.txt by a static site build.
var securityTxtRepoPaths = []string{
	".well-known/security.txt",
	"security.txt",
	"static/.well-known/security.txt",
	"public/.well-known/security.txt",
	"docs/.well-known/security.txt",
	"site/.well-known/security.txt",
	"web/.well-known/security.txt",
}

var checkSecurityTxt = Check{
	ID:        "CRA-04",
	Title:     "security.txt is present, complete and unexpired",
	Reference: cvdRef,
	Run: func(ctx context.Context, in *Input) evidence.Result {
		const id, title = "CRA-04", "security.txt is present, complete and unexpired"

		var file *securitytxt.File
		var details []string

		if in.Domain != "" {
			attempts := securitytxt.Fetch(ctx, in.Fetch, in.Domain)
			for _, a := range attempts {
				if a.Error != nil {
					details = append(details, fmt.Sprintf("GET %s: %v", a.URL, a.Error))
					continue
				}
				details = append(details, fmt.Sprintf("GET %s: 200 OK", a.URL))
				file = a.File
			}
			if file == nil {
				return evidence.Fail(id, title, cvdRef,
					fmt.Sprintf("no security.txt served by %s", in.Domain), details...)
			}
		} else {
			rel, ok := evidence.FirstExisting(in.RepoDir, securityTxtRepoPaths...)
			if !ok {
				return evidence.Fail(id, title, cvdRef,
					"no security.txt in the repository and no --domain given",
					"Looked for: "+strings.Join(securityTxtRepoPaths, ", "),
					"Pass --domain example.com to check the published file instead of the repository copy.")
			}
			data, err := evidence.ReadRepoFile(in.RepoDir, rel)
			if err != nil {
				return evidence.Fail(id, title, cvdRef, fmt.Sprintf("%s could not be read", rel), err.Error())
			}
			file = securitytxt.Parse(rel, data)
			details = append(details, "source: "+rel+" (repository copy — reachability over HTTPS was not checked)")
		}

		var problems []string
		contacts := file.Get("Contact")
		if len(contacts) == 0 {
			problems = append(problems, "required field 'Contact' is missing (RFC 9116 §2.5.3)")
		} else {
			details = append(details, "Contact: "+strings.Join(contacts, ", "))
		}

		switch {
		case file.ExpiresRaw == "":
			problems = append(problems, "required field 'Expires' is missing (RFC 9116 §2.5.5)")
		case file.Expires.IsZero():
			problems = append(problems, fmt.Sprintf("'Expires' value %q is not a valid RFC 3339 timestamp", file.ExpiresRaw))
		case file.Expires.Before(in.Now):
			problems = append(problems, fmt.Sprintf("'Expires' passed on %s", file.Expires.Format("2006-01-02")))
		default:
			details = append(details, fmt.Sprintf("Expires: %s (in %d days)",
				file.Expires.Format("2006-01-02"), int(file.Expires.Sub(in.Now).Hours()/24)))
		}

		if p := file.Get("Policy"); len(p) > 0 {
			details = append(details, "Policy: "+strings.Join(p, ", "))
		} else {
			details = append(details, "note: no 'Policy' field — CRA-05 checks the disclosure policy separately")
		}
		if file.Signed {
			details = append(details, "the file carries a PGP cleartext signature (signature not verified)")
		}

		if len(problems) > 0 {
			return evidence.Fail(id, title, cvdRef,
				fmt.Sprintf("security.txt found at %s but %s", file.Source, plural(len(problems), "field is wrong", "fields are wrong")),
				append(problems, details...)...)
		}
		return evidence.Pass(id, title, cvdRef, "security.txt found with a valid Contact and a future Expires", details...)
	},
}

// cvdPolicyPaths are the conventional locations for a disclosure policy.
var cvdPolicyPaths = []string{
	"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md",
	"SECURITY.rst", "SECURITY.txt", "docs/security.md", "doc/SECURITY.md",
}

var readmePaths = []string{"README.md", "README.rst", "README.txt", "README", "docs/README.md"}

// minPolicyBytes is the size below which a SECURITY.md is a stub, not a policy.
const minPolicyBytes = 200

var checkCVDPolicy = Check{
	ID:        "CRA-05",
	Title:     "A coordinated vulnerability disclosure policy exists and is linked",
	Reference: cvdRef,
	Run: func(_ context.Context, in *Input) evidence.Result {
		const id, title = "CRA-05", "A coordinated vulnerability disclosure policy exists and is linked"

		rel, ok := evidence.FirstExisting(in.RepoDir, cvdPolicyPaths...)
		if !ok {
			return evidence.Fail(id, title, cvdRef,
				"no disclosure policy file in the repository",
				"Looked for: "+strings.Join(cvdPolicyPaths, ", "))
		}
		data, err := evidence.ReadRepoFile(in.RepoDir, rel)
		if err != nil {
			return evidence.Fail(id, title, cvdRef, fmt.Sprintf("%s could not be read", rel), err.Error())
		}
		text := string(data)
		details := []string{fmt.Sprintf("policy file: %s (%d bytes)", rel, len(data))}

		var problems []string
		if len(strings.TrimSpace(text)) < minPolicyBytes {
			problems = append(problems, fmt.Sprintf("%s is only %d bytes — too short to describe a reporting process", rel, len(strings.TrimSpace(text))))
		}
		if !hasContact(text) {
			problems = append(problems, fmt.Sprintf("%s contains no reporting address (no e-mail, no https:// link, no GitHub security advisory link)", rel))
		} else {
			details = append(details, "a reporting address is present in the policy")
		}

		// "Linked" means discoverable: from the README, or from security.txt.
		linked := ""
		if readme, ok := evidence.FirstExisting(in.RepoDir, readmePaths...); ok {
			if body, err := evidence.ReadRepoFile(in.RepoDir, readme); err == nil {
				if referencesPolicy(string(body), rel) {
					linked = readme
				}
			}
		}
		if linked == "" {
			if stRel, ok := evidence.FirstExisting(in.RepoDir, securityTxtRepoPaths...); ok {
				if body, err := evidence.ReadRepoFile(in.RepoDir, stRel); err == nil {
					if len(securitytxt.Parse(stRel, body).Get("Policy")) > 0 {
						linked = stRel + " (Policy field)"
					}
				}
			}
		}
		if linked == "" {
			problems = append(problems, "the policy is not linked from the README or from a security.txt 'Policy' field")
		} else {
			details = append(details, "linked from: "+linked)
		}

		if len(problems) > 0 {
			return evidence.Fail(id, title, cvdRef,
				fmt.Sprintf("%s exists but is not usable as a disclosure policy", rel),
				append(problems, details...)...)
		}
		return evidence.Pass(id, title, cvdRef,
			fmt.Sprintf("%s describes a reporting route and is linked", rel), details...)
	},
}

func hasContact(text string) bool {
	lowered := strings.ToLower(text)
	if strings.Contains(lowered, "https://") || strings.Contains(lowered, "mailto:") {
		return true
	}
	// A bare e-mail address: something@something.tld
	for _, field := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '<' || r == '>' || r == '(' || r == ')' || r == ',' || r == ';'
	}) {
		at := strings.Index(field, "@")
		if at <= 0 || at == len(field)-1 {
			continue
		}
		if strings.Contains(field[at+1:], ".") {
			return true
		}
	}
	return false
}

// referencesPolicy reports whether a README points at the policy file, either
// by path or by the conventional wording.
func referencesPolicy(readme, policyPath string) bool {
	lowered := strings.ToLower(readme)
	base := strings.ToLower(policyPath)
	if strings.Contains(lowered, base) {
		return true
	}
	if i := strings.LastIndex(base, "/"); i >= 0 && strings.Contains(lowered, base[i+1:]) {
		return true
	}
	for _, phrase := range []string{"security policy", "vulnerability disclosure", "reporting a vulnerability", "report a vulnerability"} {
		if strings.Contains(lowered, phrase) {
			return true
		}
	}
	return false
}

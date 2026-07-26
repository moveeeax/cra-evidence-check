package securitytxt

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestParseFields(t *testing.T) {
	f := Parse("test", []byte(`# comment
Contact: mailto:security@example.invalid
Contact: https://example.invalid/report
Expires: 2035-01-01T00:00:00Z
Policy: https://example.invalid/policy
Preferred-Languages: en, de
`))
	if got := f.Get("contact"); len(got) != 2 {
		t.Fatalf("contacts = %v, want 2", got)
	}
	if got := f.Get("CONTACT"); len(got) != 2 {
		t.Error("field lookup must be case-insensitive")
	}
	if f.Expires.Year() != 2035 {
		t.Errorf("Expires = %v", f.Expires)
	}
	if len(f.Get("policy")) != 1 {
		t.Error("Policy not parsed")
	}
	if f.Signed {
		t.Error("this file is not PGP signed")
	}
}

func TestParsePGPWrapped(t *testing.T) {
	f := Parse("test", []byte(`-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Contact: mailto:security@example.invalid
Expires: 2030-06-01T00:00:00Z
-----BEGIN PGP SIGNATURE-----
Contact: mailto:attacker@evil.invalid
-----END PGP SIGNATURE-----
`))
	if !f.Signed {
		t.Error("Signed should be true")
	}
	got := f.Get("Contact")
	if len(got) != 1 || got[0] != "mailto:security@example.invalid" {
		t.Errorf("contacts = %v — fields inside the signature armour must be ignored", got)
	}
	// "Hash: SHA512" is an armour header, not a field.
	if len(f.Get("hash")) != 0 {
		t.Errorf("armour headers leaked into fields: %v", f.Fields)
	}
}

func TestParseBadExpires(t *testing.T) {
	f := Parse("test", []byte("Contact: mailto:a@b.invalid\nExpires: whenever\n"))
	if f.ExpiresRaw != "whenever" {
		t.Errorf("ExpiresRaw = %q", f.ExpiresRaw)
	}
	if !f.Expires.IsZero() {
		t.Error("an unparseable Expires must leave the time zero so the caller can report it")
	}
}

func TestBaseURL(t *testing.T) {
	cases := map[string]string{
		"example.com":           "https://example.com",
		"example.com/":          "https://example.com",
		"https://example.com":   "https://example.com",
		"http://127.0.0.1:8080": "http://127.0.0.1:8080",
	}
	for in, want := range cases {
		if got := BaseURL(in); got != want {
			t.Errorf("BaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFetchFallsBackToRootPath(t *testing.T) {
	var tried []string
	fetch := func(_ context.Context, url string) ([]byte, error) {
		tried = append(tried, url)
		if url == "https://example.invalid/security.txt" {
			return []byte("Contact: mailto:a@b.invalid\nExpires: 2030-01-01T00:00:00Z\n"), nil
		}
		return nil, errors.New("HTTP 404")
	}
	attempts := Fetch(context.Background(), fetch, "example.invalid")
	if len(attempts) != 2 {
		t.Fatalf("attempts = %+v", attempts)
	}
	if attempts[0].Error == nil || attempts[1].File == nil {
		t.Fatalf("expected the well-known path to fail and the root path to succeed: %+v", attempts)
	}
	if tried[0] != "https://example.invalid/.well-known/security.txt" {
		t.Errorf("the canonical location must be tried first, got %q", tried[0])
	}
	if attempts[1].File.Expires.Before(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("Expires not parsed from the fetched file")
	}
}

func TestFetchAllFail(t *testing.T) {
	fetch := func(context.Context, string) ([]byte, error) { return nil, errors.New("dial: no such host") }
	attempts := Fetch(context.Background(), fetch, "nope.invalid")
	for _, a := range attempts {
		if a.File != nil {
			t.Errorf("%s should not have produced a file", a.URL)
		}
	}
}

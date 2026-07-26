// Package securitytxt parses and fetches RFC 9116 "security.txt" files.
package securitytxt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// File is a parsed security.txt.
type File struct {
	Source  string              // where it came from: a repo path or a URL
	Fields  map[string][]string // lowercased field name -> values, in order
	Signed  bool                // wrapped in a PGP cleartext signature
	Expires time.Time           // zero if absent or unparseable
	// ExpiresRaw keeps the original string so an unparseable value can be reported.
	ExpiresRaw string
}

// Get returns the values of a field (case-insensitive).
func (f *File) Get(name string) []string {
	if f == nil {
		return nil
	}
	return f.Fields[strings.ToLower(name)]
}

// Parse reads a security.txt payload. It tolerates the PGP cleartext wrapper
// that RFC 9116 recommends.
func Parse(source string, data []byte) *File {
	f := &File{Source: source, Fields: map[string][]string{}}
	inHeader := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNED MESSAGE-----"):
			f.Signed = true
			inHeader = true
			continue
		case strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNATURE-----"):
			// Everything after the signature block is armour, not fields.
			return finish(f)
		case inHeader:
			// The armour header block ends at the first blank line.
			if trimmed == "" {
				inHeader = false
			}
			continue
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		}
		name, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		f.Fields[name] = append(f.Fields[name], value)
	}
	return finish(f)
}

func finish(f *File) *File {
	if v := f.Fields["expires"]; len(v) > 0 {
		f.ExpiresRaw = v[0]
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02"} {
			if t, err := time.Parse(layout, v[0]); err == nil {
				f.Expires = t.UTC()
				break
			}
		}
	}
	return f
}

// WellKnownPaths are the locations RFC 9116 allows, canonical location first.
var WellKnownPaths = []string{"/.well-known/security.txt", "/security.txt"}

// Fetcher retrieves a URL. It exists so tests do not need the network.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// HTTPFetcher returns a Fetcher backed by the given client.
func HTTPFetcher(client *http.Client) Fetcher {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "cra-evidence-check")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return body, nil
	}
}

// BaseURL turns a bare domain into an https base URL. A domain that already
// carries a scheme is returned unchanged, which is what lets tests point the
// check at an httptest server.
func BaseURL(domain string) string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), "/")
	if strings.Contains(domain, "://") {
		return domain
	}
	return "https://" + domain
}

// FetchResult records one attempted location.
type FetchResult struct {
	URL   string
	File  *File
	Error error
}

// Fetch tries the well-known locations in order and returns every attempt.
// The first successful attempt has a non-nil File.
func Fetch(ctx context.Context, fetch Fetcher, domain string) []FetchResult {
	base := BaseURL(domain)
	var attempts []FetchResult
	for _, p := range WellKnownPaths {
		url := base + p
		body, err := fetch(ctx, url)
		if err != nil {
			attempts = append(attempts, FetchResult{URL: url, Error: err})
			continue
		}
		attempts = append(attempts, FetchResult{URL: url, File: Parse(url, body)})
		return attempts
	}
	return attempts
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

// VirusTotalResult holds the fields we care about from a VirusTotal file report.
// It's used across the codebase: in cache entries, JSON output, and print functions.
type VirusTotalResult struct {
	Found       bool   `json:"found"`        // true if VirusTotal has a report for this hash
	Name        string `json:"name"`         // meaningful_name from the report
	Reputation  int    `json:"reputation"`   // reputation score
	Malicious   int    `json:"malicious"`    // number of engines that flagged as malicious
	Suspicious  int    `json:"suspicious"`   // number of engines that flagged as suspicious
	Undetected  int    `json:"undetected"`   // number of engines that didn't detect it
	Harmless    int    `json:"harmless"`     // number of engines that flagged as harmless
	ThreatLabel string `json:"threat_label"` // suggested threat label, if any
}

// lookupConfig bundles the "environment" needed for a VirusTotal lookup.
//
// Go idiom: when a function grows a long parameter list made up mostly of
// configuration values, group them into a struct. This keeps call sites
// readable and makes it easy to add new options later without touching
// every caller.
type lookupConfig struct {
	ctx          context.Context
	client       *http.Client
	apiKey       string
	output       string
	cache        map[string]cacheEntry
	refresh      bool
	cacheAgeDays int
	limiter      *rate.Limiter
}

// lookupAndPrint is the central "do the thing" function: it checks the
// cache, calls the VirusTotal API if needed, prints the result in the
// chosen format, and returns the result to the caller.
//
// Combining lookup + print in one function keeps the three call sites
// (raw hash, single file, directory walk) simple — they each call this
// one function instead of repeating cache/API/print logic.
//
// Go idiom: returning (VirusTotalResult, error) is the standard Go
// "result, error" pattern. The caller checks err first; if nil, the
// result is valid.
//
// The cfg parameter groups together the "environment" for a lookup
// (HTTP client, API key, cache, output mode, etc.) so call sites only
// pass the per-lookup data (path and hash).
func lookupAndPrint(path, hash string, cfg lookupConfig) (VirusTotalResult, error) {
	// ── Cache Check ─────────────────────────────────────────────────
	//
	// Unless -refresh was passed, try to serve from cache. The
	// "comma ok" idiom (entry, ok := cache[hash]) is how you check
	// for map key existence in Go — ok is true if the key was found.
	if !cfg.refresh {
		if entry, ok := cfg.cache[hash]; ok {
			age := time.Since(entry.Timestamp)
			if age < time.Duration(cfg.cacheAgeDays)*24*time.Hour {
				// Cache hit — result is fresh enough, skip the API call.
				switch cfg.output {
				case "json":
					if err := printJSON(path, hash, entry.Result); err != nil {
						return VirusTotalResult{}, err
					}
				default:
					printResult(hash, entry.Result)
				}
				return entry.Result, nil
			}
			// Cache entry exists but is too old — fall through to API call.
		}
	}

	// ── Rate Limit ──────────────────────────────────────────────────
	//
	// Wait for a token from the rate limiter before making an API call.
	// This is intentionally placed AFTER the cache check — cache hits
	// don't consume rate limit tokens, which is the key improvement
	// over the old approach of sleeping before every file regardless.
	if err := waitForRateLimit(cfg.ctx, cfg.limiter); err != nil {
		return VirusTotalResult{}, fmt.Errorf("rate limiter: %w", err)
	}

	// ── API Call ─────────────────────────────────────────────────────
	//
	// Cache miss (or -refresh forced): query VirusTotal.
	result, err := checkVirusTotal(cfg.ctx, cfg.client, cfg.apiKey, hash)
	if err != nil {
		return VirusTotalResult{}, err
	}

	// Store the fresh result in the in-memory cache. The cache is
	// flushed to disk by the deferred flushCache() in run() on return.
	cfg.cache[hash] = cacheEntry{
		Result:    result,
		Timestamp: time.Now(),
	}

	// ── Output ──────────────────────────────────────────────────────
	switch cfg.output {
	case "json":
		if err := printJSON(path, hash, result); err != nil {
			return VirusTotalResult{}, err
		}
	default:
		printResult(hash, result)
	}
	return result, nil
}

// ── Rate Limiting Helpers ────────────────────────────────────────────
//
// waitForRateLimit blocks until the token bucket grants a token, then
// adds random jitter (0–3 seconds) to prevent exactly periodic requests.
//
// If limiter is nil, it returns immediately — this is the "no rate
// limiting" path for premium users or single-file lookups without -free.
//
// Why jitter? Even with a token bucket, perfectly periodic requests
// (e.g. exactly every 15.000s) can trigger server-side bot detection.
// Adding 0–3s of randomness makes the traffic pattern look more natural.
// For free tier (4 req/min = 15s spacing), 0–3s jitter keeps us well
// within the limit (15–18s between requests).
func waitForRateLimit(ctx context.Context, limiter *rate.Limiter) error {
	if limiter == nil {
		return nil
	}
	if err := limiter.Wait(ctx); err != nil {
		return err
	}
	jitter := time.Duration(rand.Intn(3000)) * time.Millisecond
	time.Sleep(jitter)
	return nil
}

// parseRetryAfter parses the HTTP Retry-After header value into a
// time.Duration. The header can be either:
//   - An integer number of seconds (e.g. "60")
//   - An HTTP-date in RFC 1123 format (e.g. "Wed, 21 Oct 2025 07:28:00 GMT")
//
// If the header is missing or unparseable, we return a conservative
// 60-second default — better to wait too long than to hammer the API
// and risk a ban.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 60 * time.Second
	}
	// Most APIs (including VT) send seconds as a plain integer.
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	// Fall back to RFC 1123 date format (rare, but part of the HTTP spec).
	if t, err := time.Parse(time.RFC1123, header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 60 * time.Second
}

// checkVirusTotal queries the VirusTotal v3 API for a file report by
// SHA-256 hash. It retries up to 3 times on HTTP 429 (rate limited),
// using the Retry-After header to determine wait time.
//
// Return behavior:
//   - HTTP 404 → (VirusTotalResult{Found: false}, nil) — hash not in VT
//   - HTTP 200 → parsed result with Found: true
//   - HTTP 429 → retry with backoff (up to maxRetries times)
//   - Any other status → error with truncated response body for debugging
//
// The caller passes in a shared *http.Client so that Go's internal
// connection pool can reuse TCP connections across multiple lookups.
//
// Why retry here instead of in the caller? Because 429 handling is an
// HTTP-level concern — the caller (lookupAndPrint) shouldn't need to
// know about HTTP status codes or retry semantics.
func checkVirusTotal(ctx context.Context, client *http.Client, apiKey, hash string) (VirusTotalResult, error) {
	const maxRetries = 3

	for attempt := range maxRetries {
		// Build the GET request with context so it can be cancelled
		// (e.g. on Ctrl+C). http.NewRequestWithContext attaches the
		// context to the request — if the context is cancelled, the
		// HTTP client aborts the in-flight request immediately.
		req, err := http.NewRequestWithContext(ctx, "GET", "https://www.virustotal.com/api/v3/files/"+hash, nil)
		if err != nil {
			return VirusTotalResult{}, err
		}
		// VirusTotal authenticates via an API key in a custom header.
		req.Header.Set("x-apikey", apiKey)

		// client.Do sends the request and returns the response.
		response, err := client.Do(req)
		if err != nil {
			return VirusTotalResult{}, err
		}

		// Read the entire response body into memory so we can both check
		// the status code and parse the JSON.
		//
		// Note: we use explicit Close() instead of defer because we're
		// in a loop. defer only runs when the function returns, so
		// deferring inside a loop would keep all response bodies open
		// until the function exits — a resource leak.
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return VirusTotalResult{}, err
		}

		// ── Handle 429 (rate limited) ───────────────────────────────
		//
		// VT returns 429 when you've exceeded your API quota. The
		// Retry-After header tells us how long to wait. We parse it
		// with parseRetryAfter() (which handles both integer seconds
		// and RFC 1123 date formats) and sleep before retrying.
		//
		// The select statement makes the wait cancellable — if the
		// user presses Ctrl+C during a retry wait, we bail out
		// immediately instead of sleeping for the full duration.
		if response.StatusCode == 429 {
			if attempt == maxRetries-1 {
				return VirusTotalResult{}, fmt.Errorf("rate limited by VirusTotal after %d retries", maxRetries)
			}
			wait := parseRetryAfter(response.Header.Get("Retry-After"))
			fmt.Fprintf(os.Stderr, "Rate limited (429), retrying in %s...\n", wait)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return VirusTotalResult{}, ctx.Err()
			}
			continue
		}

		// 404 = hash not found in VirusTotal's database. This is a normal
		// condition (not an error) — the file simply hasn't been scanned.
		if response.StatusCode == 404 {
			return VirusTotalResult{Found: false}, nil
		}
		if response.StatusCode != 200 {
			// For non-200/404 responses (e.g. 403 bad key),
			// include a truncated body snippet in the error so the user can
			// see what VT said.
			bodyStr := truncateRunes(string(body), 200)
			return VirusTotalResult{}, fmt.Errorf("unexpected status: %d: %s", response.StatusCode, bodyStr)
		}

		// ── Parse the VT API v3 response ────────────────────────────
		//
		// Go idiom: anonymous struct for one-off JSON parsing. We define
		// the struct inline because it's only used here. The nested shape
		// mirrors the VT API response structure:
		//   { "data": { "attributes": { ... } } }
		//
		// We only declare the fields we care about — Go's JSON decoder
		// silently ignores any extra fields in the response, which makes
		// our code resilient to API additions.
		var result struct {
			Data struct {
				Attributes struct {
					MeaningfulName    string `json:"meaningful_name"`
					Reputation        int    `json:"reputation"`
					LastAnalysisStats struct {
						Malicious  int `json:"malicious"`
						Suspicious int `json:"suspicious"`
						Undetected int `json:"undetected"`
						Harmless   int `json:"harmless"`
					} `json:"last_analysis_stats"`
					PopularThreatClassification struct {
						SuggestedThreatLabel string `json:"suggested_threat_label"`
					} `json:"popular_threat_classification"`
				} `json:"attributes"`
			} `json:"data"`
		}

		// json.Unmarshal parses the raw JSON bytes into our struct.
		// fmt.Errorf with %w wraps the original error so callers can
		// unwrap it with errors.Is/errors.As if needed.
		if err := json.Unmarshal(body, &result); err != nil {
			return VirusTotalResult{}, fmt.Errorf("parsing response: %w", err)
		}

		// Map the deeply nested API response into our flat result struct.
		stats := result.Data.Attributes.LastAnalysisStats
		return VirusTotalResult{
			Found:       true,
			Name:        result.Data.Attributes.MeaningfulName,
			Reputation:  result.Data.Attributes.Reputation,
			Malicious:   stats.Malicious,
			Suspicious:  stats.Suspicious,
			Undetected:  stats.Undetected,
			Harmless:    stats.Harmless,
			ThreatLabel: result.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel,
		}, nil
	}

	// This is unreachable in practice — the loop always returns on
	// success, non-429 error, or final retry. But Go requires all
	// code paths to have a return statement.
	return VirusTotalResult{}, fmt.Errorf("exhausted %d retries", maxRetries)
}

// truncateRunes returns s truncated to at most max runes, with "..."
// appended if it was truncated.
//
// Why runes instead of bytes? In Go, strings are byte sequences, but a
// single character (like an emoji or accented letter) can be multiple
// bytes. Converting to []rune gives us actual characters, so we truncate
// at a clean character boundary instead of potentially splitting a
// multi-byte character in half and producing garbled output.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}

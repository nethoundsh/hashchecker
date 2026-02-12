package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

// VirusTotalResult holds the fields we care about from a VT file report.
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

type lookupConfig struct {
	ctx          context.Context
	client       *http.Client
	apiKey       string
	output       string
	algo         string // hash algorithm: "sha256", "sha1", or "md5"
	cache        map[string]cacheEntry
	refresh      bool
	cacheAgeDays int
	limiter      *rate.Limiter
	baseURL      string // base URL for VT API; empty defaults to production
}

// lookup checks the cache and calls the VirusTotal API if needed,
// returning the result without printing anything.
func lookup(hash string, cfg lookupConfig) (VirusTotalResult, error) {
	// Cache key is "algo:hash" so results from different algorithms don't collide.
	cacheKey := cfg.algo + ":" + hash
	if !cfg.refresh {
		if entry, ok := cfg.cache[cacheKey]; ok {
			age := time.Since(entry.Timestamp)
			if age < time.Duration(cfg.cacheAgeDays)*24*time.Hour {
				return entry.Result, nil
			}
		}
	}

	// Rate limit is intentionally placed AFTER the cache check —
	// cache hits don't consume rate limit tokens.
	if err := waitForRateLimit(cfg.ctx, cfg.limiter); err != nil {
		return VirusTotalResult{}, fmt.Errorf("rate limiter: %w", err)
	}

	result, err := checkVirusTotal(cfg.ctx, cfg.client, cfg.apiKey, hash, cfg.baseURL)
	if err != nil {
		return VirusTotalResult{}, err
	}

	// Store fresh result; cache is flushed to disk by deferred flushCache() in run().
	cfg.cache[cacheKey] = cacheEntry{
		Result:    result,
		Timestamp: time.Now(),
	}

	return result, nil
}

// waitForRateLimit blocks until the rate limiter grants a token, then
// adds random jitter to avoid exactly periodic requests that can trigger
// server-side bot detection. Returns immediately if limiter is nil.
func waitForRateLimit(ctx context.Context, limiter *rate.Limiter) error {
	if limiter == nil {
		return nil
	}
	if err := limiter.Wait(ctx); err != nil {
		return err
	}
	// Jitter prevents exactly periodic requests (e.g. every 15.000s)
	// which can trigger bot detection on VT's side.
	jitter := time.Duration(rand.N(3000)) * time.Millisecond
	time.Sleep(jitter)
	return nil
}

// parseRetryAfter parses the Retry-After header (integer seconds or
// RFC 1123 date). Returns 60s default if missing or unparseable.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 60 * time.Second
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if t, err := time.Parse(time.RFC1123, header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 60 * time.Second
}

// checkVirusTotal queries the VT v3 API for a file report by hash.
// Retries up to 3 times on HTTP 429 using the Retry-After header.
func checkVirusTotal(ctx context.Context, client *http.Client, apiKey, hash, baseURL string) (VirusTotalResult, error) {
	if baseURL == "" {
		baseURL = "https://www.virustotal.com/api/v3/files/"
	}
	const maxRetries = 3

	for attempt := range maxRetries {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+hash, nil)
		if err != nil {
			return VirusTotalResult{}, fmt.Errorf("checking virustotal %s: %w", hash, err)
		}
		req.Header.Set("x-apikey", apiKey)

		response, err := client.Do(req)
		if err != nil {
			return VirusTotalResult{}, fmt.Errorf("checking virustotal %s: %w", hash, err)
		}

		// Explicit Close() instead of defer — we're in a loop.
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if err != nil {
			return VirusTotalResult{}, fmt.Errorf("reading virustotal response for %s: %w", hash, err)
		}

		if response.StatusCode == 429 {
			if attempt == maxRetries-1 {
				return VirusTotalResult{}, fmt.Errorf("checking virustotal %s: rate limited after %d retries", hash, maxRetries)
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

		if response.StatusCode == 404 {
			return VirusTotalResult{Found: false}, nil
		}
		if response.StatusCode != 200 {
			bodyStr := truncateRunes(string(body), 200)
			return VirusTotalResult{}, fmt.Errorf("checking virustotal %s: unexpected status: %d: %s", hash, response.StatusCode, bodyStr)
		}

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

		if err := json.Unmarshal(body, &result); err != nil {
			return VirusTotalResult{}, fmt.Errorf("checking virustotal %s: parsing response: %w", hash, err)
		}

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

	return VirusTotalResult{}, fmt.Errorf("exhausted %d retries", maxRetries)
}

// truncateRunes returns s truncated to at most max runes, appending "..."
// if truncated. Uses runes to avoid splitting multi-byte characters.
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

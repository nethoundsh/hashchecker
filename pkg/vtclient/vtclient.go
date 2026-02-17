package vtclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Result holds the fields we care about from a VT file report.
type Result struct {
	Found       bool   `json:"found"`
	Name        string `json:"name"`
	Reputation  int    `json:"reputation"`
	Malicious   int    `json:"malicious"`
	Suspicious  int    `json:"suspicious"`
	Undetected  int    `json:"undetected"`
	Harmless    int    `json:"harmless"`
	ThreatLabel string `json:"threat_label"`
}

type CacheEntry struct {
	Result    Result    `json:"result"`
	Timestamp time.Time `json:"timestamp"`
}

type Client struct {
	Ctx        context.Context
	HTTPClient *http.Client
	APIKey     string
	BaseURL    string
	Limiter    *rate.Limiter
}

type CacheConfig struct {
	Entries    map[string]CacheEntry
	Mu         *sync.Mutex
	Refresh    bool
	MaxAgeDays int
}

type LookupConfig struct {
	VT     Client
	Cache  CacheConfig
	Output string
	Algo   string
}

// LookupConfig is passed by value, but it intentionally contains interior
// pointers/sync primitives (Cache.Entries map, Cache.Mu pointer, HTTP client
// pointer, limiter pointer). Callers can safely pass copies per operation while
// still sharing cache and transport state.
//
// Lookup checks cache and calls VirusTotal API if needed.
func Lookup(hash string, cfg LookupConfig) (Result, error) {
	cacheKey := cfg.Algo + ":" + hash
	if !cfg.Cache.Refresh {
		cfg.Cache.Mu.Lock()
		entry, ok := cfg.Cache.Entries[cacheKey]
		cfg.Cache.Mu.Unlock()
		if ok {
			age := time.Since(entry.Timestamp)
			if age < time.Duration(cfg.Cache.MaxAgeDays)*24*time.Hour {
				return entry.Result, nil
			}
		}
	}

	if err := waitForRateLimit(cfg.VT.Ctx, cfg.VT.Limiter); err != nil {
		return Result{}, fmt.Errorf("rate limiter: %w", err)
	}

	result, err := checkVirusTotal(cfg.VT.Ctx, cfg.VT.HTTPClient, cfg.VT.APIKey, hash, cfg.VT.BaseURL)
	if err != nil {
		return Result{}, err
	}

	cfg.Cache.Mu.Lock()
	cfg.Cache.Entries[cacheKey] = CacheEntry{
		Result:    result,
		Timestamp: time.Now(),
	}
	cfg.Cache.Mu.Unlock()

	return result, nil
}

// MigrateLegacyCacheKeys migrates bare-hash cache keys to algo-prefixed format.
func MigrateLegacyCacheKeys(cache map[string]CacheEntry) {
	for key, entry := range cache {
		if !strings.Contains(key, ":") {
			cache["sha256:"+key] = entry
			delete(cache, key)
		}
	}
}

func waitForRateLimit(ctx context.Context, limiter *rate.Limiter) error {
	if limiter == nil {
		return nil
	}
	if err := limiter.Wait(ctx); err != nil {
		return err
	}
	jitter := time.Duration(rand.N(3000)) * time.Millisecond
	timer := time.NewTimer(jitter)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

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

func checkVirusTotal(ctx context.Context, client *http.Client, apiKey, hash, baseURL string) (Result, error) {
	if baseURL == "" {
		baseURL = "https://www.virustotal.com/api/v3/files/"
	}
	const maxAttempts = 3

	for attempt := range maxAttempts {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+hash, nil)
		if err != nil {
			return Result{}, fmt.Errorf("checking virustotal %s: %w", hash, err)
		}
		req.Header.Set("x-apikey", apiKey)

		response, err := client.Do(req)
		if err != nil {
			return Result{}, fmt.Errorf("checking virustotal %s: %w", hash, err)
		}

		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if err != nil {
			return Result{}, fmt.Errorf("reading virustotal response for %s: %w", hash, err)
		}

		if response.StatusCode == 429 {
			if attempt == maxAttempts-1 {
				return Result{}, fmt.Errorf("checking virustotal %s: rate limited after %d retries", hash, maxAttempts-1)
			}
			wait := parseRetryAfter(response.Header.Get("Retry-After"))
			fmt.Fprintf(os.Stderr, "Rate limited (429), retrying in %s...\n", wait)
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return Result{}, ctx.Err()
			}
			continue
		}

		if response.StatusCode == 404 {
			return Result{Found: false}, nil
		}
		if response.StatusCode != 200 {
			bodyStr := truncateRunes(string(body), 200)
			return Result{}, fmt.Errorf("checking virustotal %s: unexpected status: %d: %s", hash, response.StatusCode, bodyStr)
		}

		var parsed struct {
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

		if err := json.Unmarshal(body, &parsed); err != nil {
			return Result{}, fmt.Errorf("checking virustotal %s: parsing response: %w", hash, err)
		}
		stats := parsed.Data.Attributes.LastAnalysisStats
		return Result{
			Found:       true,
			Name:        parsed.Data.Attributes.MeaningfulName,
			Reputation:  parsed.Data.Attributes.Reputation,
			Malicious:   stats.Malicious,
			Suspicious:  stats.Suspicious,
			Undetected:  stats.Undetected,
			Harmless:    stats.Harmless,
			ThreatLabel: parsed.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel,
		}, nil
	}
	return Result{}, fmt.Errorf("exhausted %d attempts", maxAttempts)
}

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

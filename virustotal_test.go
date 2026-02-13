package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// vtJSON returns a valid VirusTotal API v3 JSON response body with
// the given analysis stats. This avoids duplicating the nested JSON
// structure in every test case.
func vtJSON(name string, reputation, malicious, suspicious, undetected, harmless int, threatLabel string) string {
	return fmt.Sprintf(`{
		"data": {
			"attributes": {
				"meaningful_name": %q,
				"reputation": %d,
				"last_analysis_stats": {
					"malicious": %d,
					"suspicious": %d,
					"undetected": %d,
					"harmless": %d
				},
				"popular_threat_classification": {
					"suggested_threat_label": %q
				}
			}
		}
	}`, name, reputation, malicious, suspicious, undetected, harmless, threatLabel)
}

func TestCheckVirusTotal(t *testing.T) {
	// Go idiom: httptest.NewServer creates a real HTTP server on localhost.
	// It's the standard way to test HTTP clients in Go without mocking
	// interfaces. The server's .URL field gives you the base URL to pass
	// to your client code.

	const testHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantFound bool
		wantMal   int
		wantErr   string
		cancelCtx bool
	}{
		{
			name: "200 success with malicious",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = fmt.Fprint(w, vtJSON("malware.exe", -5, 42, 3, 10, 50, "trojan.generic"))
			},
			wantFound: true,
			wantMal:   42,
		},
		{
			name: "200 clean file",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = fmt.Fprint(w, vtJSON("clean.pdf", 0, 0, 0, 5, 60, ""))
			},
			wantFound: true,
			wantMal:   0,
		},
		{
			name: "404 not found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
				_, _ = fmt.Fprint(w, `{"error":{"code":"NotFoundError"}}`)
			},
			wantFound: false,
		},
		{
			name: "429 then 200 success",
			handler: func() http.HandlerFunc {
				var calls atomic.Int32
				return func(w http.ResponseWriter, r *http.Request) {
					if calls.Add(1) == 1 {
						w.Header().Set("Retry-After", "1")
						w.WriteHeader(429)
						return
					}
					w.WriteHeader(200)
					_, _ = fmt.Fprint(w, vtJSON("retried.exe", 0, 1, 0, 0, 60, ""))
				}
			}(),
			wantFound: true,
			wantMal:   1,
		},
		{
			name: "429 exhausted retries",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(429)
			},
			wantErr: "rate limited",
		},
		{
			name: "403 bad key",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				_, _ = fmt.Fprint(w, `{"error":{"code":"ForbiddenError","message":"Wrong API key"}}`)
			},
			wantErr: "unexpected status: 403",
		},
		{
			name: "200 bad JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = fmt.Fprint(w, `{not valid json}`)
			},
			wantErr: "parsing response",
		},
		{
			name: "context cancelled",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(5 * time.Second)
				w.WriteHeader(200)
			},
			cancelCtx: true,
			wantErr:   "context canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			ctx := context.Background()
			var cancel context.CancelFunc
			if tt.cancelCtx {
				ctx, cancel = context.WithCancel(ctx)
				cancel() // cancel immediately
			}
			_ = cancel // avoid unused variable if not cancelCtx

			client := srv.Client()
			client.Timeout = 3 * time.Second

			result, err := checkVirusTotal(ctx, client, "test-api-key", testHash, srv.URL+"/")

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Found != tt.wantFound {
				t.Fatalf("Found = %v, want %v", result.Found, tt.wantFound)
			}
			if result.Malicious != tt.wantMal {
				t.Fatalf("Malicious = %d, want %d", result.Malicious, tt.wantMal)
			}
		})
	}
}

func TestCheckVirusTotalSendsAPIKey(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-apikey")
		w.WriteHeader(404)
	}))
	defer srv.Close()

	_, _ = checkVirusTotal(context.Background(), srv.Client(), "my-secret-key", "abc123", srv.URL+"/")
	if gotKey != "my-secret-key" {
		t.Fatalf("x-apikey header = %q, want %q", gotKey, "my-secret-key")
	}
}

func TestLookup(t *testing.T) {
	const testHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name         string
		cache        map[string]cacheEntry
		refresh      bool
		wantAPICalls int32
		wantFound    bool
	}{
		{
			name:         "cache miss calls API",
			cache:        make(map[string]cacheEntry),
			wantAPICalls: 1,
			wantFound:    true,
		},
		{
			name: "cache hit skips API",
			cache: map[string]cacheEntry{
				"sha256:" + testHash: {
					Result: VirusTotalResult{
						Found: true, Name: "from-cache.exe", Malicious: 3,
					},
					Timestamp: time.Now(),
				},
			},
			wantAPICalls: 0,
			wantFound:    true,
		},
		{
			name: "expired cache calls API",
			cache: map[string]cacheEntry{
				"sha256:" + testHash: {
					Result: VirusTotalResult{
						Found: true, Name: "old-cache.exe",
					},
					Timestamp: time.Now().Add(-30 * 24 * time.Hour),
				},
			},
			wantAPICalls: 1,
			wantFound:    true,
		},
		{
			name: "refresh bypasses cache",
			cache: map[string]cacheEntry{
				"sha256:" + testHash: {
					Result:    VirusTotalResult{Found: true, Name: "cached.exe"},
					Timestamp: time.Now(),
				},
			},
			refresh:      true,
			wantAPICalls: 1,
			wantFound:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var apiCalls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				apiCalls.Add(1)
				w.WriteHeader(200)
				_, _ = fmt.Fprint(w, vtJSON("cached-file.exe", 0, 5, 0, 2, 55, ""))
			}))
			defer srv.Close()

			cfg := lookupConfig{
				vt: vtClient{
					ctx:     context.Background(),
					client:  srv.Client(),
					apiKey:  "test-key",
					baseURL: srv.URL + "/",
					limiter: nil,
				},
				cache: cacheConfig{
					entries:    tt.cache,
					mu:         &sync.Mutex{},
					refresh:    tt.refresh,
					maxAgeDays: 7,
				},
				output: "text",
				algo:   "sha256",
			}

			result, err := lookup(testHash, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Found != tt.wantFound {
				t.Fatalf("Found = %v, want %v", result.Found, tt.wantFound)
			}
			if got := apiCalls.Load(); got != tt.wantAPICalls {
				t.Fatalf("API calls = %d, want %d", got, tt.wantAPICalls)
			}
		})
	}
}

func TestWaitForRateLimit(t *testing.T) {
	t.Run("nil limiter returns immediately", func(t *testing.T) {
		err := waitForRateLimit(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("fast limiter succeeds", func(t *testing.T) {
		// 1000 req/min = basically instant
		limiter := rate.NewLimiter(rate.Every(time.Minute/1000), 1)
		err := waitForRateLimit(context.Background(), limiter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("cancelled context returns error", func(t *testing.T) {
		// Slow limiter that will block — combined with cancelled context
		limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
		// Drain the single burst token
		_ = limiter.Wait(context.Background())

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := waitForRateLimit(ctx, limiter)
		if err == nil {
			t.Fatal("expected error for cancelled context, got nil")
		}
	})
}

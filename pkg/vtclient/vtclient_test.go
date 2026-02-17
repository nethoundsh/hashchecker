package vtclient

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

func TestTruncateRunes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{name: "shorter than max", in: "hello", max: 10, want: "hello"},
		{name: "exactly max", in: "hello", max: 5, want: "hello"},
		{name: "longer than max", in: "hello world", max: 5, want: "hello..."},
		{name: "empty string with positive max", in: "", max: 5, want: ""},
		{name: "max zero", in: "hello", max: 0, want: ""},
		{name: "max negative", in: "hello", max: -1, want: ""},
		{name: "multi-byte runes truncate cleanly", in: "héllo", max: 3, want: "hél..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateRunes(tt.in, tt.max); got != tt.want {
				t.Fatalf("truncateRunes(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want time.Duration
	}{
		{name: "empty string default", in: "", want: 60 * time.Second},
		{name: "integer thirty", in: "30", want: 30 * time.Second},
		{name: "integer one", in: "1", want: 1 * time.Second},
		{name: "zero falls back to default", in: "0", want: 60 * time.Second},
		{name: "negative falls back to default", in: "-5", want: 60 * time.Second},
		{name: "non-numeric garbage", in: "not-a-number", want: 60 * time.Second},
		{name: "RFC1123 date in the future", in: time.Now().Add(30 * time.Second).UTC().Format(time.RFC1123), want: 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRetryAfter(tt.in)
			if tt.name == "RFC1123 date in the future" {
				diff := got - tt.want
				if diff < 0 {
					diff = -diff
				}
				if diff > 2*time.Second {
					t.Fatalf("parseRetryAfter(%q) = %v, want ~%v (±2s)", tt.in, got, tt.want)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("parseRetryAfter(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestMigrateLegacyCacheKeys(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cache := map[string]CacheEntry{
		"abc123": {
			Result:    Result{Found: true, Name: "legacy.exe", Malicious: 1},
			Timestamp: now,
		},
		"sha256:def456": {
			Result:    Result{Found: true, Name: "already-migrated.exe"},
			Timestamp: now,
		},
	}
	MigrateLegacyCacheKeys(cache)

	if _, ok := cache["abc123"]; ok {
		t.Fatal("bare key 'abc123' should have been migrated")
	}
	if _, ok := cache["sha256:abc123"]; !ok {
		t.Fatal("expected migrated key 'sha256:abc123'")
	}
	if cache["sha256:abc123"].Result.Name != "legacy.exe" {
		t.Fatalf("migrated entry Name = %q, want %q", cache["sha256:abc123"].Result.Name, "legacy.exe")
	}
	if _, ok := cache["sha256:def456"]; !ok {
		t.Fatal("expected key 'sha256:def456' to remain")
	}
}

func TestCheckVirusTotal(t *testing.T) {
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
			if tt.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			client := srv.Client()
			client.Timeout = 3 * time.Second

			result, err := checkVirusTotal(ctx, client, "test-api-key", testHash, srv.URL+"/")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Found != tt.wantFound || result.Malicious != tt.wantMal {
				t.Fatalf("got result %+v, want Found=%v Malicious=%d", result, tt.wantFound, tt.wantMal)
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
		cache        map[string]CacheEntry
		refresh      bool
		wantAPICalls int32
		wantFound    bool
	}{
		{name: "cache miss calls API", cache: make(map[string]CacheEntry), wantAPICalls: 1, wantFound: true},
		{
			name: "cache hit skips API",
			cache: map[string]CacheEntry{
				"sha256:" + testHash: {
					Result:    Result{Found: true, Name: "from-cache.exe", Malicious: 3},
					Timestamp: time.Now(),
				},
			},
			wantAPICalls: 0,
			wantFound:    true,
		},
		{
			name: "expired cache calls API",
			cache: map[string]CacheEntry{
				"sha256:" + testHash: {
					Result:    Result{Found: true, Name: "old-cache.exe"},
					Timestamp: time.Now().Add(-30 * 24 * time.Hour),
				},
			},
			wantAPICalls: 1,
			wantFound:    true,
		},
		{
			name: "refresh bypasses cache",
			cache: map[string]CacheEntry{
				"sha256:" + testHash: {
					Result:    Result{Found: true, Name: "cached.exe"},
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

			cfg := LookupConfig{
				VT: Client{
					Ctx:        context.Background(),
					HTTPClient: srv.Client(),
					APIKey:     "test-key",
					BaseURL:    srv.URL + "/",
					Limiter:    nil,
				},
				Cache: CacheConfig{
					Entries:    tt.cache,
					Mu:         &sync.Mutex{},
					Refresh:    tt.refresh,
					MaxAgeDays: 7,
				},
				Output: "text",
				Algo:   "sha256",
			}

			result, err := Lookup(testHash, cfg)
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
		if err := waitForRateLimit(context.Background(), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("fast limiter succeeds", func(t *testing.T) {
		limiter := rate.NewLimiter(rate.Every(time.Minute/1000), 1)
		if err := waitForRateLimit(context.Background(), limiter); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("cancelled context returns error", func(t *testing.T) {
		limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
		_ = limiter.Wait(context.Background())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := waitForRateLimit(ctx, limiter); err == nil {
			t.Fatal("expected error for cancelled context, got nil")
		}
	})
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestIsHexHash(t *testing.T) {
	const emptySHA256Lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	const emptySHA256Upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "valid lowercase sha256",
			in:   emptySHA256Lower,
			want: true,
		},
		{
			name: "valid uppercase sha256",
			in:   emptySHA256Upper,
			want: true,
		},
		{
			name: "too short",
			in:   "abc123",
			want: false,
		},
		{
			name: "too long",
			in:   emptySHA256Lower + "0",
			want: false,
		},
		{
			name: "non-hex characters",
			in:   "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			want: false,
		},
		{
			name: "empty string",
			in:   "",
			want: false,
		},
		{
			name: "md5 length hex string",
			in:   "d41d8cd98f00b204e9800998ecf8427e",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHexHash(tt.in); got != tt.want {
				t.Fatalf("isHexHash(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestHashFile(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{
			name:    "known content",
			content: []byte("hashchecker test content"),
		},
		{
			name:    "empty file",
			content: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "testfile")
			if err := os.WriteFile(path, tt.content, 0o644); err != nil {
				t.Fatalf("writing temp file: %v", err)
			}

			// Compute expected hash directly with crypto/sha256.
			sum := sha256.Sum256(tt.content)
			want := hex.EncodeToString(sum[:])

			got, err := hashFile(path)
			if err != nil {
				t.Fatalf("hashFile() error: %v", err)
			}
			if got != want {
				t.Fatalf("hashFile() = %q, want %q", got, want)
			}
		})
	}

	// Error case: nonexistent file should return an error.
	t.Run("nonexistent file", func(t *testing.T) {
		_, err := hashFile(filepath.Join(t.TempDir(), "does-not-exist"))
		if err == nil {
			t.Fatal("hashFile() should return error for nonexistent file")
		}
	})
}

func TestTruncateRunes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{
			name: "shorter than max",
			in:   "hello",
			max:  10,
			want: "hello",
		},
		{
			name: "exactly max",
			in:   "hello",
			max:  5,
			want: "hello",
		},
		{
			name: "longer than max",
			in:   "hello world",
			max:  5,
			want: "hello...",
		},
		{
			name: "empty string with positive max",
			in:   "",
			max:  5,
			want: "",
		},
		{
			name: "max zero",
			in:   "hello",
			max:  0,
			want: "",
		},
		{
			name: "max negative",
			in:   "hello",
			max:  -1,
			want: "",
		},
		{
			name: "multi-byte runes truncate cleanly",
			in:   "héllo",
			max:  3,
			want: "hél...",
		},
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
		{
			name: "empty string default",
			in:   "",
			want: 60 * time.Second,
		},
		{
			name: "integer thirty",
			in:   "30",
			want: 30 * time.Second,
		},
		{
			name: "integer one",
			in:   "1",
			want: 1 * time.Second,
		},
		{
			name: "zero falls back to default",
			in:   "0",
			want: 60 * time.Second,
		},
		{
			name: "negative falls back to default",
			in:   "-5",
			want: 60 * time.Second,
		},
		{
			name: "non-numeric garbage",
			in:   "not-a-number",
			want: 60 * time.Second,
		},
		{
			name: "RFC1123 date in the future",
			in:   time.Now().Add(30 * time.Second).UTC().Format(time.RFC1123),
			want: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRetryAfter(tt.in)
			// RFC1123 dates produce an approximate duration (time.Until is
			// evaluated at call time), so we allow ±2s tolerance for that case.
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

func TestShouldProcess(t *testing.T) {
	type args struct {
		name     string
		size     int
		includes []string
		excludes []string
		minSize  int64
		maxSize  int64
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "no filters",
			args: args{
				name: "test.exe",
				size: 1024,
			},
			want: true,
		},
		{
			name: "include exe matches",
			args: args{
				name:     "test.exe",
				size:     1024,
				includes: []string{"*.exe"},
			},
			want: true,
		},
		{
			name: "include exe does not match txt",
			args: args{
				name:     "test.txt",
				size:     1024,
				includes: []string{"*.exe"},
			},
			want: false,
		},
		{
			name: "exclude log matches",
			args: args{
				name:     "test.log",
				size:     1024,
				excludes: []string{"*.log"},
			},
			want: false,
		},
		{
			name: "exclude log does not match exe",
			args: args{
				name:     "test.exe",
				size:     1024,
				excludes: []string{"*.log"},
			},
			want: true,
		},
		{
			name: "include and exclude same pattern",
			args: args{
				name:     "test.exe",
				size:     1024,
				includes: []string{"*.exe"},
				excludes: []string{"*.exe"},
			},
			want: false,
		},
		{
			name: "minSize larger than file",
			args: args{
				name:    "test.exe",
				size:    1024,
				minSize: 2048,
			},
			want: false,
		},
		{
			name: "maxSize smaller than file",
			args: args{
				name:    "test.exe",
				size:    1024,
				maxSize: 512,
			},
			want: false,
		},
		{
			name: "size within min and max",
			args: args{
				name:    "test.exe",
				size:    1024,
				minSize: 512,
				maxSize: 2048,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a MapFS with a single file of the requested size.
			fsys := fstest.MapFS{
				tt.args.name: &fstest.MapFile{Data: make([]byte, tt.args.size)},
			}
			entries, err := fs.ReadDir(fsys, ".")
			if err != nil {
				t.Fatalf("ReadDir error: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("expected 1 entry, got %d", len(entries))
			}
			d := entries[0]

			got, err := shouldProcess(d, tt.args.includes, tt.args.excludes, tt.args.minSize, tt.args.maxSize)
			if err != nil {
				t.Fatalf("shouldProcess returned unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("shouldProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

// callRun resets the global flag state, sets os.Args, and calls run().
// This lets us test run()'s early validation paths without making real
// API calls. The flag.CommandLine reset is necessary because Go's flag
// package uses global state — without it, flags from previous test
// cases would conflict.
//
// IMPORTANT: These tests cannot run in parallel because they modify
// os.Args and flag.CommandLine (global state).
func callRun(t *testing.T, args ...string) (exitCode int, stdout string) {
	t.Helper()
	os.Args = append([]string{"hashchecker"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	var code int
	out := captureStdout(t, func() {
		code = run()
	})
	return code, out
}

func TestRunVersion(t *testing.T) {
	code, stdout := callRun(t, "-version")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "hashchecker") {
		t.Fatalf("expected version output, got %q", stdout)
	}
}

func TestRunNoArgs(t *testing.T) {
	// With no positional args, run() should print usage and return 1.
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunMissingAPIKey(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "")
	code, _ := callRun(t, "somefile.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunInvalidOutputFormat(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-o", "xml", "somefile.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunInvalidIncludePattern(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-include", "[bad", "somefile.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunInvalidExcludePattern(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-exclude", "[bad", "somefile.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunInvalidMinSize(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-min-size", "not-a-size", "somefile.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunInvalidMaxSize(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-max-size", "not-a-size", "somefile.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunMinSizeGreaterThanMaxSize(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-min-size", "100MB", "-max-size", "1MB", "somefile.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunNonexistentFile(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "/nonexistent/path/file.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunFreeModeFlag(t *testing.T) {
	// Exercises the rate limiter setup path (effectiveRate > 0)
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-free", "/nonexistent/path/file.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunCustomRateFlag(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-rate", "10", "/nonexistent/path/file.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunNoCacheFlag(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-no-cache", "/nonexistent/path/file.txt")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

// startMockVT creates a mock VirusTotal server and sets up the env vars
// for run() to use it. Returns the server (caller must defer srv.Close()).
func startMockVT(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"data": {
				"attributes": {
					"meaningful_name": "test.exe",
					"reputation": 0,
					"last_analysis_stats": {
						"malicious": 0,
						"suspicious": 0,
						"undetected": 5,
						"harmless": 60
					},
					"popular_threat_classification": {
						"suggested_threat_label": ""
					}
				}
			}
		}`)
	}))
	t.Setenv("VIRUSTOTAL_API_KEY", "test-key")
	t.Setenv("VIRUSTOTAL_BASE_URL", srv.URL+"/")
	return srv
}

func TestRunHashLookup(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	// Valid SHA-256 hash (of empty file)
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	code, stdout := callRun(t, "-no-cache", hash)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, hash) {
		t.Fatalf("output should contain hash, got %q", stdout)
	}
}

func TestRunHashLookupMalicious(t *testing.T) {
	// Mock server returns malicious > 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"data": {
				"attributes": {
					"meaningful_name": "evil.exe",
					"reputation": -10,
					"last_analysis_stats": {
						"malicious": 42,
						"suspicious": 3,
						"undetected": 5,
						"harmless": 10
					},
					"popular_threat_classification": {
						"suggested_threat_label": "trojan.generic"
					}
				}
			}
		}`)
	}))
	defer srv.Close()

	t.Setenv("VIRUSTOTAL_API_KEY", "test-key")
	t.Setenv("VIRUSTOTAL_BASE_URL", srv.URL+"/")

	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	code, _ := callRun(t, "-no-cache", hash)
	// Exit code 2 = malicious file found
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRunSingleFile(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	// Create a temp file to hash
	tmpFile := filepath.Join(t.TempDir(), "testfile.txt")
	if err := os.WriteFile(tmpFile, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout := callRun(t, "-no-cache", tmpFile)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "test.exe") {
		t.Fatalf("output should contain VT result name, got %q", stdout)
	}
}

func TestRunSingleFileMinSizeFilter(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	tmpFile := filepath.Join(t.TempDir(), "tiny.txt")
	if err := os.WriteFile(tmpFile, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	// File is 2 bytes, min-size is 1MB → should be skipped (exit 0, not error)
	code, _ := callRun(t, "-no-cache", "-min-size", "1MB", tmpFile)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (filtered out)", code)
	}
}

func TestRunSingleFileMaxSizeFilter(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	tmpFile := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(tmpFile, make([]byte, 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	// File is 2048 bytes, max-size is 1KB (1024) → should be skipped
	code, _ := callRun(t, "-no-cache", "-max-size", "1KB", tmpFile)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (filtered out)", code)
	}
}

func TestRunDirectoryScan(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout := callRun(t, "-no-cache", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	// Should see summary line
	if !strings.Contains(stdout, "Checked") || !strings.Contains(stdout, "files") {
		t.Fatalf("expected summary line, got %q", stdout)
	}
}

func TestRunDirectoryJSON(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout := callRun(t, "-no-cache", "-o", "json", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	// Should contain JSON summary with "summary" key
	if !strings.Contains(stdout, `"summary"`) {
		t.Fatalf("expected JSON summary, got %q", stdout)
	}
}

func TestRunDirectoryRecursive(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "nested.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout := callRun(t, "-no-cache", "-r", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	// With -r, both files should be scanned. Summary should say "2 files"
	if !strings.Contains(stdout, "2 files") {
		t.Fatalf("expected 2 files in summary, got %q", stdout)
	}
}

func TestRunDirectoryWithIncludeExclude(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.exe"), []byte("exe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skip.log"), []byte("log"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Include only .exe, exclude .log
	code, stdout := callRun(t, "-no-cache", "-include", "*.exe", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "1 files") {
		t.Fatalf("expected 1 file scanned, got %q", stdout)
	}
}


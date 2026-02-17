package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
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
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func TestIsHexHash(t *testing.T) {
	const emptySHA256Lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	const emptySHA256Upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	const emptySHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	const emptyMD5 = "d41d8cd98f00b204e9800998ecf8427e"

	tests := []struct {
		name     string
		in       string
		wantOK   bool
		wantAlgo string
	}{
		{
			name:     "valid lowercase sha256",
			in:       emptySHA256Lower,
			wantOK:   true,
			wantAlgo: "sha256",
		},
		{
			name:     "valid uppercase sha256",
			in:       emptySHA256Upper,
			wantOK:   true,
			wantAlgo: "sha256",
		},
		{
			name:   "too short",
			in:     "abc123",
			wantOK: false,
		},
		{
			name:   "sha256 too long",
			in:     emptySHA256Lower + "0",
			wantOK: false,
		},
		{
			name:   "non-hex characters",
			in:     "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantOK: false,
		},
		{
			name:   "empty string",
			in:     "",
			wantOK: false,
		},
		{
			name:     "valid sha1",
			in:       emptySHA1,
			wantOK:   true,
			wantAlgo: "sha1",
		},
		{
			name:     "valid md5",
			in:       emptyMD5,
			wantOK:   true,
			wantAlgo: "md5",
		},
		{
			name:   "unknown length",
			in:     "aabbccdd",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, gotAlgo := isHexHash(tt.in)
			if gotOK != tt.wantOK || gotAlgo != tt.wantAlgo {
				t.Fatalf("isHexHash(%q) = (%v, %q), want (%v, %q)",
					tt.in, gotOK, gotAlgo, tt.wantOK, tt.wantAlgo)
			}
		})
	}
}

func TestHashFile(t *testing.T) {
	content := []byte("hashchecker test content")

	t.Run("all three hashes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "testfile")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatalf("writing temp file: %v", err)
		}
		sum256 := sha256.Sum256(content)
		sum1 := sha1.Sum(content)
		sumMD5 := md5.Sum(content)

		got, err := hashFile(path)
		if err != nil {
			t.Fatalf("hashFile() error: %v", err)
		}
		if want := hex.EncodeToString(sum256[:]); got.SHA256 != want {
			t.Fatalf("SHA256 = %q, want %q", got.SHA256, want)
		}
		if want := hex.EncodeToString(sum1[:]); got.SHA1 != want {
			t.Fatalf("SHA1 = %q, want %q", got.SHA1, want)
		}
		if want := hex.EncodeToString(sumMD5[:]); got.MD5 != want {
			t.Fatalf("MD5 = %q, want %q", got.MD5, want)
		}
		if got.TLSH != "" {
			t.Fatalf("TLSH = %q, want empty for small file", got.TLSH)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty")
		if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
			t.Fatalf("writing temp file: %v", err)
		}
		sum256 := sha256.Sum256([]byte{})
		got, err := hashFile(path)
		if err != nil {
			t.Fatalf("hashFile() error: %v", err)
		}
		if want := hex.EncodeToString(sum256[:]); got.SHA256 != want {
			t.Fatalf("SHA256 = %q, want %q", got.SHA256, want)
		}
		if got.TLSH != "" {
			t.Fatalf("TLSH = %q, want empty for empty file", got.TLSH)
		}
	})

	t.Run("large file includes tlsh", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "large")
		data := make([]byte, 1024)
		for i := range data {
			data[i] = byte(i % 251)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("writing temp file: %v", err)
		}
		got, err := hashFile(path)
		if err != nil {
			t.Fatalf("hashFile() error: %v", err)
		}
		if got.TLSH == "" {
			t.Fatal("TLSH should be non-empty for large varied file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := hashFile(filepath.Join(t.TempDir(), "does-not-exist"))
		if err == nil {
			t.Fatal("hashFile() should return error for nonexistent file")
		}
	})
}

func TestNewFileMeta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.txt")
	if err := os.WriteFile(path, []byte("metadata test content"), 0o640); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}

	meta := newFileMeta(path, fi)
	if meta == nil {
		t.Fatal("newFileMeta returned nil")
	}
	if meta.Name != fi.Name() {
		t.Fatalf("Name = %q, want %q", meta.Name, fi.Name())
	}
	if meta.Size != fi.Size() {
		t.Fatalf("Size = %d, want %d", meta.Size, fi.Size())
	}
	if meta.SizeHuman == "" {
		t.Fatal("SizeHuman should not be empty")
	}
	if meta.Modified.IsZero() {
		t.Fatal("Modified should not be zero")
	}
	if meta.Permissions != fi.Mode().String() {
		t.Fatalf("Permissions = %q, want %q", meta.Permissions, fi.Mode().String())
	}
	if !meta.Created.IsZero() && meta.Created.Location() != time.UTC {
		t.Fatalf("Created should be UTC when present, got %v", meta.Created.Location())
	}
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

func callRunWithStderr(t *testing.T, args ...string) (exitCode int, stdout, stderr string) {
	t.Helper()
	var code int
	var out string
	errOut := captureStderr(t, func() {
		code, out = callRun(t, args...)
	})
	return code, out, errOut
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

func TestRunInvalidAlgo(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-algo", "sha512", "somefile.txt")
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

func TestRunInvalidWorkers(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "fake-key")
	code, _ := callRun(t, "-workers", "-1", "somefile.txt")
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
		_, _ = fmt.Fprint(w, vtJSON("test.exe", 0, 0, 0, 5, 60, ""))
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
		_, _ = fmt.Fprint(w, vtJSON("evil.exe", -10, 42, 3, 5, 10, "trojan.generic"))
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

func TestRunHashLookupMD5(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	// Valid MD5 hash (of empty file) — algo is auto-detected from length
	hash := "d41d8cd98f00b204e9800998ecf8427e"
	code, stdout := callRun(t, "-no-cache", hash)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, hash) {
		t.Fatalf("output should contain hash, got %q", stdout)
	}
}

func TestRunSingleFileSHA1(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	tmpFile := filepath.Join(t.TempDir(), "testfile.txt")
	if err := os.WriteFile(tmpFile, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout := callRun(t, "-no-cache", "-algo", "sha1", tmpFile)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "test.exe") {
		t.Fatalf("output should contain VT result name, got %q", stdout)
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
	if !strings.Contains(stdout, "1 file") {
		t.Fatalf("expected 1 file scanned, got %q", stdout)
	}
}

func TestRunHashListMode(t *testing.T) {
	writeHashList := func(t *testing.T, lines ...string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "hashes.txt")
		content := strings.Join(lines, "\n")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("writing hash list file: %v", err)
		}
		return p
	}

	t.Run("happy path with three hashes", func(t *testing.T) {
		srv := startMockVT(t)
		defer srv.Close()

		hashList := writeHashList(t,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		)

		code, stdout := callRun(t, "-no-cache", "-f", hashList)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if !strings.Contains(stdout, "Checked 3 hashes") {
			t.Fatalf("expected summary for 3 hashes, got %q", stdout)
		}
	})

	t.Run("malicious hash returns exit code 2", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, vtJSON("evil.exe", -10, 42, 3, 5, 10, "trojan.generic"))
		}))
		defer srv.Close()
		t.Setenv("VIRUSTOTAL_API_KEY", "test-key")
		t.Setenv("VIRUSTOTAL_BASE_URL", srv.URL+"/")

		hashList := writeHashList(t,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		)

		code, _ := callRun(t, "-no-cache", "-f", hashList)
		if code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
	})

	t.Run("mixed algorithms are detected", func(t *testing.T) {
		srv := startMockVT(t)
		defer srv.Close()

		hashList := writeHashList(t,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // sha256
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",                         // sha1
			"d41d8cd98f00b204e9800998ecf8427e",                                 // md5
		)

		code, stdout := callRun(t, "-no-cache", "-o", "json", "-f", hashList)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if !strings.Contains(stdout, `"lookup_algorithm":"sha256"`) {
			t.Fatalf("expected sha256 lookup in output, got %q", stdout)
		}
		if !strings.Contains(stdout, `"lookup_algorithm":"sha1"`) {
			t.Fatalf("expected sha1 lookup in output, got %q", stdout)
		}
		if !strings.Contains(stdout, `"lookup_algorithm":"md5"`) {
			t.Fatalf("expected md5 lookup in output, got %q", stdout)
		}
		if !strings.Contains(stdout, `"summary":{"path":"`) || !strings.Contains(stdout, `"scanned":3`) {
			t.Fatalf("expected JSON summary for 3 hashes, got %q", stdout)
		}
	})

	t.Run("comments and blank lines are skipped", func(t *testing.T) {
		srv := startMockVT(t)
		defer srv.Close()

		hashList := writeHashList(t,
			"# comment line",
			"",
			"   ",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		)

		code, stdout := callRun(t, "-no-cache", "-f", hashList)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if !strings.Contains(stdout, "Checked 1 hash") {
			t.Fatalf("expected summary for 1 hash, got %q", stdout)
		}
	})

	t.Run("invalid hashes are warned and skipped", func(t *testing.T) {
		srv := startMockVT(t)
		defer srv.Close()

		hashList := writeHashList(t,
			"not-a-hash",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		)

		code, stdout, stderr := callRunWithStderr(t, "-no-cache", "-f", hashList)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if !strings.Contains(stderr, "Warning: skipping invalid hash: not-a-hash") {
			t.Fatalf("expected warning for invalid hash, got %q", stderr)
		}
		if !strings.Contains(stdout, "Checked 1 hash") {
			t.Fatalf("expected summary for 1 looked-up hash, got %q", stdout)
		}
	})

	t.Run("empty file exits cleanly", func(t *testing.T) {
		srv := startMockVT(t)
		defer srv.Close()

		hashList := writeHashList(t)
		code, stdout := callRun(t, "-no-cache", "-f", hashList)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if !strings.Contains(stdout, "Checked 0 hashes") {
			t.Fatalf("expected summary for 0 hashes, got %q", stdout)
		}
	})

	t.Run("-f with positional arg returns error", func(t *testing.T) {
		t.Setenv("VIRUSTOTAL_API_KEY", "test-key")
		hashList := writeHashList(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

		code, _, stderr := callRunWithStderr(t, "-f", hashList, "extra-arg")
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr, "-f cannot be combined with a positional argument") {
			t.Fatalf("expected mutually-exclusive args error, got %q", stderr)
		}
	})

	t.Run("missing hash list file returns error", func(t *testing.T) {
		t.Setenv("VIRUSTOTAL_API_KEY", "test-key")
		missing := filepath.Join(t.TempDir(), "does-not-exist.txt")

		code, _, stderr := callRunWithStderr(t, "-no-cache", "-f", missing)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr, "Error:") {
			t.Fatalf("expected missing-file error output, got %q", stderr)
		}
	})
}

func TestRunDirectoryConcurrent(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout := callRun(t, "-no-cache", "-workers", "4", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Checked 2 files") {
		t.Fatalf("expected summary line for 2 files, got %q", stdout)
	}
}

func TestRunDirectoryConcurrentOutputOrder(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	dir := t.TempDir()
	fileNames := []string{
		"a.txt", "b.txt", "c.txt", "d.txt", "e.txt",
		"f.txt", "g.txt", "h.txt", "i.txt", "j.txt",
	}
	for i, name := range fileNames {
		if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{byte('a' + i)}, 1024*(i+1)), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, stdout := callRun(t, "-no-cache", "-workers", "4", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	lastPos := -1
	for _, name := range fileNames {
		header := fmt.Sprintf("--- %s ---", filepath.Join(dir, name))
		pos := strings.Index(stdout, header)
		if pos == -1 {
			t.Fatalf("expected header %q in output, got %q", header, stdout)
		}
		if pos < lastPos {
			t.Fatalf("output order is not deterministic; %q appeared before previous file", name)
		}
		lastPos = pos
	}
}

func TestRunDirectoryConcurrentMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, vtJSON("evil.exe", -10, 42, 3, 5, 10, "trojan.generic"))
	}))
	defer srv.Close()

	t.Setenv("VIRUSTOTAL_API_KEY", "test-key")
	t.Setenv("VIRUSTOTAL_BASE_URL", srv.URL+"/")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _ := callRun(t, "-no-cache", "-workers", "2", dir)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRunDirectoryWorkers1(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0o644); err != nil {
		t.Fatal(err)
	}

	codeWorkers4, stdoutWorkers4 := callRun(t, "-no-cache", "-workers", "4", dir)
	if codeWorkers4 != 0 {
		t.Fatalf("workers=4 exit code = %d, want 0", codeWorkers4)
	}
	codeWorkers1, stdoutWorkers1 := callRun(t, "-no-cache", "-workers", "1", dir)
	if codeWorkers1 != 0 {
		t.Fatalf("workers=1 exit code = %d, want 0", codeWorkers1)
	}
	if stdoutWorkers4 != stdoutWorkers1 {
		t.Fatalf("workers=1 output differs from workers=4\nwant:\n%s\ngot:\n%s", stdoutWorkers4, stdoutWorkers1)
	}
}

func TestRunHashListConcurrent(t *testing.T) {
	srv := startMockVT(t)
	defer srv.Close()

	hashListPath := filepath.Join(t.TempDir(), "hashes.txt")
	content := strings.Join([]string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"d41d8cd98f00b204e9800998ecf8427e",
	}, "\n")
	if err := os.WriteFile(hashListPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing hash list file: %v", err)
	}

	code, stdout := callRun(t, "-no-cache", "-workers", "3", "-f", hashListPath)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Checked 3 hashes") {
		t.Fatalf("expected summary for 3 hashes, got %q", stdout)
	}
}

func TestRunConcurrentInterrupt(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.txt", i)), []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := lookupConfig{
		vt: vtClient{
			ctx:    ctx,
			client: &http.Client{Timeout: 1 * time.Second},
		},
		cache: cacheConfig{
			entries:    make(map[string]cacheEntry),
			mu:         &sync.Mutex{},
			maxAgeDays: 7,
		},
		output: "text",
		algo:   "sha256",
	}

	code := runDir(dir, cfg, scanConfig{}, false, 4)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 for interrupted run", code)
	}
}

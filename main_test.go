package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseRetryAfter(tt.in); got != tt.want {
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


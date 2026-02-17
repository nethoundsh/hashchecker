package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
		{name: "valid lowercase sha256", in: emptySHA256Lower, wantOK: true, wantAlgo: "sha256"},
		{name: "valid uppercase sha256", in: emptySHA256Upper, wantOK: true, wantAlgo: "sha256"},
		{name: "too short", in: "abc123", wantOK: false},
		{name: "sha256 too long", in: emptySHA256Lower + "0", wantOK: false},
		{name: "non-hex characters", in: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", wantOK: false},
		{name: "empty string", in: "", wantOK: false},
		{name: "valid sha1", in: emptySHA1, wantOK: true, wantAlgo: "sha1"},
		{name: "valid md5", in: emptyMD5, wantOK: true, wantAlgo: "md5"},
		{name: "unknown length", in: "aabbccdd", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, gotAlgo := IsHexHash(tt.in)
			if gotOK != tt.wantOK || gotAlgo != tt.wantAlgo {
				t.Fatalf("IsHexHash(%q) = (%v, %q), want (%v, %q)", tt.in, gotOK, gotAlgo, tt.wantOK, tt.wantAlgo)
			}
		})
	}
}

func TestFile(t *testing.T) {
	content := []byte("hashchecker test content")

	t.Run("all hashes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "testfile")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatalf("writing temp file: %v", err)
		}
		sum256 := sha256.Sum256(content)
		sum1 := sha1.Sum(content)
		sumMD5 := md5.Sum(content)

		got, err := File(path)
		if err != nil {
			t.Fatalf("File() error: %v", err)
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
		got, err := File(path)
		if err != nil {
			t.Fatalf("File() error: %v", err)
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
		got, err := File(path)
		if err != nil {
			t.Fatalf("File() error: %v", err)
		}
		if got.TLSH == "" {
			t.Fatal("TLSH should be non-empty for large varied file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := File(filepath.Join(t.TempDir(), "does-not-exist"))
		if err == nil {
			t.Fatal("File() should return error for nonexistent file")
		}
	})
}

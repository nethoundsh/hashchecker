package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCache(t *testing.T) {
	t.Run("file does not exist returns empty map", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nonexistent.json")
		cache, err := loadCache(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cache) != 0 {
			t.Fatalf("expected empty map, got %d entries", len(cache))
		}
	})

	t.Run("valid cache file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "results.json")

		// Write a valid cache file with the new "algo:hash" key format.
		now := time.Now().Truncate(time.Second) // truncate for JSON round-trip
		data := map[string]cacheEntry{
			"sha256:abc123": {
				Result:    VirusTotalResult{Found: true, Name: "test.exe", Malicious: 5},
				Timestamp: now,
			},
		}
		b, err := json.Marshal(data)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		cache, err := loadCache(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cache) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(cache))
		}
		entry, ok := cache["sha256:abc123"]
		if !ok {
			t.Fatal("expected key 'sha256:abc123' in cache")
		}
		if entry.Result.Name != "test.exe" {
			t.Fatalf("Name = %q, want %q", entry.Result.Name, "test.exe")
		}
		if entry.Result.Malicious != 5 {
			t.Fatalf("Malicious = %d, want 5", entry.Result.Malicious)
		}
	})

	t.Run("corrupt JSON returns empty map", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "results.json")
		if err := os.WriteFile(path, []byte(`{garbage`), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		cache, err := loadCache(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cache) != 0 {
			t.Fatalf("expected empty map for corrupt JSON, got %d entries", len(cache))
		}
	})
}

func TestLoadCacheMigratesLegacyKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")

	// Write a cache file with legacy bare-hash keys (no "algo:" prefix).
	now := time.Now().Truncate(time.Second)
	data := map[string]cacheEntry{
		"abc123": {
			Result:    VirusTotalResult{Found: true, Name: "legacy.exe", Malicious: 1},
			Timestamp: now,
		},
		"sha256:def456": {
			Result:    VirusTotalResult{Found: true, Name: "already-migrated.exe"},
			Timestamp: now,
		},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cache, err := loadCache(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Legacy key should have been migrated to "sha256:abc123".
	if _, ok := cache["abc123"]; ok {
		t.Fatal("bare key 'abc123' should have been migrated")
	}
	if _, ok := cache["sha256:abc123"]; !ok {
		t.Fatal("expected migrated key 'sha256:abc123'")
	}
	if cache["sha256:abc123"].Result.Name != "legacy.exe" {
		t.Fatalf("migrated entry Name = %q, want %q", cache["sha256:abc123"].Result.Name, "legacy.exe")
	}

	// Already-prefixed key should be unchanged.
	if _, ok := cache["sha256:def456"]; !ok {
		t.Fatal("expected key 'sha256:def456' to remain")
	}
}

func TestSaveCache(t *testing.T) {
	t.Run("normal save", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sub", "results.json")

		data := map[string]cacheEntry{
			"sha256:hash1": {
				Result:    VirusTotalResult{Found: true, Name: "file.exe"},
				Timestamp: time.Now(),
			},
		}
		if err := saveCache(path, data); err != nil {
			t.Fatalf("saveCache: %v", err)
		}

		// Verify file exists with correct permissions
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("permissions = %o, want 600", perm)
		}

		// Verify valid JSON
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var parsed map[string]cacheEntry
		if err := json.Unmarshal(b, &parsed); err != nil {
			t.Fatalf("saved file is not valid JSON: %v", err)
		}
		if _, ok := parsed["sha256:hash1"]; !ok {
			t.Fatal("saved file missing key 'sha256:hash1'")
		}
	})

	t.Run("round trip", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "results.json")

		now := time.Now().Truncate(time.Second)
		original := map[string]cacheEntry{
			"sha256:aaa": {
				Result:    VirusTotalResult{Found: true, Name: "a.exe", Malicious: 1},
				Timestamp: now,
			},
			"md5:bbb": {
				Result:    VirusTotalResult{Found: false},
				Timestamp: now,
			},
		}

		if err := saveCache(path, original); err != nil {
			t.Fatalf("save: %v", err)
		}
		loaded, err := loadCache(path)
		if err != nil {
			t.Fatalf("load: %v", err)
		}

		if len(loaded) != len(original) {
			t.Fatalf("loaded %d entries, want %d", len(loaded), len(original))
		}
		for k, orig := range original {
			got, ok := loaded[k]
			if !ok {
				t.Fatalf("missing key %q after round trip", k)
			}
			if got.Result.Name != orig.Result.Name {
				t.Fatalf("key %q: Name = %q, want %q", k, got.Result.Name, orig.Result.Name)
			}
			if got.Result.Found != orig.Result.Found {
				t.Fatalf("key %q: Found = %v, want %v", k, got.Result.Found, orig.Result.Found)
			}
		}
	})
}

func TestGetCacheFilePath(t *testing.T) {
	path, err := getCacheFilePath()
	if err != nil {
		t.Fatalf("getCacheFilePath: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("hashchecker", "results.json")) {
		t.Fatalf("path %q does not end with hashchecker/results.json", path)
	}
}

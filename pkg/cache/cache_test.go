package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testEntry struct {
	Name      string    `json:"name"`
	Malicious int       `json:"malicious"`
	Timestamp time.Time `json:"timestamp"`
}

func TestLoad(t *testing.T) {
	t.Run("file does not exist returns empty map", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nonexistent.json")
		data, err := Load[testEntry](path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 0 {
			t.Fatalf("expected empty map, got %d entries", len(data))
		}
	})

	t.Run("valid cache file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "results.json")
		now := time.Now().Truncate(time.Second)
		original := map[string]testEntry{
			"sha256:abc123": {Name: "test.exe", Malicious: 5, Timestamp: now},
		}
		b, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		data, err := Load[testEntry](path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(data))
		}
		entry, ok := data["sha256:abc123"]
		if !ok {
			t.Fatal("expected key 'sha256:abc123' in cache")
		}
		if entry.Name != "test.exe" || entry.Malicious != 5 {
			t.Fatalf("unexpected entry: %+v", entry)
		}
	})

	t.Run("corrupt JSON returns error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "results.json")
		if err := os.WriteFile(path, []byte(`{garbage`), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := Load[testEntry](path); err == nil {
			t.Fatal("expected decode error for corrupt JSON")
		}
	})
}

func TestSave(t *testing.T) {
	t.Run("normal save", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sub", "results.json")
		data := map[string]testEntry{
			"sha256:hash1": {Name: "file.exe", Timestamp: time.Now()},
		}
		if err := Save(path, data); err != nil {
			t.Fatalf("Save: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("permissions = %o, want 600", perm)
		}

		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var parsed map[string]testEntry
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
		original := map[string]testEntry{
			"sha256:aaa": {Name: "a.exe", Malicious: 1, Timestamp: now},
			"md5:bbb":    {Name: "", Malicious: 0, Timestamp: now},
		}
		if err := Save(path, original); err != nil {
			t.Fatalf("save: %v", err)
		}
		loaded, err := Load[testEntry](path)
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
			if got.Name != orig.Name || got.Malicious != orig.Malicious {
				t.Fatalf("key %q mismatch: got %+v want %+v", k, got, orig)
			}
		}
	})
}

func TestFilePath(t *testing.T) {
	path, err := FilePath()
	if err != nil {
		t.Fatalf("FilePath: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("hashchecker", "results.json")) {
		t.Fatalf("path %q does not end with hashchecker/results.json", path)
	}
}

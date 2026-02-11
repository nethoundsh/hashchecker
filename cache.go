package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── Cache Persistence ───────────────────────────────────────────────
//
// The cache is stored as a JSON file on disk at a platform-appropriate
// location (e.g. ~/.cache/hashchecker/results.json on Linux). This
// avoids wasting API calls on files that have already been checked.

// cacheEntry pairs a VirusTotal result with the time it was fetched.
// The timestamp lets us expire stale entries (controlled by -cache-age).
type cacheEntry struct {
	Result    VirusTotalResult `json:"result"`    // the cached API result
	Timestamp time.Time        `json:"timestamp"` // when this result was fetched
}

// getCacheFilePath returns the path to the cache file, using the
// OS-standard user cache directory.
//
// os.UserCacheDir() returns:
//   - Linux:   $XDG_CACHE_HOME or ~/.cache
//   - macOS:   ~/Library/Caches
//   - Windows: %LocalAppData%
func getCacheFilePath() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating cache directory: %w", err)
	}
	return filepath.Join(cacheDir, "hashchecker", "results.json"), nil
}

// loadCache reads the cache file from disk and returns the parsed map.
//
// Resilience strategy:
//   - File doesn't exist → return empty map (first run, not an error)
//   - File exists but is corrupt JSON → warn and return empty map
//   - Other read errors → return error (caller decides how to handle)
//
// Go idiom: errors.Is(err, os.ErrNotExist) checks for the specific
// "file not found" sentinel, regardless of how it's wrapped. This is
// preferred over os.IsNotExist(err) in modern Go.
func loadCache(path string) (_ map[string]cacheEntry, err error) {
	cache := make(map[string]cacheEntry)
	cacheFile, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return cache, nil // first run — no cache file yet, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("opening cache %s: %w", path, err)
	}
	defer func() {
		if closeErr := cacheFile.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing cache %s: %w", path, closeErr)
		}
	}()

	// json.NewDecoder streams from the file reader instead of reading
	// the whole file into memory first. For a cache file this is
	// negligible, but it's a good habit for JSON file parsing.
	if err := json.NewDecoder(cacheFile).Decode(&cache); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: corrupt cache file, starting fresh")
		return make(map[string]cacheEntry), nil
	}

	// Migrate legacy cache keys: older versions stored bare hashes as
	// keys (e.g. "abc123"). The new format is "algo:hash" (e.g.
	// "sha256:abc123"). All pre-existing entries are SHA-256, so we
	// prepend "sha256:" to any key that doesn't already contain ":".
	// This is a one-time, lossless migration.
	for key, entry := range cache {
		if !strings.Contains(key, ":") {
			cache["sha256:"+key] = entry
			delete(cache, key)
		}
	}

	return cache, nil
}

// saveCache writes the in-memory cache map to disk as pretty-printed JSON.
//
// Steps:
//  1. Create the parent directory (e.g. ~/.cache/hashchecker/) if it
//     doesn't exist. os.MkdirAll is like `mkdir -p` — it creates all
//     missing parents and is a no-op if the directory already exists.
//  2. Serialize the map to indented JSON for human readability.
//  3. Write to a .tmp file, then atomically rename it into place.
//     This prevents a crash mid-write from corrupting the cache.
//     The 0o600 permission (owner read/write only) protects the
//     cached data from other users.
//
// Note on the 0o prefix: Go uses 0o for octal literals (like 0o700).
// This is clearer than the older 0700 syntax since it's explicit about
// the base.
func saveCache(path string, cache map[string]cacheEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	jsonBytes, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, jsonBytes, 0o600); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("committing cache file: %w", err)
	}
	return nil
}


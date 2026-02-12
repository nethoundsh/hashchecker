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

type cacheEntry struct {
	Result    VirusTotalResult `json:"result"`    // the cached API result
	Timestamp time.Time        `json:"timestamp"` // when this result was fetched
}

// getCacheFilePath returns the OS-standard cache file path
// (e.g. ~/.cache/hashchecker/results.json on Linux).
func getCacheFilePath() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating cache directory: %w", err)
	}
	return filepath.Join(cacheDir, "hashchecker", "results.json"), nil
}

// loadCache reads the cache file. Missing file returns an empty map
// (first run). Corrupt JSON is warned about and treated as empty.
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

	if err := json.NewDecoder(cacheFile).Decode(&cache); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: corrupt cache file, starting fresh")
		return make(map[string]cacheEntry), nil
	}

	// Migrate legacy bare-hash keys to "algo:hash" format.
	// Pre-existing entries are all SHA-256.
	for key, entry := range cache {
		if !strings.Contains(key, ":") {
			cache["sha256:"+key] = entry
			delete(cache, key)
		}
	}

	return cache, nil
}

// saveCache writes the cache to disk. It writes to a .tmp file first,
// then atomically renames it to prevent corruption from mid-write crashes.
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


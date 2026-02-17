package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FilePath returns the OS-standard cache file path
// (e.g. ~/.cache/hashchecker/results.json on Linux).
func FilePath() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating cache directory: %w", err)
	}
	return filepath.Join(cacheDir, "hashchecker", "results.json"), nil
}

// Load reads the cache file into a map.
// Missing file returns an empty map (first run).
func Load[V any](path string) (_ map[string]V, err error) {
	data := make(map[string]V)
	cacheFile, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening cache %s: %w", path, err)
	}
	defer func() {
		if closeErr := cacheFile.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing cache %s: %w", path, closeErr)
		}
	}()

	if err := json.NewDecoder(cacheFile).Decode(&data); err != nil {
		return nil, fmt.Errorf("decoding cache %s: %w", path, err)
	}
	return data, nil
}

// Save writes the cache to disk. It writes to a .tmp file first,
// then atomically renames it to prevent corruption from mid-write crashes.
func Save[V any](path string, data map[string]V) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, jsonBytes, 0o600); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("committing cache file: %w", err)
	}
	return nil
}

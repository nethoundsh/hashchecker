package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

// shouldProcess decides whether a file should be hashed and looked up.
// Filtering order: include → exclude → min-size → max-size.
// Glob patterns match the base name only (e.g. "report.pdf").
func shouldProcess(d fs.DirEntry, includes, excludes []string, minSize, maxSize int64) (bool, error) {
	name := d.Name()

	if len(includes) > 0 {
		matched := false
		for _, pattern := range includes {
			if ok, _ := filepath.Match(pattern, name); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}

	// Exclude runs after include, further narrowing the set.
	for _, pattern := range excludes {
		if ok, _ := filepath.Match(pattern, name); ok {
			return false, nil
		}
	}

	// Only call d.Info() (a syscall) when size filters are active.
	if minSize > 0 || maxSize > 0 {
		info, err := d.Info()
		if err != nil {
			return false, fmt.Errorf("reading file info: %w", err)
		}
		fileSize := info.Size()

		if minSize > 0 && fileSize < minSize {
			return false, nil
		}
		if maxSize > 0 && fileSize > maxSize {
			return false, nil
		}
	}

	return true, nil
}


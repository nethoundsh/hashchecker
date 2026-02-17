package filter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// SkipDirs lists directory names that are irrelevant for malware scanning.
var SkipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
	"vendor": true, ".venv": true, ".idea": true, ".vscode": true,
}

type Config struct {
	Recursive  bool
	Includes   []string
	Excludes   []string
	MinSize    int64
	MaxSize    int64
	MinSizeStr string
	MaxSizeStr string
}

// ShouldProcess decides whether a file should be hashed and looked up.
func ShouldProcess(d fs.DirEntry, includes, excludes []string, minSize, maxSize int64) (bool, error) {
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

	for _, pattern := range excludes {
		if ok, _ := filepath.Match(pattern, name); ok {
			return false, nil
		}
	}

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

// WalkMatchingFiles walks root and calls fn for every regular file that
// passes dir-skip and config filters.
func WalkMatchingFiles(root string, cfg Config, fn func(path string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning:", path, err)
			return nil
		}
		if d.IsDir() {
			if path != root {
				if SkipDirs[d.Name()] {
					return fs.SkipDir
				}
				if !cfg.Recursive {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ok, filterErr := ShouldProcess(d, cfg.Includes, cfg.Excludes, cfg.MinSize, cfg.MaxSize)
		if filterErr != nil {
			fmt.Fprintln(os.Stderr, "Warning:", path, filterErr)
			return nil
		}
		if !ok {
			return nil
		}
		return fn(path, d)
	})
}

// CollectMatchingFiles returns all files that pass filters.
func CollectMatchingFiles(root string, cfg Config) ([]string, error) {
	var files []string
	err := WalkMatchingFiles(root, cfg, func(path string, _ fs.DirEntry) error {
		files = append(files, path)
		return nil
	})
	return files, err
}

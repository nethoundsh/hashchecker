package main

import (
	"io/fs"
	"path/filepath"
)

// ── File Filtering ──────────────────────────────────────────────────
//
// shouldProcess decides whether a file should be hashed and looked up,
// based on the user's -include, -exclude, -min-size, and -max-size flags.
//
// Filtering order:
//  1. If -include is set, the filename must match at least one pattern.
//  2. If -exclude is set, the filename must NOT match any pattern.
//  3. If -min-size is set (> 0), the file must be at least that large.
//  4. If -max-size is set (> 0), the file must be at most that large.
//
// The includes and excludes parameters are pre-parsed slices of glob
// patterns (from the parsePatterns closure in run()). A nil or empty
// slice means "no filter" for that parameter. minSize/maxSize of 0
// means "no limit."
//
// filepath.Match matches against the base name only (e.g. "report.pdf"),
// not the full path. This is intentional — users think in terms of
// filenames and extensions, not full directory structures.
//
// Go idiom: returning (bool, error) lets callers distinguish "skip this
// file" (false, nil) from "something went wrong" (false, err). The
// error case can happen if d.Info() fails (e.g. file was deleted
// between WalkDir discovering it and us calling Info()).
func shouldProcess(d fs.DirEntry, includes, excludes []string, minSize, maxSize int64) (bool, error) {
	name := d.Name() // base filename, e.g. "report.pdf"

	// ── Include filter (whitelist) ──────────────────────────────────
	//
	// If -include was specified, the file must match at least one
	// pattern. Think of it as: "only process these types of files."
	if len(includes) > 0 {
		matched := false
		for _, pattern := range includes {
			// filepath.Match returns (bool, error). The error is only
			// non-nil for malformed patterns, which we already validated
			// at startup — so we can safely ignore it here.
			if ok, _ := filepath.Match(pattern, name); ok {
				matched = true
				break // one match is enough — no need to check the rest
			}
		}
		if !matched {
			return false, nil // file doesn't match any include pattern
		}
	}

	// ── Exclude filter (blacklist) ──────────────────────────────────
	//
	// If -exclude was specified, skip files matching any pattern.
	// This runs AFTER the include check, so -exclude can further
	// narrow the set selected by -include.
	for _, pattern := range excludes {
		if ok, _ := filepath.Match(pattern, name); ok {
			return false, nil // file matches an exclude pattern — skip it
		}
	}

	// ── Size filters ────────────────────────────────────────────────
	//
	// Size checks require file metadata (the file size in bytes).
	// d.Info() calls os.Lstat under the hood — this is a syscall.
	// We only call it when at least one size filter is active, to
	// avoid unnecessary syscalls when no size filtering is requested.
	if minSize > 0 || maxSize > 0 {
		info, err := d.Info()
		if err != nil {
			// The file might have been deleted or become inaccessible
			// between WalkDir discovering it and us calling Info().
			// Return the error so the caller can log it and continue.
			return false, err
		}
		fileSize := info.Size()

		if minSize > 0 && fileSize < minSize {
			return false, nil // file is too small
		}
		if maxSize > 0 && fileSize > maxSize {
			return false, nil // file is too large
		}
	}

	return true, nil // file passes all filters
}


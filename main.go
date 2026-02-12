// hashchecker is a CLI tool that computes file hashes and looks them up
// against the VirusTotal API to check for known malware. It supports
// SHA-256 (default), SHA-1, and MD5 via the -algo flag.
//
// It supports three input modes:
//   - A raw hash string (64 hex chars for SHA-256, 40 for SHA-1, 32 for MD5)
//   - A path to a single file
//   - A path to a directory (scans all regular files, optionally recursive)
//
// Results can be printed as colored human-readable text or as NDJSON for
// piping into other tools. A local disk cache avoids redundant API calls.
package main

import (
	"context"       // context.Context for cancellation propagation
	"crypto/md5"    // MD5 hashing (16-byte digest)
	"crypto/sha1"   // SHA-1 hashing (20-byte digest)
	"crypto/sha256" // SHA-256 hashing (32-byte digest)
	"encoding/hex"  // hex encode/decode — used for hash string conversion and validation
	"flag"          // stdlib CLI flag parsing — simple and idiomatic for Go CLIs
	"fmt"           // formatted I/O — Printf, Fprintln, etc.
	"hash"          // hash.Hash interface — common type for all crypto hash functions
	"io"            // io.Copy for streaming file content into the hasher without loading it all into memory
	"io/fs"         // filesystem interfaces — fs.SkipDir for WalkDir control, DirEntry for file metadata
	"net/http"      // HTTP client for VirusTotal API calls
	"os"            // file operations, environment variables, exit codes
	"os/signal"     // signal.NotifyContext for graceful Ctrl+C handling
	"path/filepath" // cross-platform path manipulation and directory walking
	"strings"       // string utilities — TrimSpace, ToLower
	"time"          // durations for rate limiting and cache expiry

	"github.com/dustin/go-humanize"         // third-party library for parsing human-readable sizes (e.g. "10MB" → bytes)
	"github.com/fatih/color"                // third-party library for ANSI-colored terminal output
	"github.com/mattn/go-isatty"            // detect whether a file descriptor is a terminal (TTY)
	"github.com/schollz/progressbar/v3"     // terminal progress bar with ETA and throughput display
	"golang.org/x/time/rate"                // token bucket rate limiter for API call pacing
)

// version identifies the build of hashchecker. This is printed via the
// -version flag and can be overridden at build time with:
//
//	go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

// skipDirs lists directory names that should always be skipped during
// directory scanning. These are typically version-control metadata,
// dependency caches, or IDE config folders — large trees of files that
// are irrelevant for malware scanning and would waste API quota.
//
// Go idiom: using a map[string]bool as a set. Lookups like
// skipDirs["node_modules"] return true if present, false (the zero
// value for bool) if absent — so it works as a clean membership test.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
	"vendor": true, ".venv": true, ".idea": true, ".vscode": true,
}

// scanConfig bundles the file-filter and scan flags that runFile and runDir
// both need. Extracting these into a struct keeps parameter lists short when
// passing filter state from run() to the helper functions.
type scanConfig struct {
	recursive  bool
	includes   []string
	excludes   []string
	minSize    int64
	maxSize    int64
	minSizeStr string // original flag value for human-readable skip messages
	maxSizeStr string
}

func main() {
	os.Exit(run())
}

func run() int {
	// ── CLI Flag Definitions ────────────────────────────────────────────
	//
	// Go idiom: flag.Bool / flag.String / flag.Int return *pointers*.
	// You dereference them later with *freeMode, *output, etc.
	// This is because the flag package needs to write to these variables
	// when it parses the command-line arguments during flag.Parse().
	freeMode := flag.Bool("free", false, "use free-tier rate limiting (4 requests/min)")
	rateLimit := flag.Int("rate", 0, "max API requests per minute (0 = no limit; overrides -free)")
	output := flag.String("o", "text", "output format: text or json")
	noColor := flag.Bool("no-color", false, "disable colored output")
	noCache := flag.Bool("no-cache", false, "disable cache (don't read or write)")
	noProgress := flag.Bool("no-progress", false, "disable progress bar for directory scans")
	refresh := flag.Bool("refresh", false, "ignore cached results but still write new ones")
	cacheAge := flag.Int("cache-age", 7, "maximum age of cached results in days")
	recursive := flag.Bool("r", false, "recursively scan subdirectories")
	algo := flag.String("algo", "sha256", "hash algorithm: sha256, sha1, or md5")
	showVersion := flag.Bool("version", false, "print version and exit")

	// ── File Filter Flags ───────────────────────────────────────────
	//
	// These flags let you narrow which files get hashed and looked up.
	// Filtering happens BEFORE hashing, so excluded files don't waste
	// CPU on hash computation or API quota on VirusTotal lookups.
	//
	// We use flag.String (not a custom flag.Value) for simplicity.
	// Comma-separated values are split after parsing — this avoids
	// the complexity of a custom flag type for a single-file project.
	include := flag.String("include", "", "comma-separated glob patterns — only process matching files (e.g. \"*.exe,*.dll\")")
	exclude := flag.String("exclude", "", "comma-separated glob patterns — skip matching files (e.g. \"*.tmp,*.log\")")
	minSizeStr := flag.String("min-size", "", "minimum file size with units (e.g. \"1KB\", \"10MB\")")
	maxSizeStr := flag.String("max-size", "", "maximum file size with units (e.g. \"100MB\", \"1GB\")")

	// Customize the usage message printed by -h or when no arguments
	// are provided. flag.PrintDefaults() formats all registered flags
	// with their types and default values.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: hashchecker [flags] <file | hash | directory>\n\nFlags:\n")
		flag.PrintDefaults()
	}

	// flag.Parse() processes os.Args[1:] and populates all the flag
	// pointers above. Any remaining non-flag arguments (the file path
	// or hash) are available via flag.Arg(n) / flag.NArg().
	flag.Parse()

	// -version is a common convention for CLIs — print version and exit
	// without requiring any positional arguments.
	if *showVersion {
		fmt.Println("hashchecker", version)
		return 0
	}

	// ── Signal Handling ─────────────────────────────────────────────
	//
	// Create a context that is cancelled when the user presses Ctrl+C.
	// This lets long-running operations (rate-limit waits, HTTP requests)
	// exit cleanly instead of hanging. The deferred stop() restores
	// default signal behavior when run() returns.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// ── Parse Filter Flags ──────────────────────────────────────────
	//
	// Convert the raw string flag values into typed Go values that
	// the shouldProcess() function can use efficiently.

	// parsePatterns splits a comma-separated string into a slice of
	// trimmed, non-empty patterns. Returns nil for an empty input.
	//
	// Go idiom: a nil slice and an empty slice ([]string{}) behave
	// identically with len() and range, so nil is the idiomatic way
	// to represent "nothing" for slices. This matters because we
	// check len(includes) > 0 in shouldProcess to decide whether
	// the include filter is active.
	parsePatterns := func(s string) []string {
		if s == "" {
			return nil
		}
		raw := strings.Split(s, ",")
		var patterns []string
		for _, p := range raw {
			p = strings.TrimSpace(p)
			if p != "" {
				patterns = append(patterns, p)
			}
		}
		return patterns
	}

	includes := parsePatterns(*include)
	excludes := parsePatterns(*exclude)

	// Validate all glob patterns up front so we fail fast with a
	// clear error message rather than failing mid-scan on the first
	// matching file. filepath.Match returns filepath.ErrBadPattern
	// for malformed patterns like "[unclosed-bracket".
	validatePatterns := func(flagName string, patterns []string) error {
		for _, p := range patterns {
			if _, err := filepath.Match(p, "test"); err != nil {
				return fmt.Errorf("invalid %s pattern %q: %w", flagName, p, err)
			}
		}
		return nil
	}
	if err := validatePatterns("-include", includes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := validatePatterns("-exclude", excludes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// Parse human-readable size strings into byte counts.
	//
	// humanize.ParseBytes understands units like B, KB, MB, GB, TB.
	// It returns uint64 because file sizes are never negative. We
	// convert to int64 because os.FileInfo.Size() returns int64 —
	// keeping the same type avoids mixed-type comparisons.
	//
	// A value of 0 means "no limit" — this is our sentinel. Zero
	// works because a 0-byte minimum is effectively "no minimum" and
	// a 0-byte maximum would make no practical sense.
	var minSize, maxSize int64

	if *minSizeStr != "" {
		bytes, err := humanize.ParseBytes(*minSizeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -min-size value %q: %v\n", *minSizeStr, err)
			return 1
		}
		minSize = int64(bytes)
	}

	if *maxSizeStr != "" {
		bytes, err := humanize.ParseBytes(*maxSizeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -max-size value %q: %v\n", *maxSizeStr, err)
			return 1
		}
		maxSize = int64(bytes)
	}

	// Sanity check: if both are set, min must not exceed max.
	if minSize > 0 && maxSize > 0 && minSize > maxSize {
		fmt.Fprintf(os.Stderr, "-min-size (%s) cannot be greater than -max-size (%s)\n",
			*minSizeStr, *maxSizeStr)
		return 1
	}

	// Validate the output format immediately. A switch with empty "ok"
	// cases is a common Go pattern for whitelisting allowed values.
	switch *output {
	case "text", "json":
		// ok — valid output format
	default:
		fmt.Fprintln(os.Stderr, "invalid -o value; must be 'text' or 'json'")
		return 1
	}

	// Validate the hash algorithm. Same whitelisting pattern.
	switch *algo {
	case "sha256", "sha1", "md5":
		// ok — valid algorithm
	default:
		fmt.Fprintln(os.Stderr, "invalid -algo value; must be 'sha256', 'sha1', or 'md5'")
		return 1
	}

	// Disable color when outputting JSON (so it can be parsed by other
	// tools) or when the user explicitly requests no color.
	// color.NoColor is a package-level variable from fatih/color that
	// globally disables ANSI escape codes when set to true.
	if *output == "json" || *noColor {
		color.NoColor = true
	}

	// ── Progress Bar Decision ───────────────────────────────────────
	//
	// Show a progress bar for directory scans when:
	//   1. Output is text (not JSON — JSON consumers parse stdout)
	//   2. User hasn't explicitly disabled it with -no-progress
	//   3. Stderr is a real terminal (not piped or redirected)
	//
	// Why stderr? The bar writes to stderr so that piping stdout
	// (e.g. hashchecker -r dir > results.txt) still shows progress
	// on the terminal. isatty checks whether stderr is a TTY.
	showProgress := *output == "text" && !*noProgress &&
		isatty.IsTerminal(os.Stderr.Fd())

	// ── Rate Limiter Setup ──────────────────────────────────────────
	//
	// Resolve the effective rate from -free and --rate flags.
	// --rate takes precedence: if set to a non-zero value, it overrides
	// -free. If neither is set, effectiveRate stays 0 (no limiting).
	//
	// Go idiom: using a nil pointer to represent "feature disabled."
	// We check limiter != nil before calling Wait(), so callers don't
	// need separate "is rate limiting enabled?" booleans.
	effectiveRate := *rateLimit
	if effectiveRate == 0 && *freeMode {
		effectiveRate = 4 // VT free tier: 4 requests per minute
	}

	var limiter *rate.Limiter
	if effectiveRate > 0 {
		// rate.Every converts "one event per duration" into a rate.Limit.
		// For 4 req/min: time.Minute / 4 = 15s → one token every 15 seconds.
		// Burst of 1 means we never "bank" unused tokens — each request
		// must wait for its own token. This matches VT's sliding window.
		limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(effectiveRate)), 1)
		fmt.Fprintf(os.Stderr, "Rate limiting: %d requests/min\n", effectiveRate)
	}

	// Require at least one positional argument (the target to scan).
	// flag.NArg() returns the count of non-flag arguments remaining
	// after flag.Parse().
	if flag.NArg() < 1 {
		flag.Usage()
		return 1
	}

	// ── Cache Initialization ────────────────────────────────────────────
	//
	// The cache maps "algo:hash" keys to their VirusTotal results and
	// a timestamp. This avoids redundant API calls for files that have
	// already been checked recently.
	//
	// We declare the cache and its path here so they're available to
	// all code paths (hash lookup, single file, directory scan).
	var cache map[string]cacheEntry
	var cachePath string
	if !*noCache {
		var err error
		cachePath, err = getCacheFilePath()
		if err != nil {
			// Graceful degradation: if we can't determine the cache path
			// (e.g. HOME isn't set), we warn and continue without caching
			// rather than failing the entire run.
			fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			cache = make(map[string]cacheEntry)
		} else {
			cache, err = loadCache(cachePath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			}
		}
	}
	// Ensure cache is never nil so we can always read/write it without
	// nil-pointer checks throughout the code. This is a common Go
	// defensive pattern: initialize maps before use.
	if cache == nil {
		cache = make(map[string]cacheEntry)
	}

	// flushCache is a closure that persists the in-memory cache to disk.
	// We define it as a closure (anonymous function assigned to a variable)
	// so it captures the cachePath and cache variables from the enclosing
	// scope. This avoids passing them as parameters at every exit point.
	flushCache := func() {
		if !*noCache && cachePath != "" {
			if err := saveCache(cachePath, cache); err != nil {
				fmt.Fprintln(os.Stderr, "Warning: failed to save cache:", err)
			}
		}
	}
	defer flushCache()

	// ── HTTP Client & API Key ───────────────────────────────────────────
	//
	// Create a single shared HTTP client. Go's http.Client reuses TCP
	// connections internally (via its Transport), so creating one client
	// and passing it around is more efficient than creating a new one per
	// request. The 15-second timeout covers the full request lifecycle
	// (DNS, connect, TLS handshake, response headers, body read).
	client := &http.Client{Timeout: 15 * time.Second}

	// Read and validate the API key up front so we fail fast before
	// doing any expensive work (hashing files, etc.).
	// strings.TrimSpace removes any trailing newline that might sneak
	// in from a shell export or .env file.
	apiKey := strings.TrimSpace(os.Getenv("VIRUSTOTAL_API_KEY"))
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "VIRUSTOTAL_API_KEY is not set")
		return 1
	}

	// The first positional argument — either a hex hash string, a file
	// path, or a directory path.
	arg := flag.Arg(0)

	// Bundle the lookup configuration into a struct so we don't have to
	// thread a long parameter list through every call site.
	cfg := lookupConfig{
		ctx:          ctx,
		client:       client,
		apiKey:       apiKey,
		output:       *output,
		algo:         *algo,
		cache:        cache,
		refresh:      *refresh,
		cacheAgeDays: *cacheAge,
		limiter:      limiter,
		baseURL:      os.Getenv("VIRUSTOTAL_BASE_URL"),
	}

	// ── Dispatch ────────────────────────────────────────────────────────
	//
	// Bundle filter flags into a scanConfig for the helper functions,
	// then dispatch to the appropriate handler based on the argument type.
	sc := scanConfig{
		recursive:  *recursive,
		includes:   includes,
		excludes:   excludes,
		minSize:    minSize,
		maxSize:    maxSize,
		minSizeStr: *minSizeStr,
		maxSizeStr: *maxSizeStr,
	}

	if isHexHash(arg, *algo) {
		return runHash(arg, cfg)
	}

	fi, err := os.Stat(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if fi.IsDir() {
		return runDir(arg, cfg, sc, showProgress)
	}
	return runFile(arg, fi, cfg, sc)
}

// ── Extracted Helpers ───────────────────────────────────────────────
//
// runHash, runDir, and runFile each handle one of the three dispatch
// branches in run(). They return an exit code: 0 = clean, 1 = error,
// 2 = malicious file(s) found.

// runHash handles the case where the user passes a raw hex hash
// string. It normalizes the hash to lowercase, looks it up on
// VirusTotal, and returns the appropriate exit code.
func runHash(arg string, cfg lookupConfig) int {
	hash := strings.ToLower(arg)
	result, err := lookupAndPrint("", hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if result.Found && result.Malicious > 0 {
		return 2
	}
	return 0
}

// runDir handles the case where the user passes a directory path.
// It walks the directory tree (optionally recursive), hashes each
// matching file, looks it up on VirusTotal, and prints a summary.
//
// When showProgress is true, a pre-walk counts matching files so
// we can display a determinate progress bar with percentage and ETA.
func runDir(arg string, cfg lookupConfig, sc scanConfig, showProgress bool) int {
	var looked, found, malicious int

	// ── Progress Bar Setup ──────────────────────────────────────────
	//
	// Pre-walk the directory to count matching files. This is fast
	// (no hashing or API calls) and gives us a total for the bar.
	var bar *progressbar.ProgressBar
	if showProgress {
		total, err := countMatchingFiles(arg, sc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning: could not count files:", err)
		} else if total > 0 {
			bar = progressbar.NewOptions(total,
				progressbar.OptionSetWriter(os.Stderr),
				progressbar.OptionSetDescription("Scanning"),
				progressbar.OptionShowCount(),
				progressbar.OptionShowIts(),
				progressbar.OptionSetItsString("files"),
				progressbar.OptionClearOnFinish(),
				progressbar.OptionSetPredictTime(true),
				progressbar.OptionSetTheme(progressbar.Theme{
					Saucer:        "=",
					SaucerHead:    ">",
					SaucerPadding: " ",
					BarStart:      "[",
					BarEnd:        "]",
				}),
			)
		}
	}

	err := filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
		if cfg.ctx.Err() != nil {
			return cfg.ctx.Err()
		}

		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", path, err)
			return nil
		}

		if d.IsDir() {
			if path != arg {
				if skipDirs[d.Name()] {
					return fs.SkipDir
				}
				if !sc.recursive {
					return fs.SkipDir
				}
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		ok, filterErr := shouldProcess(d, sc.includes, sc.excludes, sc.minSize, sc.maxSize)
		if filterErr != nil {
			fmt.Fprintln(os.Stderr, "Warning:", path, filterErr)
			return nil
		}
		if !ok {
			return nil
		}

		hash, err := hashFile(path, cfg.algo)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", path, err)
			return nil
		}

		if cfg.output == "text" {
			fmt.Println(color.HiBlueString("--- %s ---", path))
		}

		result, err := lookupAndPrint(path, hash, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return nil
		}

		looked++
		if result.Found {
			found++
			if result.Malicious > 0 {
				malicious++
			}
		}

		if bar != nil {
			_ = bar.Add(1)
		}
		return nil
	})
	if bar != nil {
		_ = bar.Finish()
	}

	if err != nil {
		if cfg.ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "\nInterrupted")
		} else {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		return 1
	}

	if cfg.output == "json" {
		if err := printJSONSummary(arg, looked, found, malicious); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return 1
		}
	} else {
		maliciousStr := color.GreenString("%d", malicious)
		if malicious > 0 {
			maliciousStr = color.RedString("%d", malicious)
		}
		fmt.Printf("Checked %d files, %d found in VirusTotal, %s malicious\n", looked, found, maliciousStr)
	}

	if malicious > 0 {
		return 2
	}
	return 0
}

// countMatchingFiles does a fast pre-walk of the directory tree using
// the same dir-skip and shouldProcess() filter logic as runDir, but
// only counts files — no hashing or API calls. This gives us a total
// for the progress bar so it can show percentage and ETA.
//
// Even for thousands of files, this completes in milliseconds because
// it only reads directory entries and (when size filters are active)
// file metadata — no file contents are read.
func countMatchingFiles(root string, sc scanConfig) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}
		if d.IsDir() {
			if path != root {
				if skipDirs[d.Name()] {
					return fs.SkipDir
				}
				if !sc.recursive {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ok, filterErr := shouldProcess(d, sc.includes, sc.excludes, sc.minSize, sc.maxSize)
		if filterErr != nil || !ok {
			return nil
		}
		count++
		return nil
	})
	return count, err
}

// runFile handles the case where the user passes a path to a single file.
// Glob filters (-include/-exclude) are not applied — the user explicitly
// named this file. Size filters still apply because a pipeline may
// enforce size constraints.
func runFile(arg string, fi os.FileInfo, cfg lookupConfig, sc scanConfig) int {
	if sc.minSize > 0 || sc.maxSize > 0 {
		fileSize := fi.Size()
		if sc.minSize > 0 && fileSize < sc.minSize {
			fmt.Fprintf(os.Stderr, "Skipped: %s (%s) is smaller than -min-size %s\n",
				arg, humanize.Bytes(uint64(fileSize)), sc.minSizeStr)
			return 0
		}
		if sc.maxSize > 0 && fileSize > sc.maxSize {
			fmt.Fprintf(os.Stderr, "Skipped: %s (%s) is larger than -max-size %s\n",
				arg, humanize.Bytes(uint64(fileSize)), sc.maxSizeStr)
			return 0
		}
	}

	hash, err := hashFile(arg, cfg.algo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	result, err := lookupAndPrint(arg, hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if result.Found && result.Malicious > 0 {
		return 2
	}
	return 0
}

// ── Utility Functions ───────────────────────────────────────────────

// isHexHash reports whether s looks like a valid hex-encoded hash for
// the given algorithm. Each algorithm has a fixed digest size:
//   - SHA-256 = 32 bytes (64 hex chars)
//   - SHA-1   = 20 bytes (40 hex chars)
//   - MD5     = 16 bytes (32 hex chars)
//
// Rather than checking length and character set separately, we use
// hex.DecodeString which validates both in one call — if the string
// has an odd length or non-hex characters, it returns an error.
// We then confirm the decoded length matches the expected digest size.
//
// Go naming convention: functions that return bool are often named
// "isSomething" or "hasSomething" for readability at the call site.
func isHexHash(s, algo string) bool {
	b, err := hex.DecodeString(s)
	if err != nil {
		return false
	}
	switch algo {
	case "sha256":
		return len(b) == 32
	case "sha1":
		return len(b) == 20
	case "md5":
		return len(b) == 16
	default:
		return false
	}
}

// hashFile computes the hash of the file at filePath using the specified
// algorithm and returns it as a lowercase hex string.
//
// Go idiom: hash.Hash is the standard interface that all crypto hash
// functions (sha256, sha1, md5) implement. It also satisfies io.Writer,
// so the same io.Copy streaming pattern works for any algorithm —
// polymorphism through interfaces.
//
// Go idiom: defer file.Close() guarantees the file handle is released
// when the function returns, regardless of whether we return normally
// or via an error. This prevents file descriptor leaks.
//
// Go idiom: io.Copy streams data from the file (an io.Reader) into the
// hash (an io.Writer) in chunks. This means we never load the entire
// file into memory — critical for hashing large files without running
// out of RAM.
func hashFile(filePath, algo string) (_ string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("hashing: %w", err) // os.Open already includes the path
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("hashing %s: %w", filePath, closeErr)
		}
	}()

	// Select the hash function based on the algorithm flag. Each
	// New() returns a hash.Hash, which implements io.Writer. Each
	// Write call updates the running hash. Sum(nil) finalizes it
	// and returns the digest bytes.
	var h hash.Hash
	switch algo {
	case "sha256":
		h = sha256.New()
	case "sha1":
		h = sha1.New()
	case "md5":
		h = md5.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algo)
	}
	_, err = io.Copy(h, file)
	if err != nil {
		return "", fmt.Errorf("hashing %s: %w", filePath, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

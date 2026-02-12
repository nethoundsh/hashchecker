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
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/time/rate"
)

// version can be overridden at build time with:
//
//	go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

// skipDirs lists directory names that are irrelevant for malware
// scanning (VCS metadata, dependency caches, IDE config).
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
	"vendor": true, ".venv": true, ".idea": true, ".vscode": true,
}

// hashResult holds all three hash digests computed from a single file read.
type hashResult struct {
	SHA256 string
	SHA1   string
	MD5    string
}

// ForAlgo returns the hash for the given algorithm name.
func (h hashResult) ForAlgo(algo string) string {
	switch algo {
	case "sha256":
		return h.SHA256
	case "sha1":
		return h.SHA1
	case "md5":
		return h.MD5
	default:
		return h.SHA256
	}
}

type scanConfig struct {
	recursive  bool
	includes   []string
	excludes   []string
	minSize    int64
	maxSize    int64
	minSizeStr string // original flag value for human-readable skip messages
	maxSizeStr string
}

type appConfig struct {
	lookupCfg    lookupConfig
	scanCfg      scanConfig
	arg          string
	showProgress bool
	flushCache   func()
	stop         func()
}

var (
	errVersion = errors.New("version requested")
	errUsage   = errors.New("no arguments provided")
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := parseConfig()
	if err != nil {
		switch {
		case errors.Is(err, errVersion):
			fmt.Println("hashchecker", version)
			return 0
		case errors.Is(err, errUsage):
			flag.Usage()
			return 1
		default:
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	defer cfg.stop()
	defer cfg.flushCache()

	if ok, detectedAlgo := isHexHash(cfg.arg); ok {
		return runHash(cfg.arg, detectedAlgo, cfg.lookupCfg)
	}
	fi, err := os.Stat(cfg.arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if fi.IsDir() {
		return runDir(cfg.arg, cfg.lookupCfg, cfg.scanCfg, cfg.showProgress)
	}
	return runFile(cfg.arg, fi, cfg.lookupCfg, cfg.scanCfg)
}

// parseConfig parses CLI flags, validates inputs, and initializes all
// resources (cache, HTTP client, rate limiter, signal handler).
func parseConfig() (appConfig, error) {
	freeMode := flag.Bool("free", false, "use free-tier rate limiting (4 requests/min)")
	rateLimit := flag.Int("rate", 0, "max API requests per minute (0 = no limit; overrides -free)")
	output := flag.String("o", "text", "output format: text or json")
	noColor := flag.Bool("no-color", false, "disable colored output")
	noCache := flag.Bool("no-cache", false, "disable cache (don't read or write)")
	noProgress := flag.Bool("no-progress", false, "disable progress bar for directory scans")
	refresh := flag.Bool("refresh", false, "ignore cached results but still write new ones")
	cacheAge := flag.Int("cache-age", 7, "maximum age of cached results in days")
	recursive := flag.Bool("r", false, "recursively scan subdirectories")
	algo := flag.String("algo", "sha256", "hash algorithm for VirusTotal lookup: sha256, sha1, or md5")
	showVersion := flag.Bool("version", false, "print version and exit")

	include := flag.String("include", "", "comma-separated glob patterns — only process matching files (e.g. \"*.exe,*.dll\")")
	exclude := flag.String("exclude", "", "comma-separated glob patterns — skip matching files (e.g. \"*.tmp,*.log\")")
	minSizeStr := flag.String("min-size", "", "minimum file size with units (e.g. \"1KB\", \"10MB\")")
	maxSizeStr := flag.String("max-size", "", "maximum file size with units (e.g. \"100MB\", \"1GB\")")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: hashchecker [flags] <file | hash | directory>\n\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		return appConfig{}, errVersion
	}

	// Cancelled on Ctrl+C so long-running operations exit cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	// If parseConfig returns an error, stop() must be called to
	// unregister the signal handler. On success, ownership of stop()
	// transfers to the caller via appConfig.stop.
	succeeded := false
	defer func() {
		if !succeeded {
			stop()
		}
	}()

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

	validatePatterns := func(flagName string, patterns []string) error {
		for _, p := range patterns {
			if _, err := filepath.Match(p, "test"); err != nil {
				return fmt.Errorf("invalid %s pattern %q: %w", flagName, p, err)
			}
		}
		return nil
	}
	if err := validatePatterns("-include", includes); err != nil {
		return appConfig{}, err
	}
	if err := validatePatterns("-exclude", excludes); err != nil {
		return appConfig{}, err
	}

	var minSize, maxSize int64 // 0 means "no limit"

	if *minSizeStr != "" {
		bytes, err := humanize.ParseBytes(*minSizeStr)
		if err != nil {
			return appConfig{}, fmt.Errorf("invalid -min-size value %q: %w", *minSizeStr, err)
		}
		minSize = int64(bytes)
	}

	if *maxSizeStr != "" {
		bytes, err := humanize.ParseBytes(*maxSizeStr)
		if err != nil {
			return appConfig{}, fmt.Errorf("invalid -max-size value %q: %w", *maxSizeStr, err)
		}
		maxSize = int64(bytes)
	}

	if minSize > 0 && maxSize > 0 && minSize > maxSize {
		return appConfig{}, fmt.Errorf("-min-size (%s) cannot be greater than -max-size (%s)",
			*minSizeStr, *maxSizeStr)
	}

	switch *output {
	case "text", "json":
	default:
		return appConfig{}, fmt.Errorf("invalid -o value; must be 'text' or 'json'")
	}

	switch *algo {
	case "sha256", "sha1", "md5":
	default:
		return appConfig{}, fmt.Errorf("invalid -algo value; must be 'sha256', 'sha1', or 'md5'")
	}

	if *output == "json" || *noColor {
		color.NoColor = true
	}

	// Progress bar: text output only, on a real terminal (not piped).
	showProgress := *output == "text" && !*noProgress &&
		isatty.IsTerminal(os.Stderr.Fd())

	// --rate overrides -free. Burst of 1 matches VT's sliding window.
	effectiveRate := *rateLimit
	if effectiveRate == 0 && *freeMode {
		effectiveRate = 4
	}

	var limiter *rate.Limiter
	if effectiveRate > 0 {
		limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(effectiveRate)), 1)
		fmt.Fprintf(os.Stderr, "Rate limiting: %d requests/min\n", effectiveRate)
	}

	if flag.NArg() < 1 {
		return appConfig{}, errUsage
	}

	// Graceful degradation: warn and continue without caching on errors.
	var cache map[string]cacheEntry
	var cachePath string
	if !*noCache {
		var err error
		cachePath, err = getCacheFilePath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			cache = make(map[string]cacheEntry)
		} else {
			cache, err = loadCache(cachePath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			}
		}
	}
	if cache == nil {
		cache = make(map[string]cacheEntry)
	}

	flushCache := func() {
		if !*noCache && cachePath != "" {
			if err := saveCache(cachePath, cache); err != nil {
				fmt.Fprintln(os.Stderr, "Warning: failed to save cache:", err)
			}
		}
	}

	client := &http.Client{Timeout: 15 * time.Second}

	apiKey := strings.TrimSpace(os.Getenv("VIRUSTOTAL_API_KEY"))
	if apiKey == "" {
		return appConfig{}, fmt.Errorf("VIRUSTOTAL_API_KEY is not set")
	}

	arg := flag.Arg(0)

	succeeded = true
	return appConfig{
		lookupCfg: lookupConfig{
			ctx:          ctx,
			client:       client,
			apiKey:       apiKey,
			output:       *output,
			algo:         *algo,
			cache:        cache,
			cacheMu:      &sync.Mutex{},
			refresh:      *refresh,
			cacheAgeDays: *cacheAge,
			limiter:      limiter,
			baseURL:      os.Getenv("VIRUSTOTAL_BASE_URL"),
		},
		scanCfg: scanConfig{
			recursive:  *recursive,
			includes:   includes,
			excludes:   excludes,
			minSize:    minSize,
			maxSize:    maxSize,
			minSizeStr: *minSizeStr,
			maxSizeStr: *maxSizeStr,
		},
		arg:          arg,
		showProgress: showProgress,
		flushCache:   flushCache,
		stop:         stop,
	}, nil
}

// Exit codes: 0 = clean, 1 = error, 2 = malicious file(s) found.

func runHash(arg, detectedAlgo string, cfg lookupConfig) int {
	cfg.algo = detectedAlgo
	hash := strings.ToLower(arg)
	result, err := lookup(hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if err := printLookupResult(os.Stdout, "", hash, cfg, result, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if result.Found && result.Malicious > 0 {
		return 2
	}
	return 0
}

// runDir walks a directory, hashes each matching file, and looks it up.
// With showProgress, files are collected first to get a total for the bar.
func runDir(arg string, cfg lookupConfig, sc scanConfig, showProgress bool) int {
	var looked, found, malicious int
	var progress *mpb.Progress
	var bar *mpb.Bar

	processFile := func(path string) {
		hashes, err := hashFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", path, err)
			return
		}
		hash := hashes.ForAlgo(cfg.algo)

		var w io.Writer = os.Stdout
		var buf bytes.Buffer
		if progress != nil {
			w = &buf
		}

		if cfg.output == "text" {
			_, _ = fmt.Fprintln(w, color.HiBlueString("--- %s ---", path))
		}

		result, err := lookup(hash, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return
		}
		if err := printLookupResult(w, path, hash, cfg, result, &hashes); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return
		}

		if progress != nil {
			_, _ = progress.Write(buf.Bytes())
		}

		looked++
		if result.Found {
			found++
			if result.Malicious > 0 {
				malicious++
			}
		}

		if bar != nil {
			bar.Increment()
		}
	}

	var err error

	if showProgress {
		files, collectErr := collectMatchingFiles(arg, sc)
		if collectErr != nil {
			fmt.Fprintln(os.Stderr, "Warning: could not collect files:", collectErr)
		}

		if len(files) > 0 {
			progress = mpb.NewWithContext(cfg.ctx, mpb.WithOutput(os.Stderr))
			bar = progress.New(int64(len(files)),
				mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding(" ").Rbound("]"),
				mpb.PrependDecorators(decor.Name("Scanning ")),
				mpb.AppendDecorators(
					decor.CountersNoUnit(" %d / %d "),
					decor.AverageETA(decor.ET_STYLE_MMSS),
				),
				mpb.BarRemoveOnComplete(),
			)
		}

		for _, path := range files {
			if cfg.ctx.Err() != nil {
				err = cfg.ctx.Err()
				break
			}
			processFile(path)
		}
	} else {
		err = walkMatchingFiles(arg, sc, func(path string, _ fs.DirEntry) error {
			if cfg.ctx.Err() != nil {
				return cfg.ctx.Err()
			}
			processFile(path)
			return nil
		})
	}

	if progress != nil {
		progress.Wait()
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
		if err := printJSONSummary(os.Stdout, arg, looked, found, malicious); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return 1
		}
	} else {
		maliciousStr := color.GreenString("%d", malicious)
		if malicious > 0 {
			maliciousStr = color.RedString("%d", malicious)
		}
		fileWord := "files"
		if looked == 1 {
			fileWord = "file"
		}
		_, _ = fmt.Fprintf(os.Stdout, "Checked %d %s, %d found in VirusTotal, %s malicious\n", looked, fileWord, found, maliciousStr)
	}

	if malicious > 0 {
		return 2
	}
	return 0
}

// walkMatchingFiles walks root and calls fn for every regular file that
// passes the dir-skip and scanConfig filters. It is the single place
// where directory traversal + filtering logic lives.
func walkMatchingFiles(root string, sc scanConfig, fn func(path string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning:", path, err)
			return nil
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

// collectMatchingFiles walks the directory tree once and returns paths
// of all files that pass the dir-skip and shouldProcess() filters.
func collectMatchingFiles(root string, sc scanConfig) ([]string, error) {
	var files []string
	err := walkMatchingFiles(root, sc, func(path string, _ fs.DirEntry) error {
		files = append(files, path)
		return nil
	})
	return files, err
}

// runFile handles a single file. Glob filters are not applied (user
// explicitly named this file), but size filters still apply.
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

	hashes, err := hashFile(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	hash := hashes.ForAlgo(cfg.algo)
	result, err := lookup(hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if err := printLookupResult(os.Stdout, arg, hash, cfg, result, &hashes); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if result.Found && result.Malicious > 0 {
		return 2
	}
	return 0
}

// isHexHash reports whether s is a valid hex-encoded hash and, if so,
// which algorithm it matches based on decoded byte length:
// 32 bytes = sha256, 20 = sha1, 16 = md5.
func isHexHash(s string) (bool, string) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return false, ""
	}
	switch len(b) {
	case 32:
		return true, "sha256"
	case 20:
		return true, "sha1"
	case 16:
		return true, "md5"
	default:
		return false, ""
	}
}

// hashFile computes SHA-256, SHA-1, and MD5 of filePath in a single pass
// using io.MultiWriter. Disk I/O dominates, so computing all three costs
// essentially the same as one.
func hashFile(filePath string) (_ hashResult, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return hashResult{}, fmt.Errorf("hashing: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("hashing %s: %w", filePath, closeErr)
		}
	}()

	h256 := sha256.New()
	h1 := sha1.New()
	hMD5 := md5.New()

	if _, err = io.Copy(io.MultiWriter(h256, h1, hMD5), file); err != nil {
		return hashResult{}, fmt.Errorf("hashing %s: %w", filePath, err)
	}
	return hashResult{
		SHA256: hex.EncodeToString(h256.Sum(nil)),
		SHA1:   hex.EncodeToString(h1.Sum(nil)),
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
	}, nil
}

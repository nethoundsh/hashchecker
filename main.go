// hashchecker is a CLI tool that computes file hashes and looks them up
// against the VirusTotal API to check for known malware. It supports
// SHA-256 (default), SHA-1, and MD5 via the -algo flag.
//
// It supports four input modes:
//   - A raw hash string (64 hex chars for SHA-256, 40 for SHA-1, 32 for MD5)
//   - A path to a single file
//   - A path to a directory (scans all regular files, optionally recursive)
//   - A hash-list file via -f (one hash per line; comments with # supported)
//
// Results can be printed as colored human-readable text or as NDJSON for
// piping into other tools. A local disk cache avoids redundant API calls.
// Directory and hash-list scans run concurrently using a worker pool
// (configurable with -workers). Output order matches input order
// regardless of worker count.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	runnerpkg "github.com/nethoundsh/hashchecker/internal/runner"
	cachepkg "github.com/nethoundsh/hashchecker/pkg/cache"
	filterpkg "github.com/nethoundsh/hashchecker/pkg/filter"
	"github.com/nethoundsh/hashchecker/pkg/hasher"
	"github.com/nethoundsh/hashchecker/pkg/vtclient"
	"golang.org/x/time/rate"
)

// version can be overridden at build time with:
//
//	go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

// testBaseURL is a test hook for overriding VirusTotal API base URL.
// It is intentionally unexported and not environment-driven.
var testBaseURL string

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
	if cfg.Stop != nil {
		defer cfg.Stop()
	}
	if cfg.FlushCache != nil {
		defer cfg.FlushCache()
	}

	if cfg.HashListPath != "" {
		return runnerpkg.RunHashList(cfg.HashListPath, cfg.LookupCfg, cfg.Workers)
	}

	fi, err := os.Stat(cfg.Arg)
	if err == nil {
		if fi.IsDir() {
			return runnerpkg.RunDir(cfg.Arg, cfg.LookupCfg, cfg.ScanCfg, cfg.ShowProgress, cfg.Workers)
		}
		return runnerpkg.RunFile(cfg.Arg, fi, cfg.LookupCfg, cfg.ScanCfg)
	}
	if !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}

	if ok, detectedAlgo := hasher.IsHexHash(cfg.Arg); ok {
		return runnerpkg.RunHash(cfg.Arg, detectedAlgo, cfg.LookupCfg)
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	return 1
}

type flagConfig struct {
	freeMode     bool
	rateLimit    int
	output       string
	noColor      bool
	noCache      bool
	noProgress   bool
	refresh      bool
	cacheAge     int
	recursive    bool
	workers      int
	algo         string
	hashListFile string
	includes     []string
	excludes     []string
	minSize      int64
	maxSize      int64
	minSizeStr   string
	maxSizeStr   string
	arg          string
}

func parseConfig() (runnerpkg.AppConfig, error) {
	flags, err := parseFlags()
	if err != nil {
		return runnerpkg.AppConfig{}, err
	}
	return initResources(flags)
}

func parseFlags() (flagConfig, error) {
	freeMode := flag.Bool("free", false, "use free-tier rate limiting (4 requests/min)")
	rateLimit := flag.Int("rate", 0, "max API requests per minute (0 = no limit; overrides -free)")
	output := flag.String("o", "text", "output format: text or json")
	noColor := flag.Bool("no-color", false, "disable colored output")
	noCache := flag.Bool("no-cache", false, "disable cache (don't read or write)")
	noProgress := flag.Bool("no-progress", false, "disable progress bar for directory scans")
	refresh := flag.Bool("refresh", false, "ignore cached results but still write new ones")
	cacheAge := flag.Int("cache-age", 7, "maximum age of cached results in days")
	recursive := flag.Bool("r", false, "recursively scan subdirectories")
	workers := flag.Int("workers", 0, "number of concurrent workers for directory and hash-list scans (0 = number of CPUs)")
	algo := flag.String("algo", "sha256", "hash algorithm for file lookup mode: sha256, sha1, or md5 (raw hash and -f modes auto-detect)")
	hashListFile := flag.String("f", "", "path to a file containing one hash per line")
	showVersion := flag.Bool("version", false, "print version and exit")

	include := flag.String("include", "", "comma-separated glob patterns — only process matching files (e.g. \"*.exe,*.dll\")")
	exclude := flag.String("exclude", "", "comma-separated glob patterns — skip matching files (e.g. \"*.tmp,*.log\")")
	minSizeStr := flag.String("min-size", "", "minimum file size with units (e.g. \"1KB\", \"10MB\")")
	maxSizeStr := flag.String("max-size", "", "maximum file size with units (e.g. \"100MB\", \"1GB\")")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: hashchecker [flags] <file | hash | directory | -f hashlist>\n\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		return flagConfig{}, errVersion
	}

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
		return flagConfig{}, err
	}
	if err := validatePatterns("-exclude", excludes); err != nil {
		return flagConfig{}, err
	}

	var minSize, maxSize int64 // 0 means "no limit"

	if *minSizeStr != "" {
		bytes, err := humanize.ParseBytes(*minSizeStr)
		if err != nil {
			return flagConfig{}, fmt.Errorf("invalid -min-size value %q: %w", *minSizeStr, err)
		}
		minSize = int64(bytes)
	}

	if *maxSizeStr != "" {
		bytes, err := humanize.ParseBytes(*maxSizeStr)
		if err != nil {
			return flagConfig{}, fmt.Errorf("invalid -max-size value %q: %w", *maxSizeStr, err)
		}
		maxSize = int64(bytes)
	}

	if minSize > 0 && maxSize > 0 && minSize > maxSize {
		return flagConfig{}, fmt.Errorf("-min-size (%s) cannot be greater than -max-size (%s)",
			*minSizeStr, *maxSizeStr)
	}

	switch *output {
	case "text", "json":
	default:
		return flagConfig{}, errors.New("invalid -o value; must be 'text' or 'json'")
	}

	switch *algo {
	case "sha256", "sha1", "md5":
	default:
		return flagConfig{}, errors.New("invalid -algo value; must be 'sha256', 'sha1', or 'md5'")
	}

	if *hashListFile == "" && flag.NArg() < 1 {
		return flagConfig{}, errUsage
	}
	if *hashListFile != "" && flag.NArg() > 0 {
		return flagConfig{}, errors.New("-f cannot be combined with a positional argument")
	}

	if *workers < 0 {
		return flagConfig{}, errors.New("invalid -workers value; must be >= 0")
	}

	var arg string
	if flag.NArg() > 0 {
		arg = flag.Arg(0)
	}

	return flagConfig{
		freeMode:     *freeMode,
		rateLimit:    *rateLimit,
		output:       *output,
		noColor:      *noColor,
		noCache:      *noCache,
		noProgress:   *noProgress,
		refresh:      *refresh,
		cacheAge:     *cacheAge,
		recursive:    *recursive,
		workers:      *workers,
		algo:         *algo,
		hashListFile: *hashListFile,
		includes:     includes,
		excludes:     excludes,
		minSize:      minSize,
		maxSize:      maxSize,
		minSizeStr:   *minSizeStr,
		maxSizeStr:   *maxSizeStr,
		arg:          arg,
	}, nil
}

func initResources(flags flagConfig) (runnerpkg.AppConfig, error) {
	if flags.output == "json" || flags.noColor {
		color.NoColor = true
	}

	showProgress := flags.output == "text" && !flags.noProgress &&
		isatty.IsTerminal(os.Stderr.Fd())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	succeeded := false
	defer func() {
		if !succeeded {
			stop()
		}
	}()

	effectiveRate := flags.rateLimit
	if effectiveRate == 0 && flags.freeMode {
		effectiveRate = 4
	}

	var limiter *rate.Limiter
	if effectiveRate > 0 {
		limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(effectiveRate)), 1)
		fmt.Fprintf(os.Stderr, "Rate limiting: %d requests/min\n", effectiveRate)
	}

	w := flags.workers
	if w <= 0 {
		w = runtime.NumCPU()
	}

	var cache map[string]vtclient.CacheEntry
	var cachePath string
	if !flags.noCache {
		var err error
		cachePath, err = cachepkg.FilePath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			cache = make(map[string]vtclient.CacheEntry)
		} else {
			cache, err = cachepkg.Load[vtclient.CacheEntry](cachePath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			} else {
				vtclient.MigrateLegacyCacheKeys(cache)
			}
		}
	}
	if cache == nil {
		cache = make(map[string]vtclient.CacheEntry)
	}

	flushCache := func() {
		if !flags.noCache && cachePath != "" {
			if err := cachepkg.Save(cachePath, cache); err != nil {
				fmt.Fprintln(os.Stderr, "Warning: failed to save cache:", err)
			}
		}
	}

	client := &http.Client{Timeout: 15 * time.Second}
	apiKey := strings.TrimSpace(os.Getenv("VIRUSTOTAL_API_KEY"))
	if apiKey == "" {
		return runnerpkg.AppConfig{}, errors.New("VIRUSTOTAL_API_KEY is not set")
	}

	succeeded = true
	return runnerpkg.AppConfig{
		LookupCfg: vtclient.LookupConfig{
			VT: vtclient.Client{
				Ctx:        ctx,
				HTTPClient: client,
				APIKey:     apiKey,
				BaseURL:    testBaseURL,
				Limiter:    limiter,
			},
			Cache: vtclient.CacheConfig{
				Entries:    cache,
				Mu:         &sync.Mutex{},
				Refresh:    flags.refresh,
				MaxAgeDays: flags.cacheAge,
			},
			Output: flags.output,
			Algo:   flags.algo,
		},
		ScanCfg: filterpkg.Config{
			Recursive:  flags.recursive,
			Includes:   flags.includes,
			Excludes:   flags.excludes,
			MinSize:    flags.minSize,
			MaxSize:    flags.maxSize,
			MinSizeStr: flags.minSizeStr,
			MaxSizeStr: flags.maxSizeStr,
		},
		Arg:          flags.arg,
		HashListPath: flags.hashListFile,
		Workers:      w,
		ShowProgress: showProgress,
		FlushCache:   flushCache,
		Stop:         stop,
	}, nil
}

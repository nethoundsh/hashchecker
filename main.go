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
	"bufio"
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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/glaslos/tlsh"
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

// hashResult holds all hash digests computed from a single file read.
type hashResult struct {
	SHA256 string
	SHA1   string
	MD5    string
	TLSH   string
}

type fileResult struct {
	looked    bool // true if the file was successfully looked up
	found     bool // true if VirusTotal had a report
	malicious bool // true if any engine flagged as malicious
}

// fileJob represents a file to be processed by a worker.
type fileJob struct {
	index int
	path  string
}

// workerOutput holds rendered output for a single worker job.
type workerOutput struct {
	index  int
	label  string
	output []byte
	result fileResult
	err    error
}

type hashJob struct {
	index int
	hash  string
	algo  string
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
	hashListPath string
	workers      int
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

	if cfg.hashListPath != "" {
		return runHashList(cfg.hashListPath, cfg.lookupCfg, cfg.workers)
	}

	if ok, detectedAlgo := isHexHash(cfg.arg); ok {
		return runHash(cfg.arg, detectedAlgo, cfg.lookupCfg)
	}
	fi, err := os.Stat(cfg.arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if fi.IsDir() {
		return runDir(cfg.arg, cfg.lookupCfg, cfg.scanCfg, cfg.showProgress, cfg.workers)
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
	workers := flag.Int("workers", 0, "number of concurrent workers for directory and hash-list scans (0 = number of CPUs)")
	algo := flag.String("algo", "sha256", "hash algorithm for VirusTotal lookup: sha256, sha1, or md5")
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
		return appConfig{}, errors.New("invalid -o value; must be 'text' or 'json'")
	}

	switch *algo {
	case "sha256", "sha1", "md5":
	default:
		return appConfig{}, errors.New("invalid -algo value; must be 'sha256', 'sha1', or 'md5'")
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

	if *hashListFile == "" && flag.NArg() < 1 {
		return appConfig{}, errUsage
	}
	if *hashListFile != "" && flag.NArg() > 0 {
		return appConfig{}, errors.New("-f cannot be combined with a positional argument")
	}

	w := *workers
	if w < 0 {
		return appConfig{}, errors.New("invalid -workers value; must be >= 0")
	}
	if w <= 0 {
		w = runtime.NumCPU()
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
		return appConfig{}, errors.New("VIRUSTOTAL_API_KEY is not set")
	}

	var arg string
	if flag.NArg() > 0 {
		arg = flag.Arg(0)
	}

	succeeded = true
	return appConfig{
		lookupCfg: lookupConfig{
			vt: vtClient{
				ctx:     ctx,
				client:  client,
				apiKey:  apiKey,
				baseURL: os.Getenv("VIRUSTOTAL_BASE_URL"),
				limiter: limiter,
			},
			cache: cacheConfig{
				entries:    cache,
				mu:         &sync.Mutex{},
				refresh:    *refresh,
				maxAgeDays: *cacheAge,
			},
			output: *output,
			algo:   *algo,
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
		hashListPath: *hashListFile,
		workers:      w,
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
	if err := printLookupResult(os.Stdout, "", hash, cfg.output, cfg.algo, result, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if result.Found && result.Malicious > 0 {
		return 2
	}
	return 0
}

func processFileToOutput(path string, cfg lookupConfig) workerOutput {
	var buf bytes.Buffer
	if cfg.output == "text" {
		_, _ = fmt.Fprintln(&buf, color.HiBlueString("--- %s ---", path))
	}
	fi, err := os.Stat(path)
	if err != nil {
		return workerOutput{label: path, output: buf.Bytes(), err: err}
	}
	meta := newFileMeta(path, fi)

	hashes, err := hashFile(path)
	if err != nil {
		return workerOutput{label: path, output: buf.Bytes(), err: err}
	}
	hash := hashes.ForAlgo(cfg.algo)

	result, err := lookup(hash, cfg)
	if err != nil {
		return workerOutput{label: path, output: buf.Bytes(), err: err}
	}
	if err := printLookupResult(&buf, path, hash, cfg.output, cfg.algo, result, &hashes, meta); err != nil {
		return workerOutput{label: path, output: buf.Bytes(), err: err}
	}

	return workerOutput{
		label:  path,
		output: buf.Bytes(),
		result: fileResult{
			looked:    true,
			found:     result.Found,
			malicious: result.Found && result.Malicious > 0,
		},
	}
}

func processHashToOutput(job hashJob, cfg lookupConfig) workerOutput {
	var buf bytes.Buffer
	cfg.algo = job.algo

	result, err := lookup(job.hash, cfg)
	if err != nil {
		return workerOutput{index: job.index, label: job.hash, err: err}
	}
	if err := printLookupResult(&buf, "", job.hash, cfg.output, cfg.algo, result, nil, nil); err != nil {
		return workerOutput{index: job.index, label: job.hash, output: buf.Bytes(), err: err}
	}

	return workerOutput{
		index:  job.index,
		label:  job.hash,
		output: buf.Bytes(),
		result: fileResult{
			looked:    true,
			found:     result.Found,
			malicious: result.Found && result.Malicious > 0,
		},
	}
}

func handleConcurrentFileResult(out workerOutput, looked, found, malicious *int, bar *mpb.Bar, progress *mpb.Progress) {
	if len(out.output) > 0 {
		if progress != nil {
			_, _ = progress.Write(out.output)
		} else {
			_, _ = os.Stdout.Write(out.output)
		}
	}
	if out.err != nil {
		fmt.Fprintln(os.Stderr, "Error:", out.label, out.err)
	} else {
		if out.result.looked {
			*looked++
		}
		if out.result.found {
			*found++
		}
		if out.result.malicious {
			*malicious++
		}
	}
	if bar != nil {
		bar.Increment()
	}
}

func initProgressBar(ctx context.Context, total int64) (*mpb.Progress, *mpb.Bar) {
	p := mpb.NewWithContext(ctx, mpb.WithOutput(os.Stderr))
	b := p.New(total,
		mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding(" ").Rbound("]"),
		mpb.PrependDecorators(decor.Name("Scanning ")),
		mpb.AppendDecorators(
			decor.CountersNoUnit(" %d / %d "),
			decor.AverageETA(decor.ET_STYLE_MMSS),
		),
		mpb.BarRemoveOnComplete(),
	)
	return p, b
}

// runHashList reads hashes from a file (one per line) and looks each up.
// Blank lines and lines starting with # are skipped.
func runHashList(path string, cfg lookupConfig, workers int) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	defer func() { _ = f.Close() }()

	var looked, found, malicious int
	scanner := bufio.NewScanner(f)
	var jobs []hashJob

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ok, detectedAlgo := isHexHash(line)
		if !ok {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid hash: %s\n", line)
			continue
		}
		jobs = append(jobs, hashJob{
			index: len(jobs),
			hash:  strings.ToLower(line),
			algo:  detectedAlgo,
		})
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading hash list:", err)
		return 1
	}

	if workers > 1 && len(jobs) > 1 {
		jobCh := make(chan hashJob, workers)
		results := make(chan workerOutput, workers)

		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobCh {
					if cfg.vt.ctx.Err() != nil {
						return
					}
					out := processHashToOutput(job, cfg)
					select {
					case results <- out:
					case <-cfg.vt.ctx.Done():
						return
					}
				}
			}()
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			pending := make(map[int]workerOutput)
			next := 0
			for out := range results {
				pending[out.index] = out
				for {
					current, ok := pending[next]
					if !ok {
						break
					}
					delete(pending, next)
					handleConcurrentFileResult(current, &looked, &found, &malicious, nil, nil)
					next++
				}
			}
		}()

		interrupted := false
	sendJobs:
		for _, job := range jobs {
			select {
			case jobCh <- job:
			case <-cfg.vt.ctx.Done():
				interrupted = true
				break sendJobs
			}
		}
		close(jobCh)
		wg.Wait()
		close(results)
		<-done

		if interrupted {
			fmt.Fprintln(os.Stderr, "\nInterrupted")
			return 1
		}
	} else {
		for _, job := range jobs {
			if cfg.vt.ctx.Err() != nil {
				fmt.Fprintln(os.Stderr, "\nInterrupted")
				return 1
			}
			out := processHashToOutput(job, cfg)
			handleConcurrentFileResult(out, &looked, &found, &malicious, nil, nil)
		}
	}

	if cfg.output == "json" {
		if err := printJSONSummary(os.Stdout, path, looked, found, malicious); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return 1
		}
	} else {
		maliciousStr := color.GreenString("%d", malicious)
		if malicious > 0 {
			maliciousStr = color.RedString("%d", malicious)
		}
		hashWord := "hashes"
		if looked == 1 {
			hashWord = "hash"
		}
		_, _ = fmt.Fprintf(os.Stdout, "Checked %d %s, %d found in VirusTotal, %s malicious\n", looked, hashWord, found, maliciousStr)
	}

	if malicious > 0 {
		return 2
	}
	return 0
}

// runDir walks a directory, hashes each matching file, and looks it up.
// With showProgress, files are collected first to get a total for the bar.
// Without showProgress, worker mode streams files lazily from WalkDir.
func runDir(arg string, cfg lookupConfig, sc scanConfig, showProgress bool, workers int) int {
	var looked, found, malicious int
	var progress *mpb.Progress
	var bar *mpb.Bar

	var err error
	if workers > 1 {
		var files []string
		if showProgress {
			var collectErr error
			files, collectErr = collectMatchingFiles(arg, sc)
			if collectErr != nil {
				fmt.Fprintln(os.Stderr, "Warning: could not collect files:", collectErr)
			}
			if len(files) > 0 {
				progress, bar = initProgressBar(cfg.vt.ctx, int64(len(files)))
			}
		}

		jobs := make(chan fileJob, workers)
		results := make(chan workerOutput, workers)

		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					if cfg.vt.ctx.Err() != nil {
						return
					}
					out := processFileToOutput(job.path, cfg)
					out.index = job.index
					select {
					case results <- out:
					case <-cfg.vt.ctx.Done():
						return
					}
				}
			}()
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			pending := make(map[int]workerOutput)
			nextIndex := 0
			for out := range results {
				pending[out.index] = out
				for {
					current, ok := pending[nextIndex]
					if !ok {
						break
					}
					delete(pending, nextIndex)
					handleConcurrentFileResult(current, &looked, &found, &malicious, bar, progress)
					nextIndex++
				}
			}
		}()

		if showProgress {
		sendCollectedJobs:
			for i, path := range files {
				select {
				case jobs <- fileJob{index: i, path: path}:
				case <-cfg.vt.ctx.Done():
					err = cfg.vt.ctx.Err()
					break sendCollectedJobs
				}
			}
		} else {
			nextIndex := 0
			err = walkMatchingFiles(arg, sc, func(path string, _ fs.DirEntry) error {
				if cfg.vt.ctx.Err() != nil {
					return cfg.vt.ctx.Err()
				}
				select {
				case jobs <- fileJob{index: nextIndex, path: path}:
					nextIndex++
					return nil
				case <-cfg.vt.ctx.Done():
					return cfg.vt.ctx.Err()
				}
			})
		}

		close(jobs)
		wg.Wait()
		close(results)
		<-done
	} else if showProgress {
		files, collectErr := collectMatchingFiles(arg, sc)
		if collectErr != nil {
			fmt.Fprintln(os.Stderr, "Warning: could not collect files:", collectErr)
		}
		if len(files) > 0 {
			progress, bar = initProgressBar(cfg.vt.ctx, int64(len(files)))
		}
		for _, path := range files {
			if cfg.vt.ctx.Err() != nil {
				err = cfg.vt.ctx.Err()
				break
			}
			out := processFileToOutput(path, cfg)
			handleConcurrentFileResult(out, &looked, &found, &malicious, bar, progress)
		}
	} else {
		err = walkMatchingFiles(arg, sc, func(path string, _ fs.DirEntry) error {
			if cfg.vt.ctx.Err() != nil {
				return cfg.vt.ctx.Err()
			}
			out := processFileToOutput(path, cfg)
			handleConcurrentFileResult(out, &looked, &found, &malicious, nil, nil)
			return nil
		})
	}

	if progress != nil {
		progress.Wait()
	}

	if err != nil {
		if cfg.vt.ctx.Err() != nil {
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
	if err := printLookupResult(os.Stdout, arg, hash, cfg.output, cfg.algo, result, &hashes, newFileMeta(arg, fi)); err != nil {
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

// hashFile computes SHA-256, SHA-1, MD5, and TLSH of filePath in a single pass.
// Disk I/O dominates, so computing all four costs essentially the same as one.
// TLSH requires >=256 bytes of diverse content; smaller/uniform files get TLSH="".
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
	hTLSH := tlsh.New()
	var totalBytes int64
	tlshEnabled := true
	buf := make([]byte, 32*1024)
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			totalBytes += int64(n)
			if _, err := h256.Write(chunk); err != nil {
				return hashResult{}, fmt.Errorf("hashing %s: %w", filePath, err)
			}
			if _, err := h1.Write(chunk); err != nil {
				return hashResult{}, fmt.Errorf("hashing %s: %w", filePath, err)
			}
			if _, err := hMD5.Write(chunk); err != nil {
				return hashResult{}, fmt.Errorf("hashing %s: %w", filePath, err)
			}
			if tlshEnabled {
				wrote, tlshErr := hTLSH.Write(chunk)
				if tlshErr != nil {
					// TLSH can fail on some input; keep cryptographic hashes regardless.
					tlshEnabled = false
				}
				_ = wrote // TLSH may report partial writes; best-effort collection is fine.
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return hashResult{}, fmt.Errorf("hashing %s: %w", filePath, readErr)
		}
	}

	// TLSH is only valid for sufficiently large, diverse content.
	var tlshValue string
	if tlshEnabled && totalBytes >= 256 {
		_ = hTLSH.Sum(nil)
		tlshValue = func() (value string) {
			defer func() {
				if recover() != nil {
					value = ""
				}
			}()
			return hTLSH.String()
		}()
		if strings.Trim(tlshValue, "0") == "" {
			tlshValue = ""
		}
	}

	return hashResult{
		SHA256: hex.EncodeToString(h256.Sum(nil)),
		SHA1:   hex.EncodeToString(h1.Sum(nil)),
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		TLSH:   tlshValue,
	}, nil
}

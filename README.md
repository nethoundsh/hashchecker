# hashchecker

A command-line tool that computes file hashes and checks them against the [VirusTotal](https://www.virustotal.com/) API. Computes SHA-256, SHA-1, MD5, and [TLSH](https://tlsh.org/) (locality-sensitive fuzzy hash) in a single pass. Scan a single file, look up a known hash, or sweep an entire directory — with colored terminal output, file filtering, and machine-readable JSON.

## Features

- **Multi-hash support** — SHA-256 (default), SHA-1, MD5, and TLSH computed in a single pass. The `-algo` flag selects which cryptographic hash is sent to VirusTotal. Files are streamed so even large files are hashed without loading them entirely into memory.
- **TLSH (fuzzy hashing)** — every file scan also computes a [TLSH](https://tlsh.org/) locality-sensitive hash. Unlike cryptographic hashes, similar files produce similar TLSH values, making it useful for malware family clustering and similarity analysis. TLSH requires at least 256 bytes of diverse content; smaller or uniform files omit the TLSH line. TLSH is informational only and is not sent to VirusTotal.
- **VirusTotal lookup** — queries the VirusTotal v3 API and reports malicious/suspicious/undetected/harmless engine counts, reputation score, and threat classification. The API natively accepts SHA-256, SHA-1, and MD5 hashes.
- **Direct hash lookup** — pass a hex hash string instead of a file path to look up a hash you already have (64 chars for SHA-256, 40 for SHA-1, 32 for MD5).
- **Bulk hash-list input** — use `-f hashes.txt` to check a list of IOCs (one hash per line). Supports `#` comments and mixed hash types (SHA-256, SHA-1, MD5) in the same file — each hash's algorithm is auto-detected from its length.
- **Directory scanning** — point it at a directory to scan all regular files (symlinks are skipped). Use `-r` for recursive scanning with automatic skipping of common non-essential directories (`.git`, `node_modules`, `__pycache__`, `vendor`, etc.). A bottom-anchored progress bar shows file count and ETA while per-file results scroll above it.
- **Concurrent processing** — directory and hash-list scans use a bounded worker pool (default: one worker per CPU). Workers hash files and query VirusTotal in parallel while output order remains deterministic. The rate limiter is shared across all workers, so API pacing is always respected.
- **Progress bar** — directory scans display a bottom-anchored progress bar on stderr with file count and ETA. Per-file results scroll above the bar so it always stays at the bottom of the terminal. Automatically suppressed in JSON mode, when stderr is not a TTY (piped/redirected), or when `-no-progress` is passed.
- **File filtering** — narrow which files get scanned with glob patterns (`-include`, `-exclude`) and size limits (`-min-size`, `-max-size`). Filters are applied before hashing, so excluded files don't waste CPU or API quota.
- **Rate limiting** — the `-free` flag enforces VirusTotal's free-tier limit (4 requests/minute), or use `-rate N` for custom pacing. Uses a token-bucket limiter with random jitter to avoid bot detection.
- **Colored output** — malicious results in red, suspicious in yellow, clean in green. Disable with `-no-color` or the `NO_COLOR` environment variable.
- **JSON output** — use `-o json` for NDJSON (one JSON object per line), suitable for piping into `jq` or other tools.
- **Result caching** — caches VirusTotal results locally (`~/.cache/hashchecker/results.json`) to avoid redundant API calls. Cached results expire after 7 days by default. Control with `-no-cache`, `-refresh`, and `-cache-age`. Cache writes are atomic (write to temp file, then rename) to prevent corruption.
- **Graceful cancellation** — press Ctrl+C to cleanly interrupt long-running scans. In-flight rate-limit waits, HTTP requests, and directory walks exit immediately, and the cache is flushed before shutdown.
- **Contextual error messages** — every error is wrapped with `fmt.Errorf("context: %w", err)` so messages tell you *what operation* failed and *which file or hash* was involved (e.g. `"hashing /tmp/foo: permission denied"` instead of a bare `"permission denied"`). Error chains are preserved via `%w`, so `errors.Is` and `errors.As` still work for programmatic error inspection.
- **File metadata** — every file scan displays metadata (name, size, modified/created timestamps, permissions) before the hash lines. Created time uses platform-native APIs (`statx` on Linux, `Birthtime` on macOS/Windows) and is omitted when unavailable. Metadata is included in both text and JSON output.
- **Scriptable exit codes** — exit 0 for clean, 1 for errors, 2 when malicious files are detected.

## Use Cases

- **SOC Triage** — When your security operations center receives an alert, analysts can instantly check whether a suspicious file is known malware by scanning it against 70+ antivirus engines via VirusTotal. Batch-scan an entire quarantine folder in one command and get a clear malicious/clean verdict for each file, cutting triage time from minutes to seconds.

- **Ransomware Recovery** — During incident response, quickly assess which files on a compromised system are known malicious. Sweep entire directories recursively to identify the ransomware payload, its droppers, and any other known threats — helping your IR team determine scope of compromise and prioritize remediation.

- **Supply Chain Verification** — Before deploying third-party binaries, scripts, or vendor-provided software into production, verify that no component is flagged by any of VirusTotal's detection engines. Integrate into your deployment pipeline with JSON output and scriptable exit codes (exit 2 = malicious detected).

- **Threat Hunting** — Proactively scan file servers, shared drives, or developer workstations for known indicators of compromise (IOCs). Use file filtering to focus on high-risk file types (executables, DLLs, scripts) and size ranges that match known threat profiles. Bulk-check IOC hash lists from threat intelligence feeds with `-f iocs.txt`.

- **Compliance & Audit** — Generate machine-readable JSON reports of file integrity checks across critical systems. The NDJSON output integrates directly with SIEM platforms, log aggregators, and compliance reporting tools.

## Prerequisites

- A **VirusTotal API key** — sign up for a free account at [virustotal.com](https://www.virustotal.com/) and copy your API key from the API section of your profile.

## Installation

### Pre-built binaries (recommended)

Download the latest release for your platform from the [Releases page](https://github.com/nethoundsh/hashchecker/releases). Binaries are available for Linux, macOS, and Windows on both amd64 and arm64. Each release includes a `checksums.txt` for integrity verification.

```bash
# Example: Linux amd64
curl -LO https://github.com/nethoundsh/hashchecker/releases/latest/download/hashchecker_linux_amd64.tar.gz
tar xzf hashchecker_linux_amd64.tar.gz
sudo mv hashchecker /usr/local/bin/
```

Verify the download:

```bash
hashchecker -version
```

### Build from source

Requires **Go 1.25.7+**:

```bash
go install github.com/nethoundsh/hashchecker@latest
```

Or clone and build manually:

```bash
git clone https://github.com/nethoundsh/hashchecker.git
cd hashchecker
go build -o hashchecker .
```

## Configuration

Set your VirusTotal API key as an environment variable:

**Linux/macOS:**

```bash
export VIRUSTOTAL_API_KEY="your-api-key-here"
```

Add this to your `~/.bashrc`, `~/.zshrc`, or equivalent to persist it across sessions.

**Windows (Command Prompt):**

```cmd
set VIRUSTOTAL_API_KEY=your-api-key-here
```

To persist across sessions, use `setx` instead of `set`.

**Windows (PowerShell):**

```powershell
$env:VIRUSTOTAL_API_KEY="your-api-key-here"
```

To persist, add this to your PowerShell profile (`$PROFILE`).

## Usage

```
hashchecker [flags] <file | hash | directory | -f hashlist>
```

### Flags

| Flag | Description |
|------|-------------|
| `-algo sha256\|sha1\|md5` | Hash algorithm to use. Default: `sha256` |
| `-free` | Rate-limit API requests to 4/minute (VirusTotal free tier) |
| `-rate N` | Custom rate limit: max N API requests per minute (overrides `-free`) |
| `-r` | Recursively scan subdirectories (skips `.git`, `node_modules`, `__pycache__`, `vendor`, `.venv`, `.idea`, `.vscode`) |
| `-o text\|json` | Output format. Default: `text`. Use `json` for NDJSON output |
| `-no-color` | Disable colored terminal output |
| `-no-progress` | Disable progress bar for directory scans |
| `-no-cache` | Disable cache entirely (don't read or write) |
| `-refresh` | Ignore cached results but still write new ones |
| `-cache-age N` | Maximum age of cached results in days (default: 7) |
| `-include PATTERNS` | Comma-separated glob patterns — only process matching files (e.g. `"*.exe,*.dll"`) |
| `-exclude PATTERNS` | Comma-separated glob patterns — skip matching files (e.g. `"*.tmp,*.log"`) |
| `-min-size SIZE` | Minimum file size with units (e.g. `"1KB"`, `"10MB"`) |
| `-max-size SIZE` | Maximum file size with units (e.g. `"100MB"`, `"1GB"`) |
| `-version` | Print version and exit |
| `-f PATH` | Read hashes from a file (one hash per line) and look up each one |
| `-workers N` | Number of concurrent workers for directory and hash-list scans (default: CPU count) |

### Scan a single file

```bash
hashchecker /path/to/suspicious-file.exe
```

```
  File:         suspicious-file.exe
  Size:         145 kB
  Modified:     2026-01-15 09:23:41 UTC
  Created:      2026-01-10 14:05:12 UTC
  Permissions:  -rwxr-xr-x

* SHA-256:      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  SHA-1:        da39a3ee5e6b4b0d3255bfef95601890afd80709
  MD5:          d41d8cd98f00b204e9800998ecf8427e
  TLSH:         T1A12F0E8546A28B5E9734F0400B1F84E82F5D9EF3C47A951441048B50D9DAA44D0B8A1

Name:           suspicious-file.exe
Reputation:     -47

Malicious:      52
Suspicious:     0
Undetected:     12
Harmless:       0

Threat:         trojan.generic/agent
```

The `*` marks the hash used for the VirusTotal lookup (SHA-256 by default). All four hashes are computed in a single pass. The TLSH line is omitted for files smaller than 256 bytes.

### Look up a known hash

```bash
hashchecker 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Bulk Hash Checking

Check a list of IOCs from a file (one hash per line):

```bash
hashchecker -f iocs.txt -free
```

The file supports comments (`#`) and mixed hash types (SHA-256, SHA-1, MD5):

```text
# Emotet samples - 2024-01
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
da39a3ee5e6b4b0d3255bfef95601890afd80709
d41d8cd98f00b204e9800998ecf8427e
```

Filter JSON output for malicious hits:

```bash
hashchecker -f iocs.txt -o json | jq 'select(.result.malicious > 0)'
```

### Use a different hash algorithm

```bash
# Hash a file with SHA-1
hashchecker -algo sha1 /path/to/file.exe

# Look up an MD5 hash directly
hashchecker -algo md5 d41d8cd98f00b204e9800998ecf8427e

# Scan a directory using SHA-1
hashchecker -algo sha1 -r ~/Downloads
```

### Scan a directory

```bash
hashchecker -free ~/Downloads
```

Scans every regular file in the directory (non-recursive by default). With `-free`, requests are paced at 4 per minute using a token-bucket limiter. A bottom-anchored progress bar on stderr shows scan progress and ETA while per-file results scroll above it.

To disable the progress bar:

```bash
hashchecker -free -no-progress ~/Downloads
```

### Recursive scan

```bash
hashchecker -r -free ~/projects
```

Walks the entire directory tree, automatically skipping `.git`, `node_modules`, `__pycache__`, `vendor`, `.venv`, `.idea`, and `.vscode`.

### File filtering

Filter which files get scanned using glob patterns and size limits. Filters are applied **before hashing**, so excluded files don't consume CPU or API quota.

**Only scan executables and DLLs:**

```bash
hashchecker -r -include "*.exe,*.dll" -free ~/Downloads
```

**Skip log and temp files:**

```bash
hashchecker -r -exclude "*.log,*.tmp" -free ~/Downloads
```

**Only scan files between 1 KB and 100 MB:**

```bash
hashchecker -r -min-size 1KB -max-size 100MB -free ~/Downloads
```

**Combine filters — executables over 10 KB, skip anything named `*.test.exe`:**

```bash
hashchecker -r -include "*.exe" -exclude "*.test.exe" -min-size 10KB -free ~/Downloads
```

Size units supported: `B`, `KB`, `MB`, `GB`, `TB` (parsed by [go-humanize](https://github.com/dustin/go-humanize)).

> **Note:** For single-file scans, glob filters (`-include`/`-exclude`) are not applied since you explicitly named the file. Size filters (`-min-size`/`-max-size`) still apply.

### Custom rate limiting

```bash
# VirusTotal free tier (4 req/min)
hashchecker -free -r ~/Downloads

# Custom rate: 10 requests per minute
hashchecker -rate 10 -r ~/Downloads

# -rate overrides -free if both are set
hashchecker -free -rate 10 -r ~/Downloads  # uses 10 req/min
```

### Concurrent Scanning

Directory and hash-list scans use a worker pool to process entries in parallel. By default, worker count matches your CPU count.

```bash
hashchecker -r -workers 8 /path/to/directory
hashchecker -f iocs.txt -workers 8
```

Output order remains deterministic (input order), regardless of worker count.

The rate limiter still applies globally. For example, `-free -workers 8` still allows at most 4 API requests per minute. Cache hits bypass the rate limiter, so concurrency helps most when many lookups are already cached.

### JSON output

```bash
hashchecker -o json /path/to/file
```

Each result is a single NDJSON line containing all computed hashes, the lookup hash/algorithm, and the full VirusTotal result:

```json
{"path":"/path/to/file","file":{"name":"file.exe","size":145408,"size_human":"145 kB","modified":"2026-01-15T09:23:41Z","created":"2026-01-10T14:05:12Z","permissions":"-rwxr-xr-x"},"hashes":{"sha256":"e3b0c44...","sha1":"da39a3e...","md5":"d41d8cd...","tlsh":"T1A12F0..."},"lookup_hash":"e3b0c44...","lookup_algorithm":"sha256","result":{"found":true,"name":"file.exe","reputation":-47,"malicious":52,"suspicious":0,"undetected":12,"harmless":0,"threat_label":"trojan.generic/agent"}}
```

The `file` object contains name, size (bytes and human-readable), timestamps, and permissions. The `created` field is omitted when the platform cannot determine birth time. The `tlsh` field is omitted when the file is too small (<256 bytes) or has insufficient byte diversity.

For raw hash lookups, only the matched algorithm appears in `hashes` and `path` is omitted:

```json
{"hashes":{"sha256":"e3b0c44..."},"lookup_hash":"e3b0c44...","lookup_algorithm":"sha256","result":{"found":true,"name":"file.exe","reputation":-47,"malicious":52,...}}
```

For directory scans, each file produces one JSON line followed by a summary line:

```json
{"path":"/path/to/file1","file":{"name":"file1","size":2048,"size_human":"2.0 kB","modified":"2026-01-15T09:23:41Z","permissions":"-rw-r--r--"},"hashes":{"sha256":"abc...","sha1":"def...","md5":"012...","tlsh":"T1A12..."},"lookup_hash":"abc...","lookup_algorithm":"sha256","result":{...}}
{"path":"/path/to/file2","file":{"name":"file2","size":8192,"size_human":"8.2 kB","modified":"2026-02-01T12:00:00Z","permissions":"-rwxr-xr-x"},"hashes":{"sha256":"fed...","sha1":"cba...","md5":"987...","tlsh":"T1B34..."},"lookup_hash":"fed...","lookup_algorithm":"sha256","result":{...}}
{"summary":{"path":"/path/to/dir","scanned":2,"found":2,"malicious":1}}
```

Pipe into `jq` for filtering:

```bash
hashchecker -o json ~/Downloads | jq 'select(.result.malicious > 0)'
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All scanned files are clean (or not found in VirusTotal) |
| `1` | An error occurred (missing API key, network failure, file not found, etc.) |
| `2` | One or more files were flagged as malicious |

Use in scripts:

```bash
hashchecker /path/to/file
if [ $? -eq 2 ]; then
    echo "Malicious file detected!"
fi
```

## Testing with EICAR

The [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) is a safe, standardized test string that every antivirus engine flags as malicious. Its SHA-256 hash is:

```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

Use it to verify hashchecker is working:

```bash
hashchecker 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

## Caching

Results are cached locally to reduce API calls. The cache file is stored at:

- **Linux:** `~/.cache/hashchecker/results.json`
- **macOS:** `~/Library/Caches/hashchecker/results.json`
- **Windows:** `%LocalAppData%\hashchecker\results.json`

Cache writes are atomic — data is written to a temporary file first, then renamed into place. This prevents a crash mid-write from corrupting your cache.

By default, cached results are valid for 7 days. To force a fresh lookup:

```bash
hashchecker -refresh /path/to/file
```

To disable caching entirely:

```bash
hashchecker -no-cache /path/to/file
```

To change the cache expiry (e.g., 1 day):

```bash
hashchecker -cache-age 1 /path/to/file
```

## Error handling

All errors are wrapped with contextual information using Go's `fmt.Errorf("context: %w", err)` pattern. This means:

1. **Every error message tells you what went wrong and where.** Instead of a bare `permission denied`, you'll see `hashing /tmp/foo: permission denied` or `opening cache /home/user/.cache/hashchecker/results.json: permission denied`.

2. **The error chain is preserved.** The `%w` verb (not `%v`) ensures that `errors.Is(err, os.ErrPermission)` still works on wrapped errors, so programmatic error handling remains reliable.

3. **No double-wrapping.** Each function adds only the context it owns. For example, `checkVirusTotal` adds the hash (`"checking virustotal abc123: ..."`), so its caller `lookup` does not re-wrap with the same hash.

Example error messages:

```
Error: hashing /tmp/secret.bin: open /tmp/secret.bin: permission denied
Error: checking virustotal abc123...: unexpected status: 403: {"error": ...}
Error: checking virustotal abc123...: rate limited after 3 retries
Error: locating cache directory: $HOME is not defined
Error: writing cache: write /tmp/results.json.tmp: no space left on device
```

## Project structure

```
hashchecker/
  main.go                          Entry point, parseConfig(), run() dispatch, worker pool, helpers (runHash, runDir, runFile, runHashList), hashing
  virustotal.go                    VirusTotal API client, lookup(), result types, rate limiting, retry logic
  output.go                        Text and JSON output formatting, printLookupResult(), color helpers
  filestats.go                     File metadata: fileMeta struct, newFileMeta(), JSON serialization
  birthtime_linux.go               Linux birth time via statx() (build-tagged)
  birthtime_darwin.go              macOS birth time via Birthtime (build-tagged)
  birthtime_windows.go             Windows birth time via CreationTime (build-tagged)
  birthtime_other.go               Fallback (zero time) for unsupported platforms
  cache.go                         Disk cache: load, save (atomic), expiry
  filter.go                        File filtering by glob pattern and size
  main_test.go                     Tests for run(), hashing, filters, hash-list input, concurrency, retry parsing, file metadata
  virustotal_test.go               httptest integration tests for API client, caching, rate limiting
  output_test.go                   Output formatting, file metadata rendering, and color helper tests
  cache_test.go                    Filesystem tests for cache load/save/round-trip
  testhelpers_test.go              Shared test utilities (stdout capture)
  go.mod                           Module definition and dependencies
  .golangci.yml                    Linter configuration (golangci-lint v2)
  .goreleaser.yml                  Cross-platform release build configuration
  .github/workflows/ci.yml        GitHub Actions CI: golangci-lint + tests on push/PR
  .github/workflows/release.yml   Automated releases: builds binaries + checksums on tag push
  LICENSE                          MIT license
```

## CI / CD

Every push to `main` and every pull request runs two GitHub Actions jobs automatically:

| Job | What it does |
|-----|--------------|
| **Lint** | Runs [golangci-lint v2](https://golangci-lint.run/) with errcheck, govet, staticcheck, gosec, errorlint, and bodyclose |
| **Test** | Runs `go build`, `go vet`, and `go test -race -cover` to catch regressions and data races |

Pushing a version tag (e.g. `v1.2.0`) triggers an automated release via [GoReleaser](https://goreleaser.com/):

| Job | What it does |
|-----|--------------|
| **Release** | Builds cross-platform binaries (Linux, macOS, Windows — amd64 and arm64), generates SHA-256 checksums, and publishes a GitHub Release with all assets attached |

Workflows are defined in [`.github/workflows/`](.github/workflows/). The Go version is read from `go.mod` so it stays in sync automatically.

## Running tests

```bash
go test ./...
```

The test suite has **127 tests** (including subtests) across 4 test files with **~84% statement coverage**.

**`main_test.go`** — Core logic and end-to-end `run()` tests:
- **`TestIsHexHash`** — hash detection for all algorithms (SHA-256 valid/invalid, SHA-1 valid/cross-rejection, MD5 valid/cross-rejection, unsupported algorithm)
- **`TestHashFile`** — file hashing across algorithms (SHA-256, SHA-1, MD5 known content, unsupported algo error, nonexistent file error)
- **`TestNewFileMeta`** — file metadata extraction (name, size, human-readable size, modified/created timestamps in UTC, permissions)
- **`TestTruncateRunes`** — string truncation with multi-byte character safety
- **`TestParseRetryAfter`** — Retry-After header parsing (integers, zero, negative, garbage, RFC 1123 dates)
- **`TestShouldProcess`** — file filter logic (include/exclude globs, size bounds, combined filters)
- **`TestRun*`** — end-to-end tests for `run()`: flag validation (version, no args, missing API key, invalid output/patterns/sizes/algo/workers), hash lookups (clean, malicious, MD5), single file scanning (default SHA-256, SHA-1, size filters), directory scanning (flat, recursive, JSON, include/exclude)
- **`TestRunHashListMode`** — hash-list file input (`-f`): happy path with multiple hashes, malicious exit code 2, mixed algorithm auto-detection (SHA-256/SHA-1/MD5 in one file), comment and blank line skipping, invalid hash warnings, empty file handling, mutual exclusivity with positional args, missing file error
- **`TestRunDirectoryConcurrent*`** — concurrent worker pool: basic multi-worker scan, deterministic output ordering with 10 files and 4 workers, malicious exit code propagation, workers=1 matches workers=4 output
- **`TestRunHashListConcurrent`** — concurrent hash-list processing with 3 workers
- **`TestRunConcurrentInterrupt`** — graceful shutdown under pre-cancelled context with worker pool

**`virustotal_test.go`** — httptest-based integration tests:
- **`TestCheckVirusTotal`** — HTTP client against a mock server (200 success, clean file, 404 not found, 429 retry, 429 exhausted, 403 bad key, bad JSON, context cancellation)
- **`TestCheckVirusTotalSendsAPIKey`** — verifies API key header is sent
- **`TestLookup`** — cache + API integration (cache miss, cache hit, expired cache, refresh bypass)
- **`TestWaitForRateLimit`** — rate limiter (nil limiter, fast limiter, cancelled context)

**`output_test.go`** — Output formatting:
- **`TestPrintJSON`** / **`TestPrintJSONSummary`** — JSON output structure, `omitempty` behavior, file metadata presence and created-time omission when zero
- **`TestPrintResult`** — human-readable output (found with details, file metadata labels, not found message)
- **`TestColorHelpers`** — ANSI color selection for reputation, malicious, and suspicious counts

**`cache_test.go`** — Filesystem operations:
- **`TestLoadCache`** — missing file, valid file, corrupt JSON graceful degradation
- **`TestLoadCacheMigratesLegacyKeys`** — verifies bare-hash keys are migrated to `sha256:hash` format
- **`TestSaveCache`** — file permissions (0600), JSON validity, save-then-load round-trip
- **`TestGetCacheFilePath`** — path suffix verification

Check coverage:

```bash
go test -cover ./...
```

## Security considerations

- **API key handling** — the key is read from an environment variable, never from command-line flags (which are visible in `ps` output and shell history).
- **Read-only** — hashchecker only reads files and makes GET requests. It never modifies files or uploads content.
- **Symlink safety** — directory scans skip symlinks, preventing path traversal or infinite-read attacks (e.g., a symlink to `/dev/zero`).
- **Input validation** — hash arguments are validated as valid hex before being used in API URLs. Glob patterns are validated at startup before scanning begins.
- **Cache permissions** — the cache directory is created with `0700` and the cache file with `0600` (owner-only access).
- **Atomic cache writes** — cache is written to a temporary file and renamed into place, preventing corruption from crashes or interrupted writes.

## Dependencies

| Package | Purpose |
|---------|---------|
| [`github.com/dustin/go-humanize`](https://github.com/dustin/go-humanize) | Parse human-readable file sizes (`"10MB"` to bytes) |
| [`github.com/fatih/color`](https://github.com/fatih/color) | ANSI-colored terminal output |
| [`github.com/mattn/go-isatty`](https://github.com/mattn/go-isatty) | Detect whether a file descriptor is a terminal (TTY) |
| [`github.com/vbauerster/mpb/v8`](https://github.com/vbauerster/mpb) | Bottom-anchored terminal progress bar with ETA display |
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | Platform-native syscalls for file birth time (`statx` on Linux) |
| [`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate) | Token-bucket rate limiter for API call pacing |
| [`github.com/glaslos/tlsh`](https://github.com/glaslos/tlsh) | TLSH locality-sensitive fuzzy hashing |

## License

MIT

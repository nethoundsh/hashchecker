# hashchecker

A command-line tool that computes SHA-256 hashes of files and checks them against the [VirusTotal](https://www.virustotal.com/) API. Scan a single file, look up a known hash, or sweep an entire directory — with colored terminal output, file filtering, and machine-readable JSON.

## Features

- **SHA-256 hashing** — streams files through `crypto/sha256` so even large files are hashed without loading them entirely into memory.
- **VirusTotal lookup** — queries the VirusTotal v3 API and reports malicious/suspicious/undetected/harmless engine counts, reputation score, and threat classification.
- **Direct hash lookup** — pass a 64-character hex string instead of a file path to look up a hash you already have.
- **Directory scanning** — point it at a directory to scan all regular files (symlinks are skipped). Use `-r` for recursive scanning with automatic skipping of common non-essential directories (`.git`, `node_modules`, `__pycache__`, `vendor`, etc.).
- **File filtering** — narrow which files get scanned with glob patterns (`-include`, `-exclude`) and size limits (`-min-size`, `-max-size`). Filters are applied before hashing, so excluded files don't waste CPU or API quota.
- **Rate limiting** — the `-free` flag enforces VirusTotal's free-tier limit (4 requests/minute), or use `-rate N` for custom pacing. Uses a token-bucket limiter with random jitter to avoid bot detection.
- **Colored output** — malicious results in red, suspicious in yellow, clean in green. Disable with `-no-color` or the `NO_COLOR` environment variable.
- **JSON output** — use `-o json` for NDJSON (one JSON object per line), suitable for piping into `jq` or other tools.
- **Result caching** — caches VirusTotal results locally (`~/.cache/hashchecker/results.json`) to avoid redundant API calls. Cached results expire after 7 days by default. Control with `-no-cache`, `-refresh`, and `-cache-age`. Cache writes are atomic (write to temp file, then rename) to prevent corruption.
- **Graceful cancellation** — press Ctrl+C to cleanly interrupt long-running scans. In-flight rate-limit waits, HTTP requests, and directory walks exit immediately, and the cache is flushed before shutdown.
- **Contextual error messages** — every error is wrapped with `fmt.Errorf("context: %w", err)` so messages tell you *what operation* failed and *which file or hash* was involved (e.g. `"hashing /tmp/foo: permission denied"` instead of a bare `"permission denied"`). Error chains are preserved via `%w`, so `errors.Is` and `errors.As` still work for programmatic error inspection.
- **Scriptable exit codes** — exit 0 for clean, 1 for errors, 2 when malicious files are detected.

## Prerequisites

- **Go 1.25.7+** (or any recent Go toolchain)
- A **VirusTotal API key** — sign up for a free account at [virustotal.com](https://www.virustotal.com/) and copy your API key from the API section of your profile.

## Installation

```bash
git clone https://github.com/nethoundsh/hashchecker.git
cd hashchecker
go build -o hashchecker .
```

Or install directly:

```bash
go install github.com/nethoundsh/hashchecker@latest
```

### Build with version info

Embed a version string at build time using `-ldflags`:

```bash
go build -ldflags "-X main.version=v1.0.0" -o hashchecker .
```

Then check it with:

```bash
hashchecker -version
# hashchecker v1.0.0
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
hashchecker [flags] <file | SHA-256 hash | directory>
```

### Flags

| Flag | Description |
|------|-------------|
| `-free` | Rate-limit API requests to 4/minute (VirusTotal free tier) |
| `-rate N` | Custom rate limit: max N API requests per minute (overrides `-free`) |
| `-r` | Recursively scan subdirectories (skips `.git`, `node_modules`, `__pycache__`, `vendor`, `.venv`, `.idea`, `.vscode`) |
| `-o text\|json` | Output format. Default: `text`. Use `json` for NDJSON output |
| `-no-color` | Disable colored terminal output |
| `-no-cache` | Disable cache entirely (don't read or write) |
| `-refresh` | Ignore cached results but still write new ones |
| `-cache-age N` | Maximum age of cached results in days (default: 7) |
| `-include PATTERNS` | Comma-separated glob patterns — only process matching files (e.g. `"*.exe,*.dll"`) |
| `-exclude PATTERNS` | Comma-separated glob patterns — skip matching files (e.g. `"*.tmp,*.log"`) |
| `-min-size SIZE` | Minimum file size with units (e.g. `"1KB"`, `"10MB"`) |
| `-max-size SIZE` | Maximum file size with units (e.g. `"100MB"`, `"1GB"`) |
| `-version` | Print version and exit |

### Scan a single file

```bash
hashchecker /path/to/suspicious-file.exe
```

```
Hash:       e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Name:       suspicious-file.exe
Reputation: -47
Malicious:  52
Suspicious: 0
Undetected: 12
Harmless:   0
Threat:     trojan.generic/agent
```

### Look up a known hash

```bash
hashchecker 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Scan a directory

```bash
hashchecker -free ~/Downloads
```

Scans every regular file in the directory (non-recursive by default). With `-free`, requests are paced at 4 per minute using a token-bucket limiter.

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

### JSON output

```bash
hashchecker -o json /path/to/file
```

```json
{"hash":"e3b0c44...","result":{"found":true,"name":"file.exe","reputation":-47,"malicious":52,"suspicious":0,"undetected":12,"harmless":0,"threat_label":"trojan.generic/agent"}}
```

For directory scans, each file produces one JSON line followed by a summary line:

```json
{"path":"/path/to/file1","hash":"abc123...","result":{...}}
{"path":"/path/to/file2","hash":"def456...","result":{...}}
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

3. **No double-wrapping.** Each function adds only the context it owns. For example, `checkVirusTotal` adds the hash (`"checking virustotal abc123: ..."`), so its caller `lookupAndPrint` does not re-wrap with the same hash.

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
  main.go              Entry point, CLI flags, run() setup, dispatch helpers (runHash, runDir, runFile), hashing
  virustotal.go        VirusTotal API client, result types, rate limiting, retry logic
  output.go            Text and JSON output formatting, color helpers
  cache.go             Disk cache: load, save (atomic), expiry
  filter.go            File filtering by glob pattern and size
  main_test.go         Tests for run(), hashing, filters, retry parsing
  virustotal_test.go   httptest integration tests for API client, caching, rate limiting
  output_test.go       Output formatting and color helper tests
  cache_test.go        Filesystem tests for cache load/save/round-trip
  go.mod               Module definition and dependencies
```

## Running tests

```bash
go test ./...
```

The test suite has **102 tests** (including subtests) across 4 test files with **~85% statement coverage**.

**`main_test.go`** — Core logic and end-to-end `run()` tests:
- **`TestIsHexHash`** — SHA-256 hash detection (valid upper/lowercase, too short, too long, non-hex, empty, MD5-length)
- **`TestHashFile`** — file hashing (known content, empty file, nonexistent file error)
- **`TestTruncateRunes`** — string truncation with multi-byte character safety
- **`TestParseRetryAfter`** — Retry-After header parsing (integers, zero, negative, garbage, RFC 1123 dates)
- **`TestShouldProcess`** — file filter logic (include/exclude globs, size bounds, combined filters)
- **`TestRun*`** — end-to-end tests for `run()`: flag validation (version, no args, missing API key, invalid output/patterns/sizes), hash lookups (clean + malicious exit codes), single file scanning with size filters, directory scanning (flat, recursive, JSON, include/exclude)

**`virustotal_test.go`** — httptest-based integration tests:
- **`TestCheckVirusTotal`** — HTTP client against a mock server (200 success, clean file, 404 not found, 429 retry, 429 exhausted, 403 bad key, bad JSON, context cancellation)
- **`TestCheckVirusTotalSendsAPIKey`** — verifies API key header is sent
- **`TestLookupAndPrint`** — cache + API + output integration (cache miss, cache hit, expired cache, refresh bypass, JSON output)
- **`TestWaitForRateLimit`** — rate limiter (nil limiter, fast limiter, cancelled context)

**`output_test.go`** — Output formatting:
- **`TestPrintJSON`** / **`TestPrintJSONSummary`** — JSON output structure and `omitempty` behavior
- **`TestPrintResult`** — human-readable output (found with details, not found message)
- **`TestColorHelpers`** — ANSI color selection for reputation, malicious, and suspicious counts

**`cache_test.go`** — Filesystem operations:
- **`TestLoadCache`** — missing file, valid file, corrupt JSON graceful degradation
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
| [`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate) | Token-bucket rate limiter for API call pacing |

## License

MIT

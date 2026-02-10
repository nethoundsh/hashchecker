# hashchecker

A command-line tool that computes SHA-256 hashes of files and checks them against the [VirusTotal](https://www.virustotal.com/) API. Scan a single file, look up a known hash, or sweep an entire directory — with colored terminal output and machine-readable JSON.

## Features

- **SHA-256 hashing** — streams files through `crypto/sha256` so even large files are hashed without loading them entirely into memory.
- **VirusTotal lookup** — queries the VirusTotal v3 API and reports malicious/suspicious/undetected/harmless engine counts, reputation score, and threat classification.
- **Direct hash lookup** — pass a 64-character hex string instead of a file path to look up a hash you already have.
- **Directory scanning** — point it at a directory to scan all regular files (symlinks and subdirectories are skipped).
- **Free-tier rate limiting** — the `-free` flag enforces a 15-second delay between API calls to stay within VirusTotal's free API limit (4 requests/minute).
- **Colored output** — malicious results in red, suspicious in yellow, clean in green. Disable with `-no-color` or the `NO_COLOR` environment variable.
- **JSON output** — use `-o json` for NDJSON (one JSON object per line), suitable for piping into `jq` or other tools.
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

## Configuration

Set your VirusTotal API key as an environment variable:

```bash
export VIRUSTOTAL_API_KEY="your-api-key-here"
```

Add this to your `~/.bashrc`, `~/.zshrc`, or equivalent to persist it across sessions.

## Usage

```
hashchecker [-free] [-o text|json] [-no-color] <file | SHA-256 hash | directory>
```

### Flags

| Flag | Description |
|------|-------------|
| `-free` | Rate-limit API requests to 4/minute (VirusTotal free tier) |
| `-o text\|json` | Output format. Default: `text`. Use `json` for NDJSON output |
| `-no-color` | Disable colored terminal output |

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

Scans every regular file in the directory (non-recursive). With `-free`, requests are spaced 15 seconds apart.

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
{"summary":{"path":"/path/to/dir","scanned":2,"malicious":1}}
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

## Security considerations

- **API key handling** — the key is read from an environment variable, never from command-line flags (which are visible in `ps` output and shell history).
- **Read-only** — hashchecker only reads files and makes GET requests. It never modifies files or uploads content.
- **Symlink safety** — directory scans skip symlinks, preventing path traversal or infinite-read attacks (e.g., a symlink to `/dev/zero`).
- **Input validation** — hash arguments are validated as valid hex before being used in API URLs.

## License

MIT

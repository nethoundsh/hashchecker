package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/glaslos/tlsh"
)

// Result holds all hash digests computed from a single file read.
type Result struct {
	SHA256 string
	SHA1   string
	MD5    string
	TLSH   string
}

// ForAlgo returns the hash for the given algorithm name.
func (h Result) ForAlgo(algo string) string {
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

// IsHexHash reports whether s is a valid hex-encoded hash and, if so,
// which algorithm it matches based on decoded byte length:
// 32 bytes = sha256, 20 = sha1, 16 = md5.
func IsHexHash(s string) (bool, string) {
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

// File computes SHA-256, SHA-1, MD5, and TLSH of filePath in a single pass.
// Disk I/O dominates, so computing all four costs essentially the same as one.
// TLSH requires >=256 bytes of diverse content; smaller/uniform files get TLSH="".
func File(filePath string) (_ Result, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return Result{}, fmt.Errorf("hashing: %w", err)
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
				return Result{}, fmt.Errorf("hashing %s: %w", filePath, err)
			}
			if _, err := h1.Write(chunk); err != nil {
				return Result{}, fmt.Errorf("hashing %s: %w", filePath, err)
			}
			if _, err := hMD5.Write(chunk); err != nil {
				return Result{}, fmt.Errorf("hashing %s: %w", filePath, err)
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
			return Result{}, fmt.Errorf("hashing %s: %w", filePath, readErr)
		}
	}

	// TLSH is only valid for sufficiently large, diverse content.
	var tlshValue string
	if tlshEnabled && totalBytes >= 256 {
		_ = hTLSH.Sum(nil)
		tlshValue = func() (value string) {
			defer func() {
				if recovered := recover(); recovered != nil {
					// TLSH may panic for some invalid internal states; degrade gracefully.
					value = ""
				}
			}()
			return hTLSH.String()
		}()
		if strings.Trim(tlshValue, "0") == "" {
			tlshValue = ""
		}
	}

	return Result{
		SHA256: hex.EncodeToString(h256.Sum(nil)),
		SHA1:   hex.EncodeToString(h1.Sum(nil)),
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		TLSH:   tlshValue,
	}, nil
}

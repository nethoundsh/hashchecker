package main

import (
	"io"
	"os"
	"testing"
)

// captureStdout redirects os.Stdout to a pipe, runs fn, and returns
// everything fn wrote to stdout as a string. This lets tests assert
// on printed output without touching the real terminal.
//
// How it works:
//  1. os.Pipe() creates a connected (reader, writer) pair.
//  2. We swap os.Stdout for the writer — any fmt.Print/Println now
//     goes into the pipe instead of the terminal.
//  3. fn() runs, writing into the pipe.
//  4. We close the writer so the reader sees EOF.
//  5. io.ReadAll drains the pipe into a []byte.
//  6. We restore the original os.Stdout before returning.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(): %v", err)
	}

	os.Stdout = w
	fn()
	w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}

	os.Stdout = old
	return string(out)
}

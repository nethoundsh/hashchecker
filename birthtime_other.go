//go:build !linux && !darwin && !windows

package main

import (
	"os"
	"time"
)

func birthTime(_ string, _ os.FileInfo) time.Time {
	return time.Time{}
}

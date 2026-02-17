//go:build linux

package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func birthTime(path string, _ os.FileInfo) time.Time {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_SYNC_AS_STAT, unix.STATX_BTIME, &stx); err != nil {
		return time.Time{}
	}
	if stx.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}
	}
	sec := int64(stx.Btime.Sec)
	nsec := int64(stx.Btime.Nsec)
	if sec == 0 && nsec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec).UTC()
}

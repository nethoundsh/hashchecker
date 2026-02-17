//go:build windows

package fileinfo

import (
	"os"
	"syscall"
	"time"
)

func birthTime(_ string, fi os.FileInfo) time.Time {
	data, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok || data == nil {
		return time.Time{}
	}
	nsec := data.CreationTime.Nanoseconds()
	if nsec == 0 {
		return time.Time{}
	}
	return time.Unix(0, nsec).UTC()
}

//go:build darwin

package fileinfo

import (
	"os"
	"syscall"
	"time"
)

func birthTime(_ string, fi os.FileInfo) time.Time {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return time.Time{}
	}
	sec := st.Birthtimespec.Sec
	nsec := st.Birthtimespec.Nsec
	if sec == 0 && nsec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec).UTC()
}

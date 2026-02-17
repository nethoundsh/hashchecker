package main

import (
	"os"
	"time"

	"github.com/dustin/go-humanize"
)

type fileMeta struct {
	Name        string
	Size        int64
	SizeHuman   string
	Modified    time.Time
	Created     time.Time
	Permissions string
}

type jsonFileMeta struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SizeHuman   string `json:"size_human"`
	Modified    string `json:"modified"`
	Created     string `json:"created,omitempty"`
	Permissions string `json:"permissions"`
}

func newFileMeta(path string, fi os.FileInfo) *fileMeta {
	return &fileMeta{
		Name:        fi.Name(),
		Size:        fi.Size(),
		SizeHuman:   humanize.Bytes(uint64(fi.Size())),
		Modified:    fi.ModTime().UTC(),
		Created:     birthTime(path, fi).UTC(),
		Permissions: fi.Mode().String(),
	}
}

func toJSONFileMeta(meta *fileMeta) *jsonFileMeta {
	if meta == nil {
		return nil
	}
	out := &jsonFileMeta{
		Name:        meta.Name,
		Size:        meta.Size,
		SizeHuman:   meta.SizeHuman,
		Modified:    meta.Modified.Format(time.RFC3339),
		Permissions: meta.Permissions,
	}
	if !meta.Created.IsZero() {
		out.Created = meta.Created.Format(time.RFC3339)
	}
	return out
}

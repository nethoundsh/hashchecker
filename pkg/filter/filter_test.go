package filter

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestShouldProcess(t *testing.T) {
	type args struct {
		name     string
		size     int
		includes []string
		excludes []string
		minSize  int64
		maxSize  int64
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "no filters", args: args{name: "test.exe", size: 1024}, want: true},
		{name: "include exe matches", args: args{name: "test.exe", size: 1024, includes: []string{"*.exe"}}, want: true},
		{name: "include exe does not match txt", args: args{name: "test.txt", size: 1024, includes: []string{"*.exe"}}, want: false},
		{name: "exclude log matches", args: args{name: "test.log", size: 1024, excludes: []string{"*.log"}}, want: false},
		{name: "exclude log does not match exe", args: args{name: "test.exe", size: 1024, excludes: []string{"*.log"}}, want: true},
		{name: "include and exclude same pattern", args: args{name: "test.exe", size: 1024, includes: []string{"*.exe"}, excludes: []string{"*.exe"}}, want: false},
		{name: "minSize larger than file", args: args{name: "test.exe", size: 1024, minSize: 2048}, want: false},
		{name: "maxSize smaller than file", args: args{name: "test.exe", size: 1024, maxSize: 512}, want: false},
		{name: "size within min and max", args: args{name: "test.exe", size: 1024, minSize: 512, maxSize: 2048}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				tt.args.name: &fstest.MapFile{Data: make([]byte, tt.args.size)},
			}
			entries, err := fs.ReadDir(fsys, ".")
			if err != nil {
				t.Fatalf("ReadDir error: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("expected 1 entry, got %d", len(entries))
			}
			d := entries[0]

			got, err := ShouldProcess(d, tt.args.includes, tt.args.excludes, tt.args.minSize, tt.args.maxSize)
			if err != nil {
				t.Fatalf("ShouldProcess returned unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ShouldProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

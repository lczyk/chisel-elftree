package elf

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestScanRpath logs every ELF file under $ELFTREE_SCAN_DIR with a DT_RPATH,
// which unlike DT_RUNPATH also serves the searches of what the file loads,
// so a library found through it may not be found when loaded alone. It
// skips without the dir.
func TestScanRpath(t *testing.T) {
	dir := os.Getenv("ELFTREE_SCAN_DIR")
	if dir == "" {
		t.Skip("ELFTREE_SCAN_DIR not set")
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		fh, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer fh.Close()
		head := make([]byte, 4)
		if n, _ := fh.ReadAt(head, 0); n < 4 || !Magic(head) {
			return nil
		}
		f, err := Read(fh)
		if err != nil || f.Rpath == nil {
			return nil
		}
		t.Logf("%s rpath=%s runpath=%v needed=%s", strings.TrimPrefix(p, dir), strings.Join(f.Rpath, ":"), f.Runpath != nil, strings.Join(f.Needed, ","))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestScanSonames checks, on every regular file under $ELFTREE_SCAN_DIR,
// that Sonames finds what a walk of every byte does, and that an ELF file
// reads the same from memory as from the file. It logs the counts by
// machine and skips without the dir.
func TestScanSonames(t *testing.T) {
	dir := os.Getenv("ELFTREE_SCAN_DIR")
	if dir == "" {
		t.Skip("ELFTREE_SCAN_DIR not set")
	}
	type count struct{ files, names, bytes int }
	counts := map[string]*count{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		got := Sonames(data)
		if want := sonamesByByte(data); !slices.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", p, got, want)
		}
		kind := "not ELF"
		if Magic(data) {
			fh, err := os.Open(p)
			if err != nil {
				return nil
			}
			defer fh.Close()
			a, aerr := Read(fh)
			b, berr := ReadBytes(data)
			if (aerr == nil) != (berr == nil) || !reflect.DeepEqual(a, b) {
				t.Errorf("%s: read from the file and from memory differ: %v, %v", p, aerr, berr)
			}
			kind = "unreadable ELF"
			if a != nil {
				kind = a.Machine.String() + " " + a.Class.String() + " " + a.Data.String()
			}
		}
		c := counts[kind]
		if c == nil {
			c = &count{}
			counts[kind] = c
		}
		c.files++
		c.names += len(got)
		c.bytes += len(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range slices.Sorted(maps.Keys(counts)) {
		c := counts[kind]
		t.Logf("%s: %d files, %.1fmb, %d names", kind, c.files, float64(c.bytes)/1e6, c.names)
	}
}

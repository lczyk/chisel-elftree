package elf

import (
	stdelf "debug/elf"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCrossCheck reads every ELF file under $ELFTREE_XCHECK_DIR (a cut's
// rootfs, say) and compares what Read gets from the program headers with
// what debug/elf gets from the section headers, where there are any. With
// ELFTREE_DUMP=1 it also logs every dlopen note. It skips without the dir.
func TestCrossCheck(t *testing.T) {
	dir := os.Getenv("ELFTREE_XCHECK_DIR")
	if dir == "" {
		t.Skip("ELFTREE_XCHECK_DIR not set")
	}
	dump := os.Getenv("ELFTREE_DUMP") == "1"
	files, sectionless := 0, 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		fh, err := os.Open(p)
		if err != nil {
			return err
		}
		defer fh.Close()
		head := make([]byte, 4)
		if n, _ := fh.ReadAt(head, 0); n < 4 || !Magic(head) {
			return nil
		}
		files++
		got, err := Read(fh)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			return nil
		}
		if os.Getenv("ELFTREE_DUMP") == "2" {
			t.Logf("%s: soname %q needed %q rpath %q runpath %q flags1 %#x", strings.TrimPrefix(p, dir), got.Soname, got.Needed, got.Rpath, got.Runpath, got.Flags1)
		}
		if dump {
			for _, e := range got.Dlopen {
				t.Logf("%s: dlopen %s %s %v", strings.TrimPrefix(p, dir), e.Feature, e.Priority, e.Soname)
			}
		}
		ef, err := stdelf.NewFile(fh)
		if err != nil {
			t.Errorf("%s: debug/elf: %v", p, err)
			return nil
		}
		if ef.Section(".dynamic") == nil {
			sectionless++
			return nil
		}
		for _, c := range []struct {
			tag  stdelf.DynTag
			want []string
		}{
			{stdelf.DT_NEEDED, got.Needed},
			{stdelf.DT_SONAME, nonEmpty(got.Soname)},
			{stdelf.DT_RPATH, joined(got.Rpath)},
			{stdelf.DT_RUNPATH, joined(got.Runpath)},
		} {
			ref, err := ef.DynString(c.tag)
			if err != nil {
				t.Errorf("%s: debug/elf %v: %v", p, c.tag, err)
				continue
			}
			if !slices.Equal(ref, c.want) {
				t.Errorf("%s: %v: got %q, debug/elf %q", p, c.tag, c.want, ref)
			}
		}
		if libs, err := ef.ImportedLibraries(); err == nil && !slices.Equal(libs, got.Needed) {
			t.Errorf("%s: needed %q, imported libraries %q", p, got.Needed, libs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d ELF files, %d without a .dynamic section", files, sectionless)
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func joined(l []string) []string {
	if l == nil {
		return nil
	}
	return []string{strings.Join(l, ":")}
}

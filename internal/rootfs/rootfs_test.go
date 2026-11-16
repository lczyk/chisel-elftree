package rootfs

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseShebang(t *testing.T) {
	for line, want := range map[string]Shebang{
		"#!/bin/sh\n":               {Interp: "/bin/sh"},
		"#! /usr/bin/env python3\n": {Interp: "/usr/bin/env", Arg: "python3"},
		"#!/usr/bin/perl -w  \r\n":  {Interp: "/usr/bin/perl", Arg: "-w"},
		"#!/bin/bash\t-e\n":         {Interp: "/bin/bash", Arg: "-e"},
		"#!\n":                      {},
	} {
		if got := parseShebang(line); *got != want {
			t.Errorf("%q: %+v, want %+v", line, *got, want)
		}
	}
}

func TestContents(t *testing.T) {
	for _, want := range []string{"", "x", strings.Repeat("libfoo.so.1\x00", 100000)} {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, []byte(want), 0644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		data, release, err := contents(f)
		if err != nil || string(data) != want {
			t.Errorf("%d bytes: got %d, %v", len(want), len(data), err)
		}
		if release != nil {
			release()
		}
		f.Close()
	}
}

// TestScanContents checks, on every regular file under $ELFTREE_SCAN_DIR,
// that contents is the bytes a read of the file gives. It skips without
// the dir.
func TestScanContents(t *testing.T) {
	dir := os.Getenv("ELFTREE_SCAN_DIR")
	if dir == "" {
		t.Skip("ELFTREE_SCAN_DIR not set")
	}
	files := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		want, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		data, release, err := contents(f)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			return nil
		}
		defer release()
		if !bytes.Equal(data, want) {
			t.Errorf("%s: %d bytes, want %d", p, len(data), len(want))
		}
		files++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files", files)
}

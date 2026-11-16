package glob

import "testing"

// The cases chisel's own strdist.GlobPath is tested with that compare a
// pattern to a path, and a few for the sonames --prune takes.
func TestMatch(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"/a/b", "/a/b", true},
		{"/a/b", "/a/c", false},
		{"/a/?", "/a/b", true},
		{"/a/?", "/a/", false},
		{"/a?", "/a/", false},
		{"/a/*", "/a/bcd", true},
		{"/a/*", "/a/b/c", false},
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/d/c", false},
		{"/a/**", "/a/b/c", true},
		{"/a/**/c", "/a/b/d/c", true},
		{"/a/**/c", "/a/c", false},
		{"/a/**c", "/a/c", true},
		{"/**", "/", true},
		{"/usr/lib/*-linux-*/libc.so.6", "/usr/lib/aarch64-linux-gnu/libc.so.6", true},
		{"/usr/lib/*-linux-*/libc.so.6", "/usr/lib/x/aarch64-linux-gnu/libc.so.6", false},
		{"ld-linux-*", "ld-linux-aarch64.so.1", true},
		{"libc.so.*", "libc.so.6", true},
		{"libc.so.*", "libcrypt.so.1", false},
		{"[a]", "a", false},
		{"[a]", "[a]", true},
	} {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestFile(t *testing.T) {
	for _, c := range []struct {
		pattern, p string
		want       bool
	}{
		{"systemd-measure", "/usr/lib/systemd/systemd-measure", true},
		{"systemd-*", "/usr/lib/systemd/systemd-measure", true},
		{"systemd-*", "/usr/lib/systemd", false},
		{"/usr/lib/systemd/*", "/usr/lib/systemd/systemd-measure", true},
		{"/systemd-measure", "/usr/lib/systemd/systemd-measure", false},
		{"/usr/**/systemd-measure", "/usr/lib/systemd/systemd-measure", true},
	} {
		if got := File(c.pattern, c.p); got != c.want {
			t.Errorf("File(%q, %q) = %v, want %v", c.pattern, c.p, got, c.want)
		}
	}
}

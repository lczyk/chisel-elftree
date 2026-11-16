package lookup

import (
	"slices"
	"testing"
)

func TestShortlist(t *testing.T) {
	got := Shortlist("libkmod.so.2", "aarch64-linux-gnu")
	for _, want := range []string{
		"/usr/lib/*-linux-*/libkmod.so.2*",
		"/usr/lib/*-linux-*/libkmod.so.*",
		"/lib/*-linux-*/libkmod.so.2",
		"/usr/lib/aarch64-linux-gnu/libkmod.so.2.*",
		"/lib/aarch64-linux-gnu/libkmod.so*",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s", want)
		}
	}
	if slices.Contains(got, "/usr/lib/*-linux-*/libkmod.so") {
		t.Error("the dev link does not provide the soname")
	}
	if len(got) != 20 {
		t.Errorf("%d keys", len(got))
	}
	if got := Shortlist("/opt/x/libfoo.so", "aarch64-linux-gnu"); !slices.Equal(got, []string{"/opt/x/libfoo.so"}) {
		t.Errorf("a path is itself: %q", got)
	}
}

func TestCandidates(t *testing.T) {
	ix := Index{
		"/usr/lib/*-linux-*/libkmod.so.2*": {{Slice: "libkmod2_libs"}},
		"/usr/lib/*-linux-*/libkmod.so.*":  {{Slice: "other_libs", Arch: []string{"amd64"}}},
	}
	keys := Shortlist("libkmod.so.2", "aarch64-linux-gnu")
	if got := ix.Candidates(keys, "arm64"); !slices.Equal(got, []string{"libkmod2_libs"}) {
		t.Errorf("arm64 %q", got)
	}
	if got := ix.Candidates(keys, "amd64"); !slices.Equal(got, []string{"libkmod2_libs", "other_libs"}) {
		t.Errorf("amd64 %q", got)
	}
}

func TestTargets(t *testing.T) {
	got := Targets("libz.so.1", []string{"/lib/x", "/usr/lib/x", "/lib", "/usr/lib"})
	want := []string{"/lib/x/libz.so.1", "/usr/lib/x/libz.so.1", "/lib/libz.so.1", "/usr/lib/libz.so.1"}
	if !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
	if got := Targets("/bin/sh", nil); !slices.Equal(got, []string{"/bin/sh", "/usr/bin/sh"}) {
		t.Errorf("%q", got)
	}
	if got := Spellings("/usr/libexec/x"); !slices.Equal(got, []string{"/usr/libexec/x"}) {
		t.Errorf("%q", got)
	}
}

package validatetrick

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	temprelease "github.com/lczyk/chisel-proxy/pkg/temp-release"
)

func TestParse(t *testing.T) {
	for _, c := range []struct {
		out  string
		want Conflict
		ok   bool
	}{{
		out:  "error: slices elftree-probe_probe and libkmod2_libs conflict on /usr/lib/aarch64-linux-gnu/libkmod.so.2 and /usr/lib/*-linux-*/libkmod.so.2*\n",
		want: Conflict{Slice: "libkmod2_libs", Key: "/usr/lib/*-linux-*/libkmod.so.2*", Target: "/usr/lib/aarch64-linux-gnu/libkmod.so.2"}, ok: true,
	}, {
		out:  "error: slices a_b and elftree-probe_probe conflict on /usr/lib/** and /usr/lib/x\n",
		want: Conflict{Slice: "a_b", Key: "/usr/lib/**", Target: "/usr/lib/x"}, ok: true,
	}, {
		out:  "error: slices elftree-probe_probe and openssl_bins conflict on /usr/bin/openssl\n",
		want: Conflict{Slice: "openssl_bins", Key: "/usr/bin/openssl", Target: "/usr/bin/openssl"}, ok: true,
	}, {
		out:  `error: package "busybox" and "elftree-probe" conflict on /usr/bin/busybox without prefer relationship` + "\n",
		want: Conflict{Key: "/usr/bin/busybox", Target: "/usr/bin/busybox", Prefer: true, Packages: []string{"busybox", "elftree-probe"}}, ok: true,
	}, {
		// A conflict between two real slices is the release's own, not an
		// answer.
		out: "error: slices a_b and c_d conflict on /x\n",
	}, {
		// chisel may name two real packages; the path says it is the
		// probe's, which the caller checks.
		out:  `error: package "busybox" and "busybox-static" conflict on /usr/bin/busybox without prefer relationship` + "\n",
		want: Conflict{Key: "/usr/bin/busybox", Target: "/usr/bin/busybox", Prefer: true, Packages: []string{"busybox", "busybox-static"}}, ok: true,
	}, {
		out: "error: cannot read chisel.yaml\n",
	}} {
		got, ok := Parse(c.out)
		if ok != c.ok || !equal(got, c.want) {
			t.Errorf("Parse(%q) = %+v, %v; want %+v, %v", c.out, got, ok, c.want, c.ok)
		}
	}
}

func equal(a, b Conflict) bool {
	return a.Slice == b.Slice && a.Key == b.Key && a.Target == b.Target && a.Prefer == b.Prefer && slices.Equal(a.Packages, b.Packages)
}

// realRelease is chisel's cached copy of a release, for the tests that ask
// the real chisel. They skip without chisel or the copy.
func realRelease(t *testing.T, name string) (string, string) {
	t.Helper()
	bin := os.Getenv("CHISEL")
	if bin == "" {
		bin = "chisel"
	}
	if p, err := exec.LookPath(bin); err != nil {
		t.Skip("chisel not found")
	} else {
		bin = p
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cache", "chisel", "releases", name)
	if _, err := os.Stat(filepath.Join(dir, "chisel.yaml")); err != nil {
		t.Skipf("no cached %s release", name)
	}
	// A copy, so a bug writing through to the release harms chisel's cache
	// no more than the test's own dir.
	rel, err := temprelease.Copy(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rel.Remove() })
	return bin, rel.Dir
}

func collect(t *testing.T, p *Prober, target string) []Hit {
	t.Helper()
	var out []Hit
	for h, err := range p.Declarers(context.Background(), target) {
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		out = append(out, h)
	}
	return out
}

func TestRealChisel(t *testing.T) {
	bin, dir := realRelease(t, "ubuntu-26.04")
	p := &Prober{Bin: bin, Release: dir}
	for _, c := range []struct {
		target string
		want   []Hit
	}{{
		// A glob covering the target.
		target: "/usr/lib/aarch64-linux-gnu/libkmod.so.2",
		want:   []Hit{{Slice: "libkmod2_libs", Key: "/usr/lib/*-linux-*/libkmod.so.2*"}},
	}, {
		// The same glob covers another target: each target works on a
		// copy of its own, so the key deleted for one is there for the
		// other.
		target: "/usr/lib/x86_64-linux-gnu/libkmod.so.2.5.1",
		want:   []Hit{{Slice: "libkmod2_libs", Key: "/usr/lib/*-linux-*/libkmod.so.2*"}},
	}, {
		// A path with prefer relationships: every package listing it.
		target: "/usr/bin/busybox",
		want:   []Hit{{Slice: "busybox_bins", Key: "/usr/bin/busybox"}, {Slice: "busybox-static_bins", Key: "/usr/bin/busybox"}},
	}, {
		// Nothing declares it.
		target: "/usr/lib/aarch64-linux-gnu/libtss2-esys.so.0",
	}} {
		got := collect(t, p, c.target)
		for i := range got {
			got[i].Target = ""
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.target, got, c.want)
		}
	}
	// An exact path: the key deleted, the next round finds the rest.
	got := collect(t, p, "/usr/bin/openssl")
	if len(got) == 0 || got[0].Slice != "openssl_bins" || got[0].Key != "/usr/bin/openssl" {
		t.Errorf("/usr/bin/openssl: got %+v", got)
	}
	t.Logf("%d validations", p.Validations())
}

// One probe for many targets clears the ones nothing declares and leaves
// the declared ones, however declared, to Declarers.
func TestRealChiselUndeclared(t *testing.T) {
	bin, dir := realRelease(t, "ubuntu-26.04")
	p := &Prober{Bin: bin, Release: dir}
	none := []string{"/usr/lib/aarch64-linux-gnu/libtss2-esys.so.0", "/lib/s390x-linux-gnu/libtss2-esys.so.0", "/usr/lib/libqrencode.so.3"}
	declared := []string{
		"/usr/lib/aarch64-linux-gnu/libkmod.so.2", // a glob
		"/usr/lib/x86_64-linux-gnu/libkmod.so.2",  // the same glob
		"/usr/bin/busybox",                        // prefer relationships
		"/usr/bin/openssl",                        // an exact path
	}
	got := p.Undeclared(context.Background(), slices.Concat(none[:1], declared, none[1:]))
	if !slices.Equal(got, none) {
		t.Errorf("got %v, want %v", got, none)
	}
	if n := p.Validations(); n != len(declared)+1 {
		t.Errorf("%d validations, want %d", n, len(declared)+1)
	}
	if got := p.Undeclared(context.Background(), declared[:1]); len(got) != 0 {
		t.Errorf("a declared target alone: got %v", got)
	}
}

// A key deleted in the copy is deleted there only: the source release, whose
// files the copy links to, stays as it was.
func TestDeleteKeyLeavesSource(t *testing.T) {
	src := t.TempDir()
	orig := "package: a\nslices:\n  b:\n    contents:\n      /x:\n      /y:\n"
	for p, b := range map[string]string{"chisel.yaml": "format: v1\n", "slices/a.yaml": orig, "tests/t.txt": "big"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(src, p)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, p), []byte(b), 0644); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := linkCopy(src)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if _, err := os.Stat(filepath.Join(dir, "tests")); !os.IsNotExist(err) {
		t.Errorf("tests copied: %v", err)
	}
	if err := deleteKey(dir, "a_b", "/x"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(src, "slices/a.yaml")); string(b) != orig {
		t.Errorf("source changed:\n%s", b)
	}
	if hits, err := literal(dir, "/y"); err != nil || !slices.Equal(hits, []string{"a_b"}) {
		t.Errorf("copy /y: %v %v", hits, err)
	}
	if _, err := literal(dir, "/x"); err == nil {
		t.Error("copy still has /x")
	}
}

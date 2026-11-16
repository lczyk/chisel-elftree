package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lczyk/chisel-elftree/internal/check"
	"github.com/lczyk/chisel-elftree/internal/elf"
	"github.com/lczyk/chisel-elftree/internal/resolve"
	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

func TestDrawTree(t *testing.T) {
	roots := []*tline{{text: "/a", kids: []*tline{
		{text: "b", kids: []*tline{{text: "c"}}},
		{text: "d", kids: []*tline{{text: "e"}, {text: "f"}}},
	}}}
	var b bytes.Buffer
	drawTree(&b, roots, style{})
	want := `/a
├─ b
│  └─ c
└─ d
   ├─ e
   └─ f
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestDescribe(t *testing.T) {
	for _, c := range []struct {
		st   resolve.Start
		f    *elf.File
		want string
	}{
		{resolve.Start{Path: "/usr/bin/x", Kind: "exec"}, &elf.File{Interp: "/lib/ld.so"}, "executable"},
		{resolve.Start{Path: "/usr/bin/x", Kind: "exec"}, &elf.File{}, "static executable"},
		{resolve.Start{Path: "/usr/bin/x", Kind: "exec"}, &elf.File{Flags1: elf.DF1PIE}, "static-pie executable"},
		{resolve.Start{Path: "/usr/lib/libx.so.1", Kind: "lib"}, &elf.File{Soname: "libx.so.1"}, "shared library"},
		{resolve.Start{Path: "/usr/lib/libx.so.1.2", Kind: "lib"}, &elf.File{Soname: "libx.so.1",
			Dlopen: []elf.DlopenEntry{{}, {}}}, "shared library, soname libx.so.1, 2 dlopen entries"},
		{resolve.Start{Path: "/usr/bin/s", Kind: "script"}, nil, "script"},
	} {
		n := &rootfs.Node{ELF: c.f}
		if got := describe(c.st, n); got != c.want {
			t.Errorf("%s %+v: got %q, want %q", c.st.Kind, c.f, got, c.want)
		}
	}
}

// Every finding line says its severity, and is painted by it when coloured.
func TestRenderTextSeverity(t *testing.T) {
	rep := &check.Report{Arches: []string{"arm64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{}}
	for _, it := range []check.Item{
		{Severity: check.Hard, Kind: "needed", Name: "libx.so.1", Reason: "not found"},
		{Severity: check.Soft, Kind: "dlopen", Name: "liby.so.1", Feature: "y", Priority: "suggested", Reason: "no slice declares it"},
		{Severity: check.Info, Kind: "dlopen", Name: "libz.so.1", Feature: "z", Priority: "suggested", Reason: "delivered by z_libs, not an essential"},
	} {
		it.Arch, it.Against, it.Named, it.Path, it.Sev = "arm64", "a_b", true, "/usr/bin/x", it.Severity.String()
		rep.Items = append(rep.Items, it)
	}
	var plain, painted bytes.Buffer
	renderText(&plain, rep, false, nil, style{})
	renderText(&painted, rep, false, nil, colours)
	for _, want := range []string{
		"a_b [arm64]\n",
		"/usr/bin/x: hard needed libx.so.1: not found\n",
		"/usr/bin/x: soft dlopen liby.so.1 (y, suggested): no slice declares it\n",
		"/usr/bin/x: info dlopen libz.so.1 (z, suggested): delivered by z_libs, not an essential\n",
	} {
		if !strings.Contains(plain.String(), want) {
			t.Errorf("plain: no %q in\n%s", want, plain.String())
		}
	}
	if i, j := strings.Index(plain.String(), ": soft "), strings.Index(plain.String(), ": info "); i > j {
		t.Error("soft after info")
	}
	for _, want := range []string{
		colours.name + "a_b" + colours.reset,
		colours.red + "/usr/bin/x: hard",
		colours.yellow + "/usr/bin/x: soft",
		colours.dim + "/usr/bin/x: info",
	} {
		if !strings.Contains(painted.String(), want) {
			t.Errorf("painted: no %q in\n%q", want, painted.String())
		}
	}
}

func TestPruned(t *testing.T) {
	for _, c := range []struct {
		prune      []string
		name, file string
		want       bool
	}{
		{[]string{"libc.so.*"}, "libc.so.6", "", true},
		{[]string{"libc.so.*"}, "", "/usr/lib/aarch64-linux-gnu/libc.so.6", true},
		{[]string{"ld-linux-*"}, "/lib/ld-linux-aarch64.so.1", "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", true},
		{[]string{"/usr/lib/*-linux-*/libc.so.6"}, "libc.so.6", "/usr/lib/aarch64-linux-gnu/libc.so.6", true},
		{[]string{"/usr/lib/*-linux-*/libc.so.6"}, "libc.so.6", "", false},
		{[]string{"libc.so.*"}, "libcrypt.so.1", "/usr/lib/x/libcrypt.so.1", false},
		{[]string{"@ld"}, "/lib/ld-linux-aarch64.so.1", "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", true},
		{[]string{"@ld"}, "ld-linux-aarch64.so.1", "", true},
		{[]string{"@ld"}, "ld64.so.1", "/usr/lib/s390x-linux-gnu/ld64.so.1", false},
		{[]string{"@ld"}, "libc.so.6", "/usr/lib/aarch64-linux-gnu/libc.so.6", false},
	} {
		if got := pruned(c.prune, "arm64", c.name, c.file); got != c.want {
			t.Errorf("pruned(%q, %q, %q) = %v", c.prune, c.name, c.file, got)
		}
	}
}

// A pruned library goes from the tree with all under it, unless a finding is
// under it; its info lines go from the text report, its findings stay.
func TestPrune(t *testing.T) {
	x := "/usr/bin/x"
	c := &check.Cut{
		Key:       check.Key{Slice: "a_b", Arch: "arm64"},
		Available: true,
		Owners:    map[string][]string{x: {"a_b"}, "/lib/libc.so.6": {"libc6_libs"}, "/lib/liby.so.1": {"y_libs"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{x: {Path: x, ELF: &elf.File{Interp: "/lib/ld.so"}}}},
		Res: &resolve.Result{
			Starts: []resolve.Start{{Path: x, Kind: "exec", Links: []resolve.Link{
				{From: x, Kind: resolve.Needed, Name: "libc.so.6", To: "/lib/libc.so.6"},
				{From: x, Kind: resolve.Needed, Name: "liby.so.1", To: "/lib/liby.so.1"},
				{From: "/lib/liby.so.1", Kind: resolve.Needed, Name: "libc.so.6", To: "/lib/libc.so.6"},
			}}},
			Findings: []resolve.Finding{{Start: x, From: "/lib/liby.so.1", Kind: resolve.Needed, Name: "libq.so.1", Reason: "not found"}},
		},
	}
	rep := &check.Report{Arches: []string{"arm64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{c.Key: c}}
	var b bytes.Buffer
	renderTree(&b, rep, []string{"libc.so.*", "liby.so.1"}, nil, style{})
	want := `a_b [arm64]
/usr/bin/x (a_b): executable
└─ needed liby.so.1 -> /lib/liby.so.1 (y_libs)
   └─ ! needed libq.so.1: not found
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}

	for _, it := range []check.Item{
		{Severity: check.Info, Path: x, Kind: "dlopen", Name: "libz.so.1", Reason: "delivered by z_libs, not an essential"},
		{Severity: check.Info, Path: "/lib/libc.so.6", Kind: "dlopen", Name: "libw.so.1", Reason: "delivered by w_libs, not an essential"},
		{Severity: check.Soft, Path: x, Kind: "dlopen", Name: "libv.so.1", Reason: "no slice declares it"},
	} {
		it.Arch, it.Against, it.Named, it.Sev = "arm64", "a_b", true, it.Severity.String()
		rep.Items = append(rep.Items, it)
	}
	b.Reset()
	renderText(&b, rep, false, []string{"libz.so.1", "libc.so.*", "libv.so.1"}, style{})
	if got := b.String(); got != "a_b [arm64]\n/usr/bin/x: soft dlopen libv.so.1: no slice declares it\n" {
		t.Errorf("text:\n%s", got)
	}
}

// A library is drawn in full wherever it is reached, and a cycle stops at
// the node already on the way down.
func TestTreeFull(t *testing.T) {
	x := "/usr/bin/x"
	c := &check.Cut{
		Key:       check.Key{Slice: "a_b", Arch: "arm64"},
		Available: true,
		Owners:    map[string][]string{x: {"a_b"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{x: {Path: x, ELF: &elf.File{Interp: "/lib/ld.so"}}}},
		Res: &resolve.Result{Starts: []resolve.Start{{Path: x, Kind: "exec", Links: []resolve.Link{
			{From: x, Kind: resolve.Needed, Name: "liba.so", To: "/lib/liba.so"},
			{From: x, Kind: resolve.Needed, Name: "libb.so", To: "/lib/libb.so"},
			{From: "/lib/liba.so", Kind: resolve.Needed, Name: "libb.so", To: "/lib/libb.so"},
			{From: "/lib/libb.so", Kind: resolve.Needed, Name: "liba.so", To: "/lib/liba.so"},
		}}}},
	}
	rep := &check.Report{Arches: []string{"arm64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{c.Key: c}}
	var b bytes.Buffer
	renderTree(&b, rep, nil, nil, style{})
	want := `a_b [arm64]
/usr/bin/x (a_b): executable
├─ needed liba.so -> /lib/liba.so
│  └─ needed libb.so -> /lib/libb.so
│     └─ needed liba.so -> /lib/liba.so (cycle)
└─ needed libb.so -> /lib/libb.so
   └─ needed liba.so -> /lib/liba.so
      └─ needed libb.so -> /lib/libb.so (cycle)
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

// What the loader links in comes first under a node, the dynamic loader
// itself first and the rest by name, its findings after, then dlopens by
// priority, required, recommended, suggested, each by name, whatever the
// order found.
func TestTreeLoaderFirst(t *testing.T) {
	x := "/usr/bin/x"
	c := &check.Cut{
		Key:       check.Key{Slice: "a_b", Arch: "arm64"},
		Available: true,
		Owners:    map[string][]string{x: {"a_b"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{x: {Path: x, ELF: &elf.File{Interp: "/lib/ld.so"}}}},
		Res: &resolve.Result{
			Starts: []resolve.Start{{Path: x, Kind: "exec", Links: []resolve.Link{
				{From: x, Kind: resolve.Dlopen, Name: "libd.so", To: "/lib/libd.so", Note: &resolve.Via{Feature: "d", Priority: "required"}},
				{From: x, Kind: resolve.Needed, Name: "liba.so", To: "/lib/liba.so"},
				{From: x, Kind: resolve.Needed, Name: "zz-ld.so", To: "/lib/ld.so"},
				{From: x, Kind: resolve.Interp, Name: "/lib/ld.so", To: "/lib/ld.so"},
				{From: x, Kind: resolve.Dlopen, Name: "liba.so", To: "/lib/liba.so", Reused: true, Note: &resolve.Via{Feature: "a", Priority: "suggested"}},
			}}},
			Findings: []resolve.Finding{
				{Start: x, From: x, Kind: resolve.Dlopen, Name: "libe.so", Reason: "found at /lib/libe.so, which does not load", Via: &resolve.Via{Priority: "recommended"}},
				{Start: x, From: x, Kind: resolve.Needed, Name: "libq.so", Reason: "not found"},
			},
		},
	}
	rep := &check.Report{Arches: []string{"arm64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{c.Key: c}}
	var b bytes.Buffer
	renderTree(&b, rep, nil, nil, style{})
	want := `a_b [arm64]
/usr/bin/x (a_b): executable
├─ interp /lib/ld.so
├─ needed zz-ld.so -> /lib/ld.so
├─ needed liba.so -> /lib/liba.so
├─ ! needed libq.so: not found
├─ dlopen libd.so (d, required) -> /lib/libd.so
├─ ! dlopen libe.so: found at /lib/libe.so, which does not load
└─ dlopen liba.so (a, suggested) -> /lib/liba.so
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

// Under a library is what loading it alone does, its own start node, not
// what the start above did from it; under a dlopen a slice outside the cut
// delivers is that slice's cut of it.
func TestTreeIsolated(t *testing.T) {
	x, a := "/usr/bin/x", "/lib/liba.so"
	c := &check.Cut{
		Key:       check.Key{Slice: "a_b", Arch: "arm64"},
		Available: true,
		Owners:    map[string][]string{x: {"a_b"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{x: {Path: x, ELF: &elf.File{Interp: "/lib/ld.so"}}}},
		Res: &resolve.Result{
			Starts: []resolve.Start{
				{Path: x, Kind: "exec", Links: []resolve.Link{
					{From: x, Kind: resolve.Needed, Name: "liba.so", To: a},
					{From: a, Kind: resolve.Needed, Name: "libb.so", To: "/lib/b-seen-from-x.so"},
				}},
				{Path: a, Kind: "lib", Links: []resolve.Link{
					{From: a, Kind: resolve.Needed, Name: "libb.so", To: "/lib/libb.so"},
				}},
			},
			Open: []resolve.Open{{Start: a, From: a, Entry: elf.DlopenEntry{Feature: "p", Priority: "suggested", Soname: []string{"libp.so"}}, Absent: []string{"libp.so"}}},
		},
	}
	p := &check.Cut{
		Key:       check.Key{Slice: "p_libs", Arch: "arm64"},
		Available: true,
		Owners:    map[string][]string{"/lib/libp.so": {"p_libs"}, "/lib/libq.so": {"q_libs"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{}},
		Res: &resolve.Result{Starts: []resolve.Start{{Path: "/lib/libp.so", Kind: "lib", Links: []resolve.Link{
			{From: "/lib/libp.so", Kind: resolve.Needed, Name: "libq.so", To: "/lib/libq.so"},
		}}}},
	}
	rep := &check.Report{Arches: []string{"arm64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{c.Key: c, p.Key: p},
		Items: []check.Item{{Arch: "arm64", Against: "a_b", Named: true, Severity: check.Info, Sev: "info", Path: a, Kind: resolve.Dlopen,
			Name: "libp.so", Reason: "delivered by p_libs", Provider: "p_libs", ProviderPath: "/lib/libp.so"}}}
	var b bytes.Buffer
	renderTree(&b, rep, nil, nil, style{})
	want := `a_b [arm64]
/usr/bin/x (a_b): executable
└─ needed liba.so -> /lib/liba.so
   ├─ needed libb.so -> /lib/libb.so
   └─ ? dlopen libp.so (p, suggested): delivered by p_libs
      └─ needed libq.so -> /lib/libq.so (q_libs)
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
	// --fold missing: the line, not what is under it.
	b.Reset()
	renderTree(&b, rep, nil, []string{"missing"}, style{})
	if want := strings.TrimSuffix(want, "      └─ needed libq.so -> /lib/libq.so (q_libs)\n"); b.String() != want {
		t.Errorf("fold missing: got\n%s\nwant\n%s", b.String(), want)
	}
}

// A library with a PT_INTERP of its own, as libc.so.6, shows none when
// loaded as a library: the loader does not read it then.
func TestTreeLibraryInterp(t *testing.T) {
	x, libc := "/usr/bin/x", "/lib/libc.so.6"
	c := &check.Cut{
		Key:       check.Key{Slice: "a_b", Arch: "arm64"},
		Available: true,
		Owners:    map[string][]string{x: {"a_b"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{x: {Path: x, ELF: &elf.File{Interp: "/lib/ld.so"}}}},
		Res: &resolve.Result{Starts: []resolve.Start{
			{Path: x, Kind: "exec", Links: []resolve.Link{
				{From: x, Kind: resolve.Interp, Name: "/lib/ld.so", To: "/lib/ld.so"},
				{From: x, Kind: resolve.Needed, Name: "libc.so.6", To: libc},
			}},
			{Path: libc, Kind: "exec", Links: []resolve.Link{
				{From: libc, Kind: resolve.Interp, Name: "/lib/ld.so", To: "/lib/ld.so"},
				{From: libc, Kind: resolve.Needed, Name: "ld.so", To: "/lib/ld.so"},
			}},
		}},
	}
	rep := &check.Report{Arches: []string{"arm64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{c.Key: c}}
	var b bytes.Buffer
	renderTree(&b, rep, nil, nil, style{})
	want := `a_b [arm64]
/usr/bin/x (a_b): executable
├─ interp /lib/ld.so
└─ needed libc.so.6 -> /lib/libc.so.6
   └─ needed ld.so -> /lib/ld.so
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

// --fold repeats: a library is drawn once under a start node, as lddtree
// does: the lines right under a node claim theirs first, so libb is the
// start's own dlopen and not drawn again under liba, nor libc under either.
func TestFoldRepeats(t *testing.T) {
	x := "/usr/bin/x"
	c := &check.Cut{
		Key:       check.Key{Slice: "a_b", Arch: "arm64"},
		Available: true,
		Owners:    map[string][]string{x: {"a_b"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{x: {Path: x, ELF: &elf.File{Interp: "/lib/ld.so"}}}},
		Res: &resolve.Result{Starts: []resolve.Start{{Path: x, Kind: "exec", Links: []resolve.Link{
			{From: x, Kind: resolve.Needed, Name: "liba.so", To: "/lib/liba.so"},
			{From: x, Kind: resolve.Needed, Name: "libc.so", To: "/lib/libc.so"},
			{From: "/lib/liba.so", Kind: resolve.Needed, Name: "libb.so", To: "/lib/libb.so"},
			{From: "/lib/liba.so", Kind: resolve.Needed, Name: "libc.so", To: "/lib/libc.so"},
			{From: "/lib/libb.so", Kind: resolve.Needed, Name: "libc.so", To: "/lib/libc.so"},
			{From: x, Kind: resolve.Dlopen, Name: "libb.so", To: "/lib/libb.so", Note: &resolve.Via{Feature: "b", Priority: "suggested"}},
		}}}},
	}
	rep := &check.Report{Arches: []string{"arm64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{c.Key: c}}
	var b bytes.Buffer
	renderTree(&b, rep, nil, []string{"repeats"}, style{})
	want := `a_b [arm64]
/usr/bin/x (a_b): executable
├─ needed liba.so -> /lib/liba.so
├─ needed libc.so -> /lib/libc.so
└─ dlopen libb.so (b, suggested) -> /lib/libb.so
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

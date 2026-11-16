package cli

import (
	"bytes"
	"testing"

	"github.com/lczyk/chisel-elftree/internal/check"
	"github.com/lczyk/chisel-elftree/internal/elf"
	"github.com/lczyk/chisel-elftree/internal/resolve"
	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

// cutOn is a cut of a_b on arch: /usr/bin/x needs libc from the arch's
// multiarch dir, which has a string for libgcc no slice answers, and with
// bpf it has a dlopen for libbpf too.
func cutOn(arch, triplet, version string, bpf bool) (*check.Cut, []check.Item) {
	x, libc := "/usr/bin/x", "/usr/lib/"+triplet+"/libc.so.6"
	c := &check.Cut{
		Key:       check.Key{Slice: "a_b", Arch: arch},
		Available: true,
		Versions:  map[string]string{"a": version},
		Owners:    map[string][]string{x: {"a_b"}, libc: {"libc6_libs"}},
		FS:        &rootfs.FS{Nodes: map[string]*rootfs.Node{x: {Path: x, ELF: &elf.File{Interp: "/lib/ld.so"}}}},
		Res: &resolve.Result{
			Starts: []resolve.Start{{Path: x, Kind: "exec", Links: []resolve.Link{
				{From: x, Kind: resolve.Needed, Name: "libc.so.6", To: libc},
			}}},
			Open: []resolve.Open{{Start: x, From: libc, Entry: elf.DlopenEntry{Soname: []string{"libgcc_s.so.1"}, Priority: elf.PriorityStrings}}},
		},
	}
	items := []check.Item{{Arch: arch, Severity: check.Soft, Path: libc, Kind: elf.PriorityStrings, Name: "libgcc_s.so.1", Reason: "no slice declares it"}}
	if bpf {
		c.Res.Open = append(c.Res.Open, resolve.Open{Start: x, From: libc, Entry: elf.DlopenEntry{Soname: []string{"libbpf.so.1"}, Feature: "bpf", Priority: "suggested"}})
		items = append(items, check.Item{Arch: arch, Severity: check.Info, Path: libc, Kind: resolve.Dlopen, Name: "libbpf.so.1", Reason: "delivered by libbpf1_libs", Provider: "libbpf1_libs"})
	}
	return c, items
}

func reportOf(cuts ...func() (*check.Cut, []check.Item)) *check.Report {
	rep := &check.Report{Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{}}
	for _, f := range cuts {
		c, items := f()
		rep.Arches = append(rep.Arches, c.Arch)
		rep.Cuts[c.Key] = c
		rep.Items = append(rep.Items, items...)
	}
	return rep
}

func on(arch, triplet, version string, bpf bool) func() (*check.Cut, []check.Item) {
	return func() (*check.Cut, []check.Item) { return cutOn(arch, triplet, version, bpf) }
}

// Architectures fold on their trees: what they share is one block with the
// architecture normalised, and a line only some have is a block of those,
// under the lines above it as context. The text report is the same blocks
// with the findings alone, and --no-group every architecture with its own
// paths.
func TestBlocksFoldArches(t *testing.T) {
	rep := reportOf(
		on("amd64", "x86_64-linux-gnu", "1.0", true),
		on("arm64", "aarch64-linux-gnu", "1.0", true),
		on("armhf", "arm-linux-gnueabihf", "1.0", false),
	)
	for _, c := range []struct {
		name    string
		tree    bool
		noGroup bool
		want    string
	}{{name: "tree", tree: true, want: `a_b 1.0 [amd64, arm64, armhf]
/usr/bin/x (a_b): executable
└─ needed libc.so.6 -> /usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs)
   └─ ? strings libgcc_s.so.1
a_b 1.0 [amd64, arm64]
/usr/bin/x (a_b): executable
└─ needed libc.so.6 -> /usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs)
   └─ ? dlopen libbpf.so.1 (bpf, suggested) (libbpf1_libs)
`}, {name: "text", want: `a_b 1.0 [amd64, arm64, armhf]
/usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it
a_b 1.0 [amd64, arm64]
/usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs): info dlopen libbpf.so.1 (bpf, suggested): delivered by libbpf1_libs
`}, {name: "text, no group", noGroup: true, want: `a_b 1.0 [amd64]
/usr/lib/x86_64-linux-gnu/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it
/usr/lib/x86_64-linux-gnu/libc.so.6 (libc6_libs): info dlopen libbpf.so.1 (bpf, suggested): delivered by libbpf1_libs
a_b 1.0 [arm64]
/usr/lib/aarch64-linux-gnu/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it
/usr/lib/aarch64-linux-gnu/libc.so.6 (libc6_libs): info dlopen libbpf.so.1 (bpf, suggested): delivered by libbpf1_libs
a_b 1.0 [armhf]
/usr/lib/arm-linux-gnueabihf/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it
`}, {name: "tree, no group", tree: true, noGroup: true, want: `a_b 1.0 [amd64]
/usr/bin/x (a_b): executable
└─ needed libc.so.6 -> /usr/lib/x86_64-linux-gnu/libc.so.6 (libc6_libs)
   ├─ ? dlopen libbpf.so.1 (bpf, suggested) (libbpf1_libs)
   └─ ? strings libgcc_s.so.1
a_b 1.0 [arm64]
/usr/bin/x (a_b): executable
└─ needed libc.so.6 -> /usr/lib/aarch64-linux-gnu/libc.so.6 (libc6_libs)
   ├─ ? dlopen libbpf.so.1 (bpf, suggested) (libbpf1_libs)
   └─ ? strings libgcc_s.so.1
a_b 1.0 [armhf]
/usr/bin/x (a_b): executable
└─ needed libc.so.6 -> /usr/lib/arm-linux-gnueabihf/libc.so.6 (libc6_libs)
   └─ ? strings libgcc_s.so.1
`}} {
		var b bytes.Buffer
		if c.tree {
			renderTree(&b, rep, c.noGroup, nil, nil, style{})
		} else {
			renderText(&b, rep, c.noGroup, nil, nil, style{})
		}
		if b.String() != c.want {
			t.Errorf("%s: got\n%s\nwant\n%s", c.name, b.String(), c.want)
		}
	}
}

// A line a block holds only to carry what is under it is context: dim in
// the tree, and no line of the text report.
func TestBlocksContext(t *testing.T) {
	rep := reportOf(on("amd64", "x86_64-linux-gnu", "1.0", true), on("armhf", "arm-linux-gnueabihf", "1.0", false))
	bs := blocks(rep, false, nil, nil)
	if len(bs) != 2 || len(bs[1].Arches) != 1 || bs[1].Arches[0] != "amd64" {
		t.Fatalf("blocks: %+v", bs)
	}
	root := bs[1].Roots[0]
	if !root.context || !root.kids[0].context || root.kids[0].kids[0].context {
		t.Errorf("context: root %v, edge %v, dlopen %v", root.context, root.kids[0].context, root.kids[0].kids[0].context)
	}
	if got, want := root.painted(colours), colours.dim+"/usr/bin/x (a_b): executable"+colours.reset; got != want {
		t.Errorf("painted %q, want %q", got, want)
	}
	// One architecture alone keeps its own paths.
	if got, want := root.kids[0].plain(), "needed libc.so.6 -> /usr/lib/x86_64-linux-gnu/libc.so.6 (libc6_libs)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Architectures whose package is of another version do not fold, whatever
// their trees.
func TestBlocksSplitOnVersion(t *testing.T) {
	rep := reportOf(
		on("amd64", "x86_64-linux-gnu", "1.0", false),
		on("arm64", "aarch64-linux-gnu", "1.1", false),
		on("armhf", "arm-linux-gnueabihf", "1.0", false),
	)
	var b bytes.Buffer
	renderText(&b, rep, false, nil, nil, style{})
	want := `a_b 1.0 [amd64, armhf]
/usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it
a_b 1.1 [arm64]
/usr/lib/aarch64-linux-gnu/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

// Two lines saying the same under one parent are two lines, on every
// architecture.
func TestBlocksLineSaidTwice(t *testing.T) {
	rep := reportOf(on("amd64", "x86_64-linux-gnu", "1.0", false), on("arm64", "aarch64-linux-gnu", "1.0", false))
	for _, c := range rep.Cuts {
		c.Res.Open = append(c.Res.Open, c.Res.Open[0])
	}
	var b bytes.Buffer
	renderTree(&b, rep, false, nil, nil, style{})
	want := `a_b 1.0 [amd64, arm64]
/usr/bin/x (a_b): executable
└─ needed libc.so.6 -> /usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs)
   ├─ ? strings libgcc_s.so.1
   └─ ? strings libgcc_s.so.1
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

// A start node of a slice that is not named, reached by nothing, is drawn
// when something is wrong with it, and one of another named slice is left
// to that slice's block.
func TestBlocksUnreachedStart(t *testing.T) {
	c, items := cutOn("amd64", "x86_64-linux-gnu", "1.0", false)
	y := "/usr/bin/y"
	c.Owners[y] = []string{"other_bins"}
	c.FS.Nodes[y] = &rootfs.Node{Path: y, ELF: &elf.File{Interp: "/lib/ld.so"}}
	c.Res.Starts = append(c.Res.Starts, resolve.Start{Path: y, Kind: "exec"})
	c.Res.Findings = append(c.Res.Findings, resolve.Finding{Start: y, From: y, Kind: resolve.Needed, Name: "libq.so.1", Reason: "not found"})
	rep := &check.Report{Arches: []string{"amd64"}, Named: []string{"a_b"}, Cuts: map[check.Key]*check.Cut{c.Key: c}, Items: items}
	var b bytes.Buffer
	renderText(&b, rep, false, nil, nil, style{})
	want := `a_b 1.0 [amd64]
/usr/bin/y (other_bins): hard needed libq.so.1: not found
/usr/lib/x86_64-linux-gnu/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
	rep.Named = append(rep.Named, "other_bins")
	b.Reset()
	renderText(&b, rep, false, nil, nil, style{})
	if want := "a_b 1.0 [amd64]\n/usr/lib/x86_64-linux-gnu/libc.so.6 (libc6_libs): soft strings libgcc_s.so.1: no slice declares it\n"; b.String() != want {
		t.Errorf("named: got\n%s\nwant\n%s", b.String(), want)
	}
}

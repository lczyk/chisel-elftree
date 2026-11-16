package resolve

import (
	stdelf "debug/elf"
	"encoding/binary"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/lczyk/chisel-elftree/internal/elf"
	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

const tri = "aarch64-linux-gnu"

var arm64 = Arches["arm64"]

// tree builds an in-memory rootfs: parents are made as dirs.
type tree struct{ fs *rootfs.FS }

func newTree() *tree {
	t := &tree{fs: &rootfs.FS{Nodes: map[string]*rootfs.Node{"/": {Path: "/", Kind: rootfs.Dir}}}}
	t.link("/lib", "usr/lib")
	return t
}

func (t *tree) dirs(p string) {
	for d := path.Dir(p); d != "/"; d = path.Dir(d) {
		if _, ok := t.fs.Nodes[d]; !ok {
			t.fs.Nodes[d] = &rootfs.Node{Path: d, Kind: rootfs.Dir}
		}
	}
}

func (t *tree) link(p, target string) *tree {
	t.dirs(p)
	t.fs.Nodes[p] = &rootfs.Node{Path: p, Kind: rootfs.Symlink, Target: target}
	return t
}

func (t *tree) file(p string, mode fs.FileMode) *rootfs.Node {
	t.dirs(p)
	n := &rootfs.Node{Path: p, Kind: rootfs.File, Mode: mode}
	t.fs.Nodes[p] = n
	return n
}

func (t *tree) elf(p string, f *elf.File) *tree {
	if f.Machine == 0 {
		f.Machine, f.Class = stdelf.EM_AARCH64, stdelf.ELFCLASS64
	}
	if f.Data == nil {
		f.Data = binary.LittleEndian
	}
	f.Dynamic = true
	t.file(p, 0755).ELF = f
	return t
}

func exe(needed ...string) *elf.File {
	return &elf.File{Type: stdelf.ET_DYN, Flags1: elf.DF1PIE, Interp: "/lib/ld-linux-aarch64.so.1", Needed: needed}
}

func lib(soname string, needed ...string) *elf.File {
	return &elf.File{Type: stdelf.ET_DYN, Soname: soname, Needed: needed}
}

// base is a rootfs with a loader and libc.
func base() *tree {
	t := newTree()
	t.elf("/usr/lib/"+tri+"/ld-linux-aarch64.so.1", lib("ld-linux-aarch64.so.1"))
	t.link("/usr/lib/ld-linux-aarch64.so.1", tri+"/ld-linux-aarch64.so.1")
	t.elf("/usr/lib/"+tri+"/libc.so.6", lib("libc.so.6", "ld-linux-aarch64.so.1"))
	return t
}

func findings(r *Result, start string) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Start == start {
			out = append(out, f.Severity.String()+" "+f.Kind+" "+f.Name)
		}
	}
	slices.Sort(out)
	return out
}

func links(r *Result, start string) map[string]string {
	out := map[string]string{}
	for _, st := range r.Starts {
		if st.Path == start {
			for _, l := range st.Links {
				out[l.Kind+" "+l.Name] = l.To
			}
		}
	}
	return out
}

func TestNeededAndInterp(t *testing.T) {
	tr := base()
	tr.elf("/usr/bin/a", exe("libfoo.so.1", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1.2", lib("libfoo.so.1", "libbar.so.2", "libc.so.6"))
	tr.link("/usr/lib/"+tri+"/libfoo.so.1", "libfoo.so.1.2")
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard needed libbar.so.2"}) {
		t.Errorf("findings %q", got)
	}
	l := links(r, "/usr/bin/a")
	if l["interp /lib/ld-linux-aarch64.so.1"] != "/usr/lib/"+tri+"/ld-linux-aarch64.so.1" {
		t.Errorf("interp %q", l["interp /lib/ld-linux-aarch64.so.1"])
	}
	if l["needed libfoo.so.1"] != "/usr/lib/"+tri+"/libfoo.so.1.2" {
		t.Errorf("libfoo through its symlink: %q", l["needed libfoo.so.1"])
	}
}

func TestMissingInterp(t *testing.T) {
	tr := newTree()
	tr.elf("/usr/bin/a", exe())
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard interp /lib/ld-linux-aarch64.so.1"}) {
		t.Errorf("findings %q", got)
	}
}

// An rpath is inherited down the chain of the objects loading, a runpath
// is not, and an object with a runpath ignores every rpath.
func TestRpathRunpath(t *testing.T) {
	tr := base()
	e := exe("libmid.so.1", "libc.so.6")
	e.Rpath = []string{"$ORIGIN/../private"}
	tr.elf("/usr/bin/a", e)
	tr.elf("/usr/lib/"+tri+"/libmid.so.1", lib("libmid.so.1", "libpriv.so.1"))
	tr.elf("/usr/private/libpriv.so.1", lib("libpriv.so.1"))
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); len(got) != 0 {
		t.Errorf("rpath of the executable reaches libmid's need: %q", got)
	}

	tr = base()
	e = exe("libmid.so.1", "libc.so.6")
	e.Runpath = []string{"$ORIGIN/../private"}
	tr.elf("/usr/bin/a", e)
	tr.elf("/usr/lib/"+tri+"/libmid.so.1", lib("libmid.so.1", "libpriv.so.1"))
	tr.elf("/usr/private/libpriv.so.1", lib("libpriv.so.1"))
	r = Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard needed libpriv.so.1"}) {
		t.Errorf("a runpath is not inherited: %q", got)
	}

	tr = base()
	e = exe("libpriv.so.1", "libc.so.6")
	e.Rpath = []string{"/usr/private"}
	e.Runpath = []string{"/nowhere"}
	tr.elf("/usr/bin/a", e)
	tr.elf("/usr/private/libpriv.so.1", lib("libpriv.so.1"))
	r = Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard needed libpriv.so.1"}) {
		t.Errorf("a runpath turns the rpath off: %q", got)
	}
}

// A need is answered by an object already loaded under that soname, as
// the loader does, wherever it was loaded from.
func TestReuseBySoname(t *testing.T) {
	tr := base()
	e := exe("libpriv.so.1", "libmid.so.1", "libc.so.6")
	e.Runpath = []string{"/usr/private"}
	tr.elf("/usr/bin/a", e)
	tr.elf("/usr/private/libpriv.so.1", lib("libpriv.so.1"))
	tr.elf("/usr/lib/"+tri+"/libmid.so.1", lib("libmid.so.1", "libpriv.so.1"))
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); len(got) != 0 {
		t.Errorf("libmid's need is already loaded: %q", got)
	}
	// libmid on its own does not find it: a warning, since the cut has it
	// off the search path.
	if got := findings(r, "/usr/lib/"+tri+"/libmid.so.1"); !slices.Equal(got, []string{"warning needed libpriv.so.1"}) {
		t.Errorf("standalone: %q", got)
	}
}

func TestNoDefLibAndPIE(t *testing.T) {
	tr := base()
	e := exe("libc.so.6")
	e.Flags1 |= elf.DF1NoDefLib
	tr.elf("/usr/bin/a", e)
	tr.elf("/usr/bin/b", exe("libexe.so.1", "libc.so.6"))
	pie := exe()
	tr.elf("/usr/lib/"+tri+"/libexe.so.1", pie)
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard needed libc.so.6"}) {
		t.Errorf("nodeflib: %q", got)
	}
	if got := findings(r, "/usr/bin/b"); !slices.Equal(got, []string{"hard needed libexe.so.1"}) {
		t.Errorf("a PIE is not a library: %q", got)
	}
}

func TestWrongArchSkipped(t *testing.T) {
	tr := base()
	tr.elf("/usr/bin/a", exe("libfoo.so.1", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1", &elf.File{Type: stdelf.ET_DYN, Soname: "libfoo.so.1", Machine: stdelf.EM_X86_64, Class: stdelf.ELFCLASS64})
	tr.elf("/usr/lib/libfoo.so.1", lib("libfoo.so.1"))
	r := Check(tr.fs, arm64)
	if got := links(r, "/usr/bin/a")["needed libfoo.so.1"]; got != "/usr/lib/libfoo.so.1" {
		t.Errorf("the wrong machine is skipped, the search goes on: %q", got)
	}
	if !slices.Contains(r.Foreign, "/usr/lib/"+tri+"/libfoo.so.1") {
		t.Errorf("foreign %q", r.Foreign)
	}
}

func TestHwcaps(t *testing.T) {
	tr := base()
	tr.fs.Nodes["/usr/lib/"+tri+"/ld-linux-aarch64.so.1"].ELF.Machine = stdelf.EM_X86_64
	amd := Arches["amd64"]
	for _, n := range tr.fs.Nodes {
		if n.ELF != nil {
			n.ELF.Machine = stdelf.EM_X86_64
		}
	}
	e := exe("libz.so.1")
	e.Machine, e.Class = stdelf.EM_X86_64, stdelf.ELFCLASS64
	e.Interp = ""
	tr.elf("/usr/bin/a", e)
	z := lib("libz.so.1")
	z.Machine, z.Class = stdelf.EM_X86_64, stdelf.ELFCLASS64
	tr.elf("/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libz.so.1", z)
	r := Check(tr.fs, amd)
	if got := links(r, "/usr/bin/a")["needed libz.so.1"]; got != "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libz.so.1" {
		t.Errorf("hwcaps: %q", got)
	}
}

func TestConfDirOnly(t *testing.T) {
	tr := base()
	tr.elf("/usr/bin/a", exe("libfoo.so.1", "libc.so.6"))
	tr.elf("/usr/lib/foo/libfoo.so.1", lib("libfoo.so.1"))
	tr.file("/etc/ld.so.conf.d/foo.conf", 0644).Text = "# foo\n/usr/lib/foo\n"
	r := Check(tr.fs, arm64)
	var reason string
	for _, f := range r.Findings {
		if f.Start == "/usr/bin/a" {
			reason = f.Reason
		}
	}
	if !strings.Contains(reason, "ld.so.conf.d") {
		t.Errorf("reason %q", reason)
	}
}

func TestVersions(t *testing.T) {
	tr := base()
	e := exe("libc.so.6")
	e.Verneed = []elf.Verneed{{File: "libc.so.6", Versions: []elf.VersionReq{{Name: "GLIBC_2.17"}, {Name: "GLIBC_2.99"}, {Name: "GLIBC_9", Weak: true}}}}
	tr.elf("/usr/bin/a", e)
	tr.fs.Nodes["/usr/lib/"+tri+"/libc.so.6"].ELF.Verdef = []string{"libc.so.6", "GLIBC_2.17"}
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard version libc.so.6 GLIBC_2.99"}) {
		t.Errorf("findings %q", got)
	}
}

func TestShebang(t *testing.T) {
	tr := base()
	tr.file("/usr/bin/s1", 0755).Shebang = &rootfs.Shebang{Interp: "/usr/bin/perl"}
	tr.file("/usr/bin/s2", 0755).Shebang = &rootfs.Shebang{Interp: "/usr/bin/env", Arg: "python3"}
	tr.elf("/usr/bin/env", exe("libc.so.6"))
	tr.elf("/bin/sh", exe("libc.so.6"))
	tr.file("/usr/bin/s3", 0755).Shebang = &rootfs.Shebang{Interp: "/bin/sh"}
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/s1"); !slices.Equal(got, []string{"hard shebang /usr/bin/perl"}) {
		t.Errorf("s1 %q", got)
	}
	if got := findings(r, "/usr/bin/s2"); !slices.Equal(got, []string{"hard env python3"}) {
		t.Errorf("s2 %q", got)
	}
	if got := findings(r, "/usr/bin/s3"); len(got) != 0 {
		t.Errorf("s3 %q", got)
	}
}

func TestDlopen(t *testing.T) {
	tr := base()
	carrier := lib("libsd.so.0", "libc.so.6")
	carrier.Dlopen = []elf.DlopenEntry{
		{Feature: "zstd", Priority: "recommended", Soname: []string{"libzstd.so.2", "libzstd.so.1"}},
		{Feature: "tpm", Priority: "suggested", Soname: []string{"libtss2.so.0"}},
		{Feature: "kmod", Priority: "required", Soname: []string{"libkmod.so.2"}},
	}
	tr.elf("/usr/lib/"+tri+"/libsd.so.0", carrier)
	tr.elf("/usr/bin/a", exe("libsd.so.0", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libzstd.so.1", lib("libzstd.so.1", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libkmod.so.2", lib("libkmod.so.2", "liblzma.so.5"))
	r := Check(tr.fs, arm64)
	if got := links(r, "/usr/bin/a")["dlopen libzstd.so.1"]; got == "" {
		t.Errorf("the second alternative is taken: %v", links(r, "/usr/bin/a"))
	}
	var open []string
	for _, o := range r.Open {
		if o.Start == "/usr/bin/a" {
			open = append(open, o.Entry.Feature)
		}
	}
	if !slices.Equal(open, []string{"tpm"}) {
		t.Errorf("open %q", open)
	}
	// A required target in the cut whose own need is missing fails hard.
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard needed liblzma.so.5"}) {
		t.Errorf("findings %q", got)
	}
}

func TestForeignNotChecked(t *testing.T) {
	tr := base()
	tr.elf("/usr/share/go/testdata/freebsd-exec", &elf.File{Type: stdelf.ET_EXEC, Machine: stdelf.EM_386, Class: stdelf.ELFCLASS32, Interp: "/libexec/ld-elf.so.1"})
	tr.elf("/usr/lib/obj.o", &elf.File{Type: stdelf.ET_REL})
	r := Check(tr.fs, arm64)
	if len(r.Findings) != 0 {
		t.Errorf("findings %v", r.Findings)
	}
	if !slices.Equal(r.Foreign, []string{"/usr/lib/obj.o", "/usr/share/go/testdata/freebsd-exec"}) {
		t.Errorf("foreign %q", r.Foreign)
	}
}

func TestLookupSymlinks(t *testing.T) {
	tr := newTree()
	tr.file("/usr/lib/x", 0644)
	tr.link("/a", "/b")
	tr.link("/b", "/a")
	tr.link("/rel", "usr/../lib/x")
	if final, hops, err := tr.fs.Lookup("/lib/x"); err != nil || final != "/usr/lib/x" || len(hops) != 1 {
		t.Errorf("/lib/x: %q %v %v", final, hops, err)
	}
	if final, _, err := tr.fs.Lookup("/rel"); err != nil || final != "/usr/lib/x" {
		t.Errorf("/rel: %q %v", final, err)
	}
	if _, _, err := tr.fs.Lookup("/a"); err == nil || !strings.Contains(err.Error(), "too many levels") {
		t.Errorf("loop: %v", err)
	}
	if _, _, err := tr.fs.Lookup("/usr/lib/x/y"); err == nil {
		t.Error("a file is not a dir")
	}
}

func TestDanglingSymlinkWarns(t *testing.T) {
	tr := base()
	tr.link("/usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt")
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/lib/ssl/cert.pem"); !slices.Equal(got, []string{"warning symlink /etc/ssl/certs/ca-certificates.crt"}) {
		t.Errorf("findings %q", got)
	}
}

// A dlopen that fails unloads what it loaded: a later entry asking for the
// same library fails again, with its own priority.
func TestDlopenRollback(t *testing.T) {
	tr := base()
	carrier := lib("libsd.so.0", "libc.so.6")
	carrier.Dlopen = []elf.DlopenEntry{
		{Feature: "a", Priority: "suggested", Soname: []string{"libfoo.so.1"}},
		{Feature: "b", Priority: "required", Soname: []string{"libfoo.so.1"}},
	}
	tr.elf("/usr/lib/"+tri+"/libsd.so.0", carrier)
	tr.elf("/usr/bin/a", exe("libsd.so.0", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1", lib("libfoo.so.1", "libgone.so.1"))
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard needed libgone.so.1", "soft needed libgone.so.1"}) {
		t.Errorf("findings %q", got)
	}
}

// The loader stops at a file it cannot read as ELF.
func TestNonELFCandidateStops(t *testing.T) {
	tr := base()
	e := exe("libfoo.so.1", "libc.so.6")
	e.Runpath = []string{"/opt"}
	tr.elf("/usr/bin/a", e)
	tr.file("/opt/libfoo.so.1", 0644)
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1", lib("libfoo.so.1"))
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard needed libfoo.so.1"}) {
		t.Errorf("findings %q", got)
	}
}

func TestScriptChain(t *testing.T) {
	tr := base()
	tr.file("/usr/bin/inner", 0755).Shebang = &rootfs.Shebang{Interp: "/usr/bin/real"}
	tr.elf("/usr/bin/real", exe("libc.so.6"))
	tr.file("/usr/bin/outer", 0755).Shebang = &rootfs.Shebang{Interp: "/usr/bin/inner"}
	tr.file("/usr/bin/loop", 0755).Shebang = &rootfs.Shebang{Interp: "/usr/bin/loop"}
	tr.elf("/usr/bin/x86", &elf.File{Type: stdelf.ET_EXEC, Machine: stdelf.EM_X86_64, Class: stdelf.ELFCLASS64})
	tr.file("/usr/bin/s", 0755).Shebang = &rootfs.Shebang{Interp: "/usr/bin/x86"}
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/outer"); len(got) != 0 {
		t.Errorf("outer %q", got)
	}
	for _, st := range r.Starts {
		if st.Path == "/usr/bin/outer" && !slices.Equal(st.Exec, []string{"/usr/bin/inner", "/usr/bin/real"}) {
			t.Errorf("exec %q", st.Exec)
		}
	}
	if got := findings(r, "/usr/bin/loop"); !slices.Equal(got, []string{"hard shebang /usr/bin/loop"}) {
		t.Errorf("loop %q", got)
	}
	if got := findings(r, "/usr/bin/s"); !slices.Equal(got, []string{"hard shebang /usr/bin/x86"}) {
		t.Errorf("foreign interpreter %q", got)
	}
}

// An ET_DYN naming an interpreter without the PIE flag, as an older
// toolchain makes it, is an executable: its interpreter is checked.
func TestOldPIE(t *testing.T) {
	tr := newTree()
	tr.elf("/usr/bin/a", &elf.File{Type: stdelf.ET_DYN, Interp: "/lib/ld-linux-aarch64.so.1"})
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"hard interp /lib/ld-linux-aarch64.so.1"}) {
		t.Errorf("findings %q", got)
	}
}

func TestCheckLibraryStrict(t *testing.T) {
	tr := base()
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1", lib("libfoo.so.1", "libpriv.so.1"))
	tr.elf("/opt/libpriv.so.1", lib("libpriv.so.1"))
	f, reason := CheckLibrary(tr.fs, arm64, "/usr/lib/"+tri+"/libfoo.so.1")
	if reason != "" || len(f) != 1 || f[0].Name != "libpriv.so.1" {
		t.Errorf("a provider's need off the search path is hard: %v %q", f, reason)
	}
	x := lib("libbar.so.1")
	x.Machine, x.Class = stdelf.EM_X86_64, stdelf.ELFCLASS64
	tr.elf("/usr/lib/"+tri+"/libbar.so.1", x)
	if _, reason := CheckLibrary(tr.fs, arm64, "/usr/lib/"+tri+"/libbar.so.1"); !strings.Contains(reason, "not for arm64") {
		t.Errorf("wrong arch provider: %q", reason)
	}
}

// A failed alternative unloads and the next one is tried; only when none
// loads does the entry fail.
func TestDlopenAlternativeFallback(t *testing.T) {
	tr := base()
	carrier := lib("libsd.so.0", "libc.so.6")
	carrier.Dlopen = []elf.DlopenEntry{{Feature: "f", Priority: "required", Soname: []string{"libfoo.so.2", "libfoo.so.1"}}}
	tr.elf("/usr/lib/"+tri+"/libsd.so.0", carrier)
	tr.elf("/usr/bin/a", exe("libsd.so.0", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libfoo.so.2", lib("libfoo.so.2", "libgone.so.1"))
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1", lib("libfoo.so.1", "libc.so.6"))
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); len(got) != 0 {
		t.Errorf("findings %q", got)
	}
	if got := links(r, "/usr/bin/a")["dlopen libfoo.so.1"]; got == "" {
		t.Errorf("the second alternative loads: %v", links(r, "/usr/bin/a"))
	}
}

// A target the cut has but the loader refuses is a finding, not a lookup:
// the loader does not search past it.
func TestDlopenRefusedTarget(t *testing.T) {
	tr := base()
	carrier := lib("libsd.so.0", "libc.so.6")
	carrier.Dlopen = []elf.DlopenEntry{{Feature: "f", Priority: "suggested", Soname: []string{"libfoo.so.1"}}}
	tr.elf("/usr/lib/"+tri+"/libsd.so.0", carrier)
	tr.elf("/usr/bin/a", exe("libsd.so.0", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1", exe())
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"soft dlopen libfoo.so.1"}) {
		t.Errorf("findings %q", got)
	}
	for _, o := range r.Open {
		if o.Start == "/usr/bin/a" {
			t.Errorf("open %+v", o)
		}
	}
}

func TestSymlinkLoopHard(t *testing.T) {
	tr := base()
	tr.link("/usr/bin/x", "y")
	tr.link("/usr/bin/y", "x")
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/x"); !slices.Equal(got, []string{"hard symlink y"}) {
		t.Errorf("findings %q", got)
	}
}

func TestCheckProvider(t *testing.T) {
	tr := base()
	tr.elf("/usr/lib/"+tri+"/libfoo.so.1", lib("libfoo.so.1", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libbad.so.1", lib("libbad.so.1", "libgone.so.1"))
	sel, f, reason, err := CheckProvider(tr.fs, arm64, "libfoo.so.1")
	if err != nil || reason != "" || len(f) != 0 || sel != "/usr/lib/"+tri+"/libfoo.so.1" {
		t.Errorf("libfoo: %q %v %q %v", sel, f, reason, err)
	}
	if _, f, _, _ := CheckProvider(tr.fs, arm64, "libbad.so.1"); len(f) != 1 {
		t.Errorf("libbad: %v", f)
	}
	if _, _, reason, _ := CheckProvider(tr.fs, arm64, "libnone.so.1"); reason == "" {
		t.Error("libnone has a reason")
	}
	tr.file("/etc/ld.so.cache", 0644)
	if _, _, _, err := CheckProvider(tr.fs, arm64, "libfoo.so.1"); err == nil {
		t.Error("a cache is an error")
	}
}

// An entry with one alternative the cut has but cannot load and one it
// does not have is open for the absent one only, carrying the failure.
func TestDlopenOpenKeepsFailure(t *testing.T) {
	tr := base()
	carrier := lib("libsd.so.0", "libc.so.6")
	carrier.Dlopen = []elf.DlopenEntry{{Feature: "bpf", Priority: "suggested", Soname: []string{"libbpf.so.1", "libbpf.so.0"}}}
	tr.elf("/usr/lib/"+tri+"/libsd.so.0", carrier)
	tr.elf("/usr/bin/a", exe("libsd.so.0", "libc.so.6"))
	tr.elf("/usr/lib/"+tri+"/libbpf.so.1", lib("libbpf.so.1", "libelf.so.1"))
	r := Check(tr.fs, arm64)
	var open *Open
	for i := range r.Open {
		if r.Open[i].Start == "/usr/bin/a" {
			open = &r.Open[i]
		}
	}
	if open == nil || !slices.Equal(open.Absent, []string{"libbpf.so.0"}) || len(open.Failed) != 1 || open.Failed[0].Name != "libelf.so.1" {
		t.Fatalf("open %+v", open)
	}
	if got := findings(r, "/usr/bin/a"); len(got) != 0 {
		t.Errorf("the failure waits for the lookup: %q", got)
	}
}

func TestCwdRunpathWarns(t *testing.T) {
	tr := base()
	e := exe("libc.so.6")
	e.Runpath = []string{"", "lib", "/usr/lib/" + tri}
	tr.elf("/usr/bin/a", e)
	r := Check(tr.fs, arm64)
	if got := findings(r, "/usr/bin/a"); !slices.Equal(got, []string{"warning runpath ", "warning runpath lib"}) {
		t.Errorf("findings %q", got)
	}
}

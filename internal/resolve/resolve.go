// Package resolve models what glibc's dynamic loader and the kernel's exec
// would do with the files of a rootfs, without running any of them: from
// every start node (an executable, a library on its own, a script) the
// interpreter, the needed libraries breadth first with the objects already
// loaded reused, symbol versions and the dlopen metadata notes, each looked
// up inside the rootfs as the loader would look it up.
package resolve

import (
	stdelf "debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/lczyk/chisel-elftree/internal/elf"
	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

// Arch is what the loader of one architecture looks for.
type Arch struct {
	Name    string
	Triplet string
	Machine stdelf.Machine
	Class   stdelf.Class
	Little  bool
	// Hwcaps are the glibc-hwcaps subdirectories the loader knows, in its
	// order of priority, as `ld.so --help` lists them.
	Hwcaps []string
	// Loader is the soname of the arch's dynamic loader, as its PT_INTERP
	// names it.
	Loader string
}

// Arches is every architecture chisel cuts, as ubuntu 26.04's ld.so
// reports them. i386 has no container image to ask and follows the pattern.
var Arches = map[string]Arch{
	"amd64":   {"amd64", "x86_64-linux-gnu", stdelf.EM_X86_64, stdelf.ELFCLASS64, true, []string{"x86-64-v4", "x86-64-v3", "x86-64-v2"}, "ld-linux-x86-64.so.2"},
	"arm64":   {"arm64", "aarch64-linux-gnu", stdelf.EM_AARCH64, stdelf.ELFCLASS64, true, nil, "ld-linux-aarch64.so.1"},
	"armhf":   {"armhf", "arm-linux-gnueabihf", stdelf.EM_ARM, stdelf.ELFCLASS32, true, nil, "ld-linux-armhf.so.3"},
	"i386":    {"i386", "i386-linux-gnu", stdelf.EM_386, stdelf.ELFCLASS32, true, nil, "ld-linux.so.2"},
	"ppc64el": {"ppc64el", "powerpc64le-linux-gnu", stdelf.EM_PPC64, stdelf.ELFCLASS64, true, []string{"power10", "power9"}, "ld64.so.2"},
	"riscv64": {"riscv64", "riscv64-linux-gnu", stdelf.EM_RISCV, stdelf.ELFCLASS64, true, nil, "ld-linux-riscv64-lp64d.so.1"},
	"s390x":   {"s390x", "s390x-linux-gnu", stdelf.EM_S390, stdelf.ELFCLASS64, false, []string{"z17", "z16", "z15", "z14", "z13"}, "ld64.so.1"},
}

// DefaultDirs is the loader's system search path.
func (a Arch) DefaultDirs() []string {
	return []string{"/lib/" + a.Triplet, "/usr/lib/" + a.Triplet, "/lib", "/usr/lib"}
}

// Native reports whether this architecture's loader would take f.
func (a Arch) Native(f *elf.File) bool {
	little := f.Data == binary.LittleEndian
	return f.Machine == a.Machine && f.Class == a.Class && little == a.Little &&
		(f.OSABI == stdelf.ELFOSABI_NONE || f.OSABI == stdelf.ELFOSABI_LINUX)
}

// Severity says what a finding does to a verdict.
type Severity int

const (
	// Hard: the program does not start, or fails at the load it names.
	Hard Severity = iota
	// Soft: a dlopen target that is not in the cut; settled by lookup.
	Soft
	// Warning: the loader carries on.
	Warning
)

func (s Severity) String() string {
	return [...]string{"hard", "soft", "warning"}[s]
}

// Edge kinds.
const (
	Interp    = "interp"
	Needed    = "needed"
	Filter    = "filter"
	Auxiliary = "auxiliary"
	Preload   = "preload"
	Version   = "version"
	Shebang   = "shebang"
	Env       = "env"
	Dlopen    = "dlopen"
	Symlink   = "symlink"
)

// Finding is an edge that does not resolve, seen from a start node.
type Finding struct {
	Severity Severity
	Start    string   // the start node
	Chain    []string // the objects from the start node to From, both included
	From     string   // the file the edge leaves
	Kind     string
	Name     string // what was asked for
	Reason   string
	// Via is the dlopen edge whose target's load this finding is part of,
	// "" for the start node's own load.
	Via *Via
}

// Via names the dlopen note entry a load came from.
type Via struct {
	From     string
	Feature  string
	Priority string
	Soname   string
}

// Link is an edge that resolved.
type Link struct {
	From   string
	Kind   string
	Name   string
	To     string
	Hops   []rootfs.Hop
	Reused bool // the loader had it loaded already
	// Via is the dlopen edge whose load this link is part of, nil for the
	// start node's own load.
	Via *Via
	// Note is the dlopen note entry a dlopen link answers, nil for any
	// other kind.
	Note *Via
}

// Start is one start node and what loading it reached.
type Start struct {
	Path  string
	Kind  string // "exec", "lib", "script" or "symlink"
	Links []Link
	// Exec is what running or following the start node goes on to: a
	// script's interpreters (env and the command env runs), a symlink's
	// final target. Each is a start node of its own, so a failure there
	// is found there; Exec says whose failure it also is.
	Exec []string
}

// Open is a dlopen note entry none of whose sonames loads from the cut and
// some of which the cut does not have at all.
type Open struct {
	Start string
	Chain []string
	From  string
	Entry elf.DlopenEntry
	// Absent are the alternatives the cut does not have, for a slice
	// elsewhere to deliver.
	Absent []string
	// Failed is what the alternatives the cut has but cannot load left
	// behind: the entry's findings unless an absent one is delivered.
	Failed []Finding
	// Reasons per soname, why it was not taken.
	Reasons map[string]string
}

// Result is what checking a rootfs found.
type Result struct {
	Starts     []Start
	Findings   []Finding
	Open       []Open
	Foreign    []string // ELF files no loader of the arch takes, not checked
	Unreadable map[string]error
	// Unsupported says why the verdict cannot be trusted, "" when it can.
	Unsupported string
}

// Check resolves every start node of the rootfs.
func Check(fs *rootfs.FS, a Arch) *Result {
	c := newChecker(fs, a)
	for _, p := range c.paths {
		n := fs.Nodes[p]
		switch {
		case n.Kind == rootfs.Symlink:
			c.startSymlink(p)
		case n.Kind != rootfs.File:
		case n.ELFErr != nil:
			c.res.Unreadable[p] = n.ELFErr
		case n.ELF != nil:
			f := n.ELF
			if !a.Native(f) || (f.Type != stdelf.ET_EXEC && f.Type != stdelf.ET_DYN) {
				c.res.Foreign = append(c.res.Foreign, p)
				continue
			}
			switch {
			case f.Executable():
				c.startELF(p, f, "exec")
			case f.Library():
				c.startELF(p, f, "lib")
			}
		case n.Shebang != nil:
			c.startScript(p, n.Shebang)
		}
	}
	return c.res
}

// CheckLibrary resolves the library at p on its own, as a dlopen with no
// executable around it would, and returns its hard findings. ok is false
// when p is not a library the loader would take.
func CheckLibrary(fs *rootfs.FS, a Arch, p string) (findings []Finding, reason string) {
	c := newChecker(fs, a)
	if c.res.Unsupported != "" {
		return nil, c.res.Unsupported
	}
	// A provider has no executable around it that could have loaded a
	// private library first, so nothing off the search path counts.
	c.strict = true
	final, _, err := fs.Lookup(p)
	if err != nil {
		return nil, err.Error()
	}
	n := fs.Nodes[final]
	if n.Kind != rootfs.File || n.ELF == nil {
		return nil, final + " is not an ELF file"
	}
	if !a.Native(n.ELF) {
		return nil, final + " is not for " + a.Name
	}
	if why := c.loadable(n.ELF, true); why != "" {
		return nil, final + " " + why
	}
	c.startELF(final, n.ELF, "lib")
	for _, f := range c.res.Findings {
		if f.Severity == Hard {
			findings = append(findings, f)
		}
	}
	return findings, ""
}

// CheckProvider resolves a dlopen of name in fs as a caller with no rpath
// or runpath would, the way a slice elsewhere in the release would serve
// it, and checks the library selected on its own, strictly. err is a cut
// the verdict cannot be trusted for: an ld.so.cache, an unreadable ELF.
func CheckProvider(fs *rootfs.FS, a Arch, name string) (selected string, findings []Finding, reason string, err error) {
	c := newChecker(fs, a)
	if c.res.Unsupported != "" {
		return "", nil, "", errors.New(c.res.Unsupported)
	}
	c.strict = true
	r := c.search(&obj{path: "/", f: &elf.File{}}, name, true)
	if c.unreadable {
		return "", nil, "", errors.New(r.reason)
	}
	if r.path == "" {
		return "", nil, r.reason, nil
	}
	c.startELF(r.path, r.f, "lib")
	if c.unreadable {
		return r.path, nil, "", errors.New("an ELF file in the closure of " + r.path + " cannot be read")
	}
	for _, f := range c.res.Findings {
		if f.Severity == Hard {
			findings = append(findings, f)
		}
	}
	return r.path, findings, "", nil
}

type checker struct {
	fs       *rootfs.FS
	paths    []string // every path of fs, sorted
	a        Arch
	res      *Result
	confDirs []string
	preload  []string
	strict   bool // a need found only off the search path stays hard
	// unreadable: the search met an ELF file the reader could not read.
	unreadable bool
}

func newChecker(fs *rootfs.FS, a Arch) *checker {
	c := &checker{fs: fs, paths: sortedPaths(fs), a: a, res: &Result{Unreadable: map[string]error{}}}
	if _, ok := fs.Nodes["/etc/ld.so.cache"]; ok {
		c.res.Unsupported = "the cut has /etc/ld.so.cache, which is not read"
	}
	for _, p := range c.paths {
		n := fs.Nodes[p]
		if p == "/etc/ld.so.conf" || strings.HasPrefix(p, "/etc/ld.so.conf.d/") {
			for _, line := range strings.Split(n.Text, "\n") {
				line, _, _ = strings.Cut(line, "#")
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "/") {
					c.confDirs = append(c.confDirs, line)
				}
			}
		}
	}
	if n := fs.Nodes["/etc/ld.so.preload"]; n != nil && n.Kind == rootfs.Symlink {
		c.res.Unsupported = "the cut's /etc/ld.so.preload is a symlink, which is not followed"
	} else if n != nil {
		c.preload = strings.FieldsFunc(n.Text, func(r rune) bool { return r == ':' || r == ' ' || r == '\t' || r == '\n' })
	}
	return c
}

func sortedPaths(fs *rootfs.FS) []string {
	out := make([]string, 0, len(fs.Nodes))
	for p := range fs.Nodes {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// obj is an object loaded for a start node; parent is the object whose
// need loaded it, which is what the rpath chain follows.
type obj struct {
	path   string
	f      *elf.File
	parent *obj
}

func (o *obj) chain() []string {
	var out []string
	for ; o != nil; o = o.parent {
		out = append(out, o.path)
	}
	slices.Reverse(out)
	return out
}

// load is one start node's loader state.
type load struct {
	c      *checker
	st     *Start
	byName map[string]*obj
	order  []*obj
}

func (l *load) register(o *obj, names ...string) {
	for _, n := range append(names, o.path, o.f.Soname) {
		if n != "" {
			if _, ok := l.byName[n]; !ok {
				l.byName[n] = o
			}
		}
	}
	l.order = append(l.order, o)
}

func (c *checker) startELF(p string, f *elf.File, kind string) {
	c.res.Starts = append(c.res.Starts, Start{Path: p, Kind: kind})
	st := &c.res.Starts[len(c.res.Starts)-1]
	l := &load{c: c, st: st, byName: map[string]*obj{}}
	root := &obj{path: p, f: f}
	l.register(root)
	if !f.Dynamic {
		return
	}
	if kind == "exec" && f.Interp != "" {
		c.interp(l, root)
	}
	var queue []*obj
	if kind == "exec" {
		for _, name := range c.preload {
			if o := l.need(root, name, Preload, Warning, nil); o != nil {
				queue = append(queue, o)
			}
		}
	}
	queue = append(queue, root)
	l.closure(queue, nil)
	l.versions(nil)
	l.dlopen()
}

func (c *checker) interp(l *load, root *obj) {
	f := root.f
	final, hops, err := c.fs.Lookup(f.Interp)
	if err != nil {
		l.find(Hard, root, Interp, f.Interp, err.Error(), nil)
		return
	}
	n := c.fs.Nodes[final]
	if n.Kind != rootfs.File || n.ELF == nil || !c.a.Native(n.ELF) {
		l.find(Hard, root, Interp, f.Interp, final+" is not an ELF file for "+c.a.Name, nil)
		return
	}
	l.st.Links = append(l.st.Links, Link{From: root.path, Kind: Interp, Name: f.Interp, To: final, Hops: hops})
	l.register(&obj{path: final, f: n.ELF, parent: root}, f.Interp)
}

// closure loads the needs of the queued objects breadth first, as glibc's
// dl-deps.c does. via is the dlopen edge this load is part of, if any.
func (l *load) closure(queue []*obj, via *Via) {
	sev := Hard
	if via != nil && via.Priority != "required" {
		sev = Soft
	}
	for len(queue) > 0 {
		o := queue[0]
		queue = queue[1:]
		l.cwdPath(o, via)
		for _, name := range o.f.Needed {
			if n := l.need(o, name, Needed, sev, via); n != nil {
				queue = append(queue, n)
			}
		}
		for _, name := range o.f.Filter {
			if n := l.need(o, name, Filter, sev, via); n != nil {
				queue = append(queue, n)
			}
		}
		for _, name := range o.f.Auxiliary {
			if n := l.need(o, name, Auxiliary, Warning, via); n != nil {
				queue = append(queue, n)
			}
		}
	}
}

// cwdPath warns about an element of o's search path, the runpath when it
// has one else the rpath, that the loader reads against the cwd: empty or
// relative. It works when the cwd happens to be right, which is the risk.
func (l *load) cwdPath(o *obj, via *Via) {
	tag, elems := "rpath", o.f.Rpath
	if o.f.Runpath != nil {
		tag, elems = "runpath", o.f.Runpath
	}
	for _, d := range elems {
		exp, err := l.c.expand(d, o)
		if err == nil && strings.HasPrefix(exp, "/") {
			continue
		}
		reason := "an element the loader reads against the cwd"
		if err != nil {
			reason = err.Error()
		}
		l.find(Warning, o, tag, d, reason, via)
	}
}

// need resolves name for o: an object already loaded under that name, else
// a search. It returns a newly loaded object, to have its own needs loaded.
func (l *load) need(o *obj, name, kind string, sev Severity, via *Via) *obj {
	if have, ok := l.byName[name]; ok {
		l.st.Links = append(l.st.Links, Link{From: o.path, Kind: kind, Name: name, To: have.path, Reused: true, Via: via})
		return nil
	}
	r := l.c.search(o, name, false)
	if r.path == "" {
		// A library on its own has no executable to have loaded what it
		// needs from a private dir; there, that is the caller's to do.
		if r.elsewhere && l.st.Kind == "lib" && sev == Hard && !l.c.strict {
			sev = Warning
		}
		l.find(sev, o, kind, name, r.reason, via)
		return nil
	}
	l.st.Links = append(l.st.Links, Link{From: o.path, Kind: kind, Name: name, To: r.path, Hops: r.hops, Via: via})
	n := &obj{path: r.path, f: r.f, parent: o}
	l.register(n, name)
	return n
}

func (l *load) find(sev Severity, o *obj, kind, name, reason string, via *Via) {
	l.c.res.Findings = append(l.c.res.Findings, Finding{
		Severity: sev, Start: l.st.Path, Chain: o.chain(), From: o.path,
		Kind: kind, Name: name, Reason: reason, Via: via,
	})
}

// versions checks the symbol versions every loaded object needs of the
// objects loaded, as glibc's dl-version.c does.
func (l *load) versions(via *Via) {
	sev := Hard
	if via != nil && via.Priority != "required" {
		sev = Soft
	}
	for _, o := range l.order {
		for _, vn := range o.f.Verneed {
			p, ok := l.byName[vn.File]
			if !ok {
				continue
			}
			if len(p.f.Verdef) == 0 {
				l.find(Warning, o, Version, vn.File, "no version information available", via)
				continue
			}
			for _, v := range vn.Versions {
				if v.Weak || slices.Contains(p.f.Verdef, v.Name) {
					continue
				}
				l.find(sev, o, Version, vn.File+" "+v.Name, "version not found in "+p.path, via)
			}
		}
	}
}

// dlopen resolves the dlopen notes of every object loaded, in the start
// node's context, the object carrying the note as the one asking. A target
// in the cut is loaded with its needs; one that is not is left open for
// the provider lookup.
func (l *load) dlopen() {
	for i := 0; i < len(l.order); i++ {
		o := l.order[i]
		entries := o.f.Dlopen
		// A library name among the file's strings may be a dlopen with no
		// note: an entry of its own, below every note's.
		for _, s := range o.f.Strings {
			entries = append(slices.Clip(entries), elf.DlopenEntry{Priority: elf.PriorityStrings, Soname: []string{s}})
		}
		for _, e := range entries {
			reasons := map[string]string{}
			// failed holds what the alternatives found but not loadable
			// left behind: the loader tries the next, and only when none
			// loads are these the entry's findings.
			var failed []Finding
			var absent []string
			done := false
			for _, s := range e.Soname {
				via := &Via{From: o.path, Feature: e.Feature, Priority: e.Priority, Soname: s}
				if have, ok := l.byName[s]; ok {
					l.st.Links = append(l.st.Links, Link{From: o.path, Kind: Dlopen, Name: s, To: have.path, Reused: true, Note: via})
					done = true
					break
				}
				r := l.c.search(o, s, true)
				if r.path == "" {
					if r.fatal {
						failed = append(failed, Finding{Severity: prioritySeverity(e.Priority), Start: l.st.Path, Chain: o.chain(),
							From: o.path, Kind: Dlopen, Name: s, Reason: r.reason, Via: via})
					} else {
						absent = append(absent, s)
					}
					reasons[s] = r.reason
					continue
				}
				links, mark, fmark := len(l.st.Links), len(l.order), len(l.c.res.Findings)
				l.st.Links = append(l.st.Links, Link{From: o.path, Kind: Dlopen, Name: s, To: r.path, Hops: r.hops, Note: via})
				l.register(&obj{path: r.path, f: r.f, parent: o}, s)
				l.closure([]*obj{l.order[mark]}, via)
				l.versionsFrom(mark, via)
				if l.failedSince(fmark) {
					// A dlopen that fails unloads what it loaded, so a later
					// entry asking for the same library loads it again and
					// fails again, with its own priority.
					failed = append(failed, l.c.res.Findings[fmark:]...)
					l.c.res.Findings = l.c.res.Findings[:fmark]
					l.st.Links = l.st.Links[:links]
					l.rollback(mark)
					reasons[s] = "found at " + r.path + ", which does not load"
					continue
				}
				done = true
				break
			}
			switch {
			case done:
			case len(absent) > 0:
				// A slice elsewhere may still deliver an alternative the
				// cut does not have.
				l.c.res.Open = append(l.c.res.Open, Open{Start: l.st.Path, Chain: o.chain(), From: o.path, Entry: e,
					Absent: absent, Failed: failed, Reasons: reasons})
			default:
				l.c.res.Findings = append(l.c.res.Findings, failed...)
			}
		}
	}
}

func prioritySeverity(priority string) Severity {
	if priority == elf.PriorityStrings {
		return Warning
	}
	if priority == "required" {
		return Hard
	}
	return Soft
}

// failedSince reports whether a finding that fails a load was made since
// the first n findings.
func (l *load) failedSince(n int) bool {
	for _, f := range l.c.res.Findings[n:] {
		if f.Severity != Warning {
			return true
		}
	}
	return false
}

// rollback unloads the objects loaded since order[mark].
func (l *load) rollback(mark int) {
	gone := l.order[mark:]
	for name, o := range l.byName {
		if slices.Contains(gone, o) {
			delete(l.byName, name)
		}
	}
	l.order = l.order[:mark]
}

// versionsFrom checks versions for the objects loaded since order[mark].
func (l *load) versionsFrom(mark int, via *Via) {
	all := l.order
	l.order = all[mark:]
	l.versions(via)
	l.order = all
}

type found struct {
	path   string
	f      *elf.File
	hops   []rootfs.Hop
	reason string
	// elsewhere: not on the search path, but the cut has a loadable file
	// of that name, which an object loaded before would have provided.
	elsewhere bool
	// fatal: the search stopped at a file the loader refuses.
	fatal bool
}

// search looks name up for o as the loader would: a path as it is, else
// o's rpath chain (only when o has no runpath), o's runpath, then the
// default dirs (unless o says nodeflib), each with its glibc-hwcaps
// subdirectories first.
func (c *checker) search(o *obj, name string, dlopen bool) found {
	exp, err := c.expand(name, o)
	if err != nil {
		return found{reason: err.Error()}
	}
	if strings.Contains(exp, "/") {
		if !strings.HasPrefix(exp, "/") {
			return found{reason: "a relative path, which depends on the cwd"}
		}
		r, fatal := c.try(exp, dlopen)
		if r.path != "" || fatal {
			r.fatal = fatal
			return r
		}
		return found{reason: exp + " does not exist"}
	}
	var dirs []string
	var notes []string
	if o.f.Runpath == nil {
		for a := o; a != nil; a = a.parent {
			if a.f.Runpath != nil {
				continue
			}
			for _, d := range a.f.Rpath {
				dirs = append(dirs, c.dir(d, a, &notes)...)
			}
		}
	}
	for _, d := range o.f.Runpath {
		dirs = append(dirs, c.dir(d, o, &notes)...)
	}
	if o.f.Flags1&elf.DF1NoDefLib == 0 {
		dirs = append(dirs, c.a.DefaultDirs()...)
	}
	var skipped []string
	for _, d := range dirs {
		for _, cand := range c.candidates(d, name) {
			r, fatal := c.try(cand, dlopen)
			if r.path != "" || fatal {
				r.fatal = fatal
				return r
			}
			if r.reason != "" {
				skipped = append(skipped, r.reason)
			}
		}
	}
	reason := "not found"
	for _, d := range c.confDirs {
		if r, _ := c.try(path.Join(d, name), dlopen); r.path != "" {
			reason = "only reachable through ld.so.conf.d, and there is no ld.so.cache"
			break
		}
	}
	elsewhere := ""
	if reason == "not found" {
		elsewhere = c.byName(name, dlopen)
		if elsewhere != "" {
			reason = "not on the search path, only at " + elsewhere
		}
	}
	notes = append(notes, skipped...)
	if len(notes) > 0 {
		reason += " (" + strings.Join(notes, "; ") + ")"
	}
	return found{reason: reason, elsewhere: elsewhere != ""}
}

// byName is a loadable library of the cut whose file name or soname is
// name, off the search path, "" when there is none.
func (c *checker) byName(name string, dlopen bool) string {
	for _, p := range c.paths {
		n := c.fs.Nodes[p]
		if n.Kind != rootfs.File || n.ELF == nil || !c.a.Native(n.ELF) || c.loadable(n.ELF, dlopen) != "" {
			continue
		}
		if path.Base(p) == name || n.ELF.Soname == name {
			return p
		}
	}
	return ""
}

func (c *checker) candidates(dir, name string) []string {
	var out []string
	for _, h := range c.a.Hwcaps {
		out = append(out, path.Join(dir, "glibc-hwcaps", h, name))
	}
	return append(out, path.Join(dir, name))
}

// dir expands one rpath or runpath element of a; an element the loader
// would read against the cwd is noted and not searched.
func (c *checker) dir(d string, a *obj, notes *[]string) []string {
	if d == "" {
		*notes = append(*notes, "an empty path element in "+a.path+" means the cwd")
		return nil
	}
	exp, err := c.expand(d, a)
	if err != nil {
		*notes = append(*notes, err.Error())
		return nil
	}
	if !strings.HasPrefix(exp, "/") {
		*notes = append(*notes, "a relative path element "+d+" in "+a.path+" means the cwd")
		return nil
	}
	return []string{exp}
}

func (c *checker) expand(s string, o *obj) (string, error) {
	if !strings.Contains(s, "$") {
		return s, nil
	}
	r := strings.NewReplacer(
		"${ORIGIN}", path.Dir(o.path), "$ORIGIN", path.Dir(o.path),
		"${LIB}", "lib/"+c.a.Triplet, "$LIB", "lib/"+c.a.Triplet,
	)
	out := r.Replace(s)
	if strings.Contains(out, "$") {
		return "", fmt.Errorf("%s uses a token that is not modelled", s)
	}
	return out, nil
}

// try reports whether p is a library the loader takes. A file of another
// class or machine is skipped, as the loader skips it; fatal is a file the
// loader stops at with an error.
func (c *checker) try(p string, dlopen bool) (r found, fatal bool) {
	final, hops, err := c.fs.Lookup(p)
	if err != nil {
		return found{}, false
	}
	n := c.fs.Nodes[final]
	if n.Kind != rootfs.File {
		return found{}, false
	}
	if n.ELFErr != nil {
		c.unreadable = true
		return found{reason: final + " cannot be read: " + n.ELFErr.Error()}, true
	}
	if n.ELF == nil {
		// The loader stops at a file it cannot read as ELF, with
		// "invalid ELF header", rather than search on.
		return found{reason: final + " is not an ELF file"}, true
	}
	if !c.a.Native(n.ELF) {
		return found{reason: final + " is not for " + c.a.Name}, false
	}
	if why := c.loadable(n.ELF, dlopen); why != "" {
		return found{reason: final + " " + why}, true
	}
	return found{path: final, f: n.ELF, hops: hops}, false
}

// loadable says why the loader refuses to load f as a library, "" when it
// does not.
func (c *checker) loadable(f *elf.File, dlopen bool) string {
	switch {
	case f.Type == stdelf.ET_EXEC:
		return "is an executable, not a library"
	case f.Type != stdelf.ET_DYN:
		return "is not a shared object"
	case f.PIE():
		return "is a position-independent executable, which cannot be loaded"
	case !f.Dynamic:
		return "has no dynamic section"
	case dlopen && f.Flags1&elf.DF1NoOpen != 0:
		return "is marked not to be opened"
	}
	return ""
}

// maxInterp is how many interpreters deep the kernel follows #! lines.
const maxInterp = 4

func (c *checker) startScript(p string, sb *rootfs.Shebang) {
	c.res.Starts = append(c.res.Starts, Start{Path: p, Kind: "script"})
	st := &c.res.Starts[len(c.res.Starts)-1]
	l := &load{c: c, st: st, byName: map[string]*obj{}}
	self := &obj{path: p, f: &elf.File{}}
	if _, reason := c.interpreter(st, p, sb, 1); reason != "" {
		l.find(Hard, self, Shebang, sb.Interp, reason, nil)
		return
	}
	if path.Base(sb.Interp) != "env" {
		return
	}
	cmd := envCommand(sb.Arg)
	if cmd == "" {
		return
	}
	if strings.Contains(cmd, "/") {
		l.find(Warning, self, Env, cmd, "env with a path is not followed", nil)
		return
	}
	for _, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		final, hops, err := c.fs.Lookup(path.Join(d, cmd))
		if err != nil {
			continue
		}
		n := c.fs.Nodes[final]
		if n.Kind != rootfs.File || n.Mode&0111 == 0 {
			continue
		}
		st.Links = append(st.Links, Link{From: p, Kind: Env, Name: cmd, To: final, Hops: hops})
		st.Exec = append(st.Exec, final)
		if why := c.runnable(n); why != "" {
			l.find(Hard, self, Env, cmd, final+" "+why, nil)
		}
		return
	}
	l.find(Hard, self, Env, cmd, "not found on the default PATH", nil)
}

// interpreter follows a #! line to what the kernel runs: a native ELF
// executable, through up to maxInterp scripts, each hop recorded. It
// returns why the kernel would not run it, "" when it would.
func (c *checker) interpreter(st *Start, from string, sb *rootfs.Shebang, depth int) (string, string) {
	if sb.Interp == "" {
		return "", "an empty #! line"
	}
	if !strings.HasPrefix(sb.Interp, "/") {
		return "", "a relative interpreter, which depends on the cwd"
	}
	final, hops, err := c.fs.Lookup(sb.Interp)
	if err != nil {
		return "", err.Error()
	}
	st.Links = append(st.Links, Link{From: from, Kind: Shebang, Name: sb.Interp, To: final, Hops: hops})
	st.Exec = append(st.Exec, final)
	n := c.fs.Nodes[final]
	if why := c.runnable(n); why != "" {
		return final, final + " " + why
	}
	if n.Shebang != nil {
		if depth >= maxInterp {
			return final, "more than " + fmt.Sprint(maxInterp) + " levels of interpreters"
		}
		return c.interpreter(st, final, n.Shebang, depth+1)
	}
	return final, ""
}

// runnable says why the kernel would not run n, "" when it would: a regular
// file with an execute bit that is a native ELF executable or a script.
func (c *checker) runnable(n *rootfs.Node) string {
	switch {
	case n.Kind != rootfs.File:
		return "is not a regular file"
	case n.Mode&0111 == 0:
		return "is not executable"
	case n.Shebang != nil:
		return ""
	case n.ELF == nil:
		return "is neither an ELF file nor a script"
	case !c.a.Native(n.ELF):
		return "is not for " + c.a.Name
	case n.ELF.Type != stdelf.ET_EXEC && n.ELF.Type != stdelf.ET_DYN:
		return "is not an executable"
	}
	return ""
}

// startSymlink follows a symlink of the cut. One that leads nowhere is a
// warning, since a slice may ship a link another slice completes; one that
// leads to a start node passes on whose failure that start node's is.
func (c *checker) startSymlink(p string) {
	c.res.Starts = append(c.res.Starts, Start{Path: p, Kind: "symlink"})
	st := &c.res.Starts[len(c.res.Starts)-1]
	target := c.fs.Nodes[p].Target
	final, hops, err := c.fs.Lookup(p)
	if err != nil {
		sev := Warning
		if errors.Is(err, rootfs.ErrLoop) {
			sev = Hard
		}
		l := &load{c: c, st: st, byName: map[string]*obj{}}
		l.find(sev, &obj{path: p, f: &elf.File{}}, Symlink, target, err.Error(), nil)
		return
	}
	st.Links = append(st.Links, Link{From: p, Kind: Symlink, Name: target, To: final, Hops: hops})
	st.Exec = []string{final}
}

// envCommand is the command an env shebang runs: the first word of its
// argument that is not an option or a variable assignment. -S splits the
// rest into words, which is what a single argument already is here.
func envCommand(arg string) string {
	for _, w := range strings.Fields(arg) {
		if strings.HasPrefix(w, "-") || strings.Contains(w, "=") {
			continue
		}
		return w
	}
	return ""
}

package cli

import (
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/lczyk/chisel-coverage/pkg/fold"

	"github.com/lczyk/chisel-elftree/internal/check"
	"github.com/lczyk/chisel-elftree/internal/elf"
	"github.com/lczyk/chisel-elftree/internal/glob"
	"github.com/lczyk/chisel-elftree/internal/resolve"
	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

// style colours the text and tree reports. The zero value colours nothing.
type style struct {
	name, dim, red, yellow, dlopen, reset string
}

// colours is the style for a terminal: a little, not a lot.
var colours = style{name: "\x1b[1;34m", dim: "\x1b[2m", red: "\x1b[31m", yellow: "\x1b[33m", dlopen: "\x1b[36m", reset: "\x1b[0m"}

// styleFor picks colours when w is a terminal and NO_COLOR is unset or empty
// (https://no-color.org), else nothing.
func styleFor(w io.Writer) style {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return style{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return style{}
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return style{}
	}
	return colours
}

func (s style) wrap(code, text string) string {
	if code == "" || text == "" {
		return text
	}
	return code + text + s.reset
}

// sev paints text by a severity: red hard, yellow soft or warning, dim info.
func (s style) sev(sev check.Severity, text string) string {
	switch sev {
	case check.Hard:
		return s.wrap(s.red, text)
	case check.Soft, check.Warning:
		return s.wrap(s.yellow, text)
	}
	return s.wrap(s.dim, text)
}

// header is a block's first line: "<slice> <version> [<arches>]".
func (s style) header(slice, version string, arches []string) string {
	return s.wrap(s.name, slice) + version + " " + s.wrap(s.dim, "["+strings.Join(arches, ", ")+"]")
}

// line is an item as the text report prints it, "<path> (<owner>):
// <severity> <kind> <name>: <reason>", with the architecture normalised
// unless raw.
func line(it check.Item, raw bool) string {
	if !raw {
		return fold.Normalise(line(it, true), it.Arch)
	}
	p := it.Path
	if it.Owner != "" {
		p += " (" + it.Owner + ")"
	}
	name := it.Name
	if it.Feature != "" {
		name += " (" + it.Feature + ", " + it.Priority + ")"
	}
	return fmt.Sprintf("%s: %s %s %s: %s", p, it.Severity, it.Kind, name, it.Reason)
}

// renderText prints one block per (slice counted against, arches that
// agree), the not-available ones after. Nothing is indented, so the report
// greps: grep ': hard ' is what does not run.
func renderText(w io.Writer, rep *check.Report, noGroup bool, prune []string, st style) {
	var blocks []string
	byAgainst := map[string][]check.Item{}
	for _, it := range rep.Items {
		if it.Severity == check.Info && (pruned(prune, it.Arch, "", it.Path) || prunedAny(prune, it.Arch, strings.Split(it.Name, " or "))) {
			continue
		}
		k := it.Against
		if !it.Named {
			k += " reached via " + it.Reached
		}
		if _, ok := byAgainst[k]; !ok {
			blocks = append(blocks, k)
		}
		byAgainst[k] = append(byAgainst[k], it)
	}
	for _, b := range blocks {
		items := make([][]fold.Item, len(rep.Arches))
		for _, it := range byAgainst[b] {
			ai := slices.Index(rep.Arches, it.Arch)
			items[ai] = append(items[ai], fold.Item{Key: line(it, false), Tag: it.Sev, Raw: line(it, true)})
		}
		slice, rest, _ := strings.Cut(b, " ")
		via := ""
		if r, ok := strings.CutPrefix(rest, "reached via "); ok {
			via = " " + st.wrap(st.dim, "reached via") + " " + r
		}
		groups := fold.Fold(rep.Arches, items)
		if noGroup {
			groups = nil
			for ai, a := range rep.Arches {
				if len(items[ai]) == 0 {
					continue
				}
				g := fold.Group{Arches: []string{a}}
				for _, it := range items[ai] {
					g.Entries = append(g.Entries, fold.Entry{Key: it.Raw, Tag: it.Tag, Raw: []string{it.Raw}})
				}
				slices.SortFunc(g.Entries, func(x, y fold.Entry) int { return strings.Compare(x.Key, y.Key) })
				groups = append(groups, g)
			}
		}
		for _, g := range groups {
			slices.SortStableFunc(g.Entries, func(x, y fold.Entry) int { return int(severity(x.Tag)) - int(severity(y.Tag)) })
			fmt.Fprintln(w, st.header(slice, pkgVersion(rep, slice, g.Arches[0]), g.Arches)+via)
			for _, e := range g.Entries {
				text := e.Shown()
				if len(g.Arches) == 1 {
					text = e.Raw[0]
				}
				fmt.Fprintln(w, st.sev(severity(e.Tag), text))
			}
		}
	}
	notes(w, rep, st)
}

// notes tells, per named slice, the arches it is not available on and those
// where --file matched none of its files.
func notes(w io.Writer, rep *check.Report, st style) {
	for _, s := range rep.Named {
		var na, nf []string
		for _, a := range rep.Arches {
			c := rep.Cuts[check.Key{Slice: s, Arch: a}]
			switch {
			case c == nil:
			case !c.Available:
				na = append(na, a)
			case c.NoFile:
				nf = append(nf, a)
			}
		}
		for _, n := range []struct {
			arches []string
			say    string
		}{{na, "not available"}, {nf, "no file matches"}} {
			if len(n.arches) > 0 {
				fmt.Fprintf(w, "%s %s: %s\n", st.wrap(st.name, s), st.wrap(st.dim, "["+strings.Join(n.arches, ", ")+"]"), st.wrap(st.yellow, n.say))
			}
		}
	}
}

// loaderToken is the --prune value for the arch's dynamic loader, whatever
// it is called there.
const loaderToken = "@ld"

// pruned reports whether --prune leaves out, on arch, the library named name
// at path, either "" when not known: a glob with a slash matches the path,
// one without matches the name or the path's last element, and @ld the
// arch's loader by its soname.
func pruned(prune []string, arch, name, file string) bool {
	for _, g := range prune {
		if g == loaderToken {
			ld := resolve.Arches[arch].Loader
			if ld != "" && (name == ld || path.Base(name) == ld || file != "" && path.Base(file) == ld) {
				return true
			}
			continue
		}
		if file != "" && glob.File(g, file) || name != "" && !strings.Contains(g, "/") && glob.Match(g, name) {
			return true
		}
	}
	return false
}

func prunedAny(prune []string, arch string, names []string) bool {
	for _, n := range names {
		if pruned(prune, arch, n, "") {
			return true
		}
	}
	return false
}

func severity(name string) check.Severity {
	for _, s := range []check.Severity{check.Hard, check.Soft, check.Warning, check.Info} {
		if s.String() == name {
			return s
		}
	}
	return check.Info
}

// pkgVersion is the version of slice's package as the cuts on arch fetched
// it, after a space; "" when no cut did.
func pkgVersion(rep *check.Report, slice, arch string) string {
	pkg, _, _ := strings.Cut(slice, "_")
	for k, c := range rep.Cuts {
		if k.Arch == arch && c.Versions[pkg] != "" {
			return " " + c.Versions[pkg]
		}
	}
	return ""
}

// describe says what a start node is, as file(1) would in a word or two.
func describe(st resolve.Start, n *rootfs.Node) string {
	switch {
	case st.Kind == "script":
		return "script"
	case st.Kind == "symlink":
		return "symlink"
	case n == nil || n.ELF == nil:
		return st.Kind
	}
	f := n.ELF
	var out string
	switch {
	case st.Kind == "exec" && f.Interp == "" && f.PIE():
		out = "static-pie executable"
	case st.Kind == "exec" && f.Interp == "":
		out = "static executable"
	case st.Kind == "exec":
		out = "executable"
	default:
		out = "shared library"
		if f.Soname != "" && f.Soname != path.Base(st.Path) {
			out += ", soname " + f.Soname
		}
	}
	if k := len(f.Dlopen); k > 0 {
		out += fmt.Sprintf(", %d dlopen %s", k, plural(k, "entry", "entries"))
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// tline is one line of a tree and the lines drawn under it. alert is a
// finding or an unanswered dlopen worse than info, which --prune never hides.
type tline struct {
	text  string
	kids  []*tline
	alert bool
	// group, rank and name order the lines under a node: what the loader
	// links in itself (group 0) before dlopens, required, recommended and
	// suggested (groups 1 to 3). In group 0 the dynamic loader comes first,
	// then edges and then findings (rank); else, and then, by name.
	group, rank int
	name        string
	// to is the file an edge reaches, "" for any other line; note an edge
	// that says something of its own, a dlopen's note, beyond reaching it.
	to   string
	note bool
}

const (
	rankLoader = iota
	rankEdge
	rankFinding
)

// group is the group of a dlopen of priority p; the spec's default is
// recommended.
func group(p string) int {
	switch p {
	case "required":
		return 1
	case "suggested":
		return 3
	case elf.PriorityStrings:
		return 4
	}
	return 2
}

// alerts reports whether t or anything under it is an alert.
func (t *tline) alerts() bool {
	if t.alert {
		return true
	}
	for _, k := range t.kids {
		if k.alerts() {
			return true
		}
	}
	return false
}

// drawTree draws roots with no box drawing and everything under them with
// it, as chisel-diff --tree does.
func drawTree(w io.Writer, roots []*tline, st style) {
	for _, r := range roots {
		fmt.Fprintln(w, r.text)
		drawKids(w, r.kids, "", st)
	}
}

func drawKids(w io.Writer, kids []*tline, prefix string, st style) {
	for i, k := range kids {
		glyph, pad := "├─ ", "│  "
		if i == len(kids)-1 {
			glyph, pad = "└─ ", "   "
		}
		fmt.Fprintln(w, st.wrap(st.dim, prefix+glyph)+k.text)
		drawKids(w, k.kids, prefix+pad, st)
	}
}

// renderTree draws, per named slice and arch, every start node the slice
// itself delivers, what it is and what loading it reached, lddtree style:
// each edge is "<kind> <name> -> <path> (<owner>)", what the loader links
// in itself first and dlopen edges after, the dynamic loader first among
// them and the rest by name, an interpreter is drawn
// with what loading it reaches, "!" is a finding and "?" a dlopen entry the
// cut does not answer, with what lookup made of it. Every node is drawn in
// full wherever it is reached, but for one already on the way down to it.
func renderTree(w io.Writer, rep *check.Report, prune, fold []string, st style) {
	views := map[*check.Cut]*view{}
	for _, s := range rep.Named {
		for _, a := range rep.Arches {
			c := rep.Cuts[check.Key{Slice: s, Arch: a}]
			if c == nil || c.Res == nil || c.NoFile {
				continue
			}
			fmt.Fprintln(w, st.header(s, pkgVersion(rep, s, a), []string{a}))
			drawTree(w, treeOf(rep, c, s, views, prune, fold, st), st)
		}
	}
	notes(w, rep, st)
}

// foldRepeats draws every library once under a start node, as lddtree does
// without --all: the lines under a node claim their libraries before any of
// them is expanded, and a library claimed already is left out, or for a
// dlopen, whose line says more, drawn with nothing under it. An alert is
// never left out. Every library is drawn as it loads alone, so what is left
// out is drawn the same elsewhere.
func foldRepeats(lines []*tline, shown map[string]bool) []*tline {
	var kept, expand []*tline
	for _, t := range lines {
		switch {
		case t.to == "":
			expand = append(expand, t)
		case shown[t.to] && t.note:
			t.kids = slices.DeleteFunc(t.kids, func(k *tline) bool { return !k.alerts() })
		case shown[t.to]:
			if !t.alerts() {
				continue
			}
		default:
			shown[t.to] = true
			expand = append(expand, t)
		}
		kept = append(kept, t)
	}
	for _, t := range expand {
		t.kids = foldRepeats(t.kids, shown)
	}
	return kept
}

// view is one cut as the tree draws from it: every start node, each
// library being one loaded on its own, and the dynamic loaders its
// executables name.
type view struct {
	c       *check.Cut
	res     *resolve.Result
	starts  map[string]resolve.Start
	loaders map[string]bool
}

func newView(c *check.Cut) *view {
	v := &view{c: c, res: c.Full, starts: map[string]resolve.Start{}, loaders: map[string]bool{}}
	if v.res == nil {
		v.res = c.Res
	}
	for _, x := range v.res.Starts {
		v.starts[x.Path] = x
		for _, l := range x.Links {
			if l.Kind == resolve.Interp {
				v.loaders[l.To] = true
			}
		}
	}
	return v
}

// viewOf is the view of c, made once: views holds the ones made so far.
func viewOf(views map[*check.Cut]*view, c *check.Cut) *view {
	v := views[c]
	if v == nil {
		v = newView(c)
		views[c] = v
	}
	return v
}

// treeOf is the tree of what s delivers in cut c. Under every node is what
// the loader makes of that file alone, as if it were the only thing loaded:
// a library's own start node, not what was loaded before it. A dlopen a
// slice outside the cut delivers is drawn from that slice's cut, unless fold
// has "missing". A library --prune names is left out with all under it,
// unless an alert is.
func treeOf(rep *check.Report, c *check.Cut, s string, views map[*check.Cut]*view, prune, fold []string, st style) []*tline {
	a := c.Arch
	owner := func(v *view, p string) string {
		o := slices.Clone(v.c.Owners[p])
		slices.Sort(o)
		if len(o) == 0 {
			return ""
		}
		return " " + st.wrap(st.dim, "("+strings.Join(o, ", ")+")")
	}
	verdict := map[string]check.Item{}
	for _, it := range rep.Items {
		if it.Arch == a && (it.Kind == resolve.Dlopen || it.Kind == elf.PriorityStrings) {
			verdict[it.Path+"\x00"+it.Name] = it
		}
	}
	finding := func(f resolve.Finding) *tline {
		t := &tline{text: st.sev(check.Severity(f.Severity), fmt.Sprintf("! %s %s: %s", f.Kind, f.Name, f.Reason)), alert: true, rank: rankFinding, name: f.Name}
		if f.Kind == resolve.Dlopen && f.Via != nil {
			t.group = group(f.Via.Priority)
		}
		return t
	}
	// up holds the nodes on the way down to from: only a node among them is
	// not expanded again, which a dependency cycle needs to end.
	// lib is a file loaded as a library, whose PT_INTERP, as libc.so.6 has
	// one, the loader does not read.
	var build func(v *view, x resolve.Start, from string, lib bool, up map[string]bool) []*tline
	// under is what is drawn under file p, reached from start x in v: p's
	// own start node when it has one, else what x's load did from p.
	under := func(v *view, x resolve.Start, p string, lib bool, up map[string]bool) []*tline {
		up[p] = true
		defer delete(up, p)
		if next, ok := v.starts[p]; ok {
			return build(v, next, p, lib, up)
		}
		return build(v, x, p, lib, up)
	}
	build = func(v *view, x resolve.Start, from string, lib bool, up map[string]bool) []*tline {
		var out []*tline
		for _, l := range x.Links {
			if l.From != from || lib && l.Kind == resolve.Interp {
				continue
			}
			kind := st.wrap(st.dim, l.Kind)
			if l.Kind == resolve.Dlopen {
				kind = st.wrap(st.dlopen, l.Kind)
			}
			text := kind + " " + l.Name
			switch {
			case l.Note != nil && l.Note.Priority == elf.PriorityStrings:
				text = st.wrap(st.dlopen, elf.PriorityStrings) + " " + l.Name
			case l.Note != nil:
				text += " (" + l.Note.Feature + ", " + l.Note.Priority + ")"
			}
			hidden := pruned(prune, a, l.Name, l.To)
			if l.To != l.Name {
				text += " -> " + l.To
			}
			t := &tline{text: text + owner(v, l.To), rank: rankEdge, name: l.Name, to: l.To, note: l.Note != nil}
			switch {
			case l.Note != nil:
				t.group = group(l.Note.Priority)
			case l.Kind == resolve.Interp || v.loaders[l.To]:
				t.rank = rankLoader
			}
			if up[l.To] {
				if hidden {
					continue
				}
				t.text += " " + st.wrap(st.dim, "(cycle)")
				out = append(out, t)
				continue
			}
			t.kids = under(v, x, l.To, l.Kind != resolve.Shebang && l.Kind != resolve.Env, up)
			if hidden && !t.alerts() {
				continue
			}
			out = append(out, t)
		}
		for _, f := range v.res.Findings {
			if f.Start == x.Path && f.From == from {
				out = append(out, finding(f))
			}
		}
		for _, o := range v.res.Open {
			if o.Start != x.Path || o.From != from {
				continue
			}
			name := strings.Join(o.Entry.Soname, " or ")
			it, ok := verdict[o.From+"\x00"+name]
			if !ok {
				it = check.Item{Severity: check.Info, Reason: "not looked up"}
			}
			if it.Severity == check.Info && prunedAny(prune, a, o.Entry.Soname) {
				continue
			}
			text := fmt.Sprintf("? dlopen %s (%s, %s): %s", name, o.Entry.Feature, o.Entry.Priority, it.Reason)
			if o.Entry.Priority == elf.PriorityStrings {
				text = fmt.Sprintf("? strings %s: %s", name, it.Reason)
			}
			t := &tline{text: st.sev(it.Severity, text),
				alert: it.Severity != check.Info, group: group(o.Entry.Priority), name: name}
			if pc := rep.Cuts[check.Key{Slice: it.Provider, Arch: a}]; it.Provider != "" && pc != nil && pc.Res != nil && !up[it.ProviderPath] && !slices.Contains(fold, "missing") {
				pv := viewOf(views, pc)
				if px, ok := pv.starts[it.ProviderPath]; ok {
					up[it.ProviderPath] = true
					t.kids = build(pv, px, it.ProviderPath, true, up)
					delete(up, it.ProviderPath)
				}
			}
			out = append(out, t)
		}
		slices.SortStableFunc(out, func(a, b *tline) int {
			switch {
			case a.group != b.group:
				return a.group - b.group
			case a.group == 0 && a.rank != b.rank:
				return a.rank - b.rank
			}
			return strings.Compare(a.name, b.name)
		})
		return out
	}
	v := viewOf(views, c)
	repeats := slices.Contains(fold, "repeats")
	var roots []*tline
	for _, x := range c.Res.Starts {
		if !slices.Contains(c.Owners[x.Path], s) {
			continue
		}
		n := c.FS.Nodes[x.Path]
		if x.Kind == "symlink" {
			// A link that resolves is drawn where it is used; one that
			// does not is drawn here, with why.
			t := &tline{text: x.Path + " -> " + n.Target + owner(v, x.Path) + ": symlink"}
			for _, f := range v.res.Findings {
				if f.Start == x.Path {
					t.kids = append(t.kids, finding(f))
				}
			}
			if len(t.kids) > 0 {
				roots = append(roots, t)
			}
			continue
		}
		t := &tline{text: x.Path + owner(v, x.Path) + ": " + describe(x, n)}
		t.kids = build(v, x, x.Path, x.Kind == "lib", map[string]bool{x.Path: true})
		if repeats {
			t.kids = foldRepeats(t.kids, map[string]bool{x.Path: true})
		}
		roots = append(roots, t)
	}
	return roots
}

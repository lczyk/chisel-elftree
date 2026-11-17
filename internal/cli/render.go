package cli

import (
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/lczyk/chisel-coverage/pkg/fold"
	"github.com/lczyk/chisel-coverage/pkg/pathtree"

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

// renderText prints, per block, the findings and the dlopens the cut does
// not answer among the block's lines, one a line as "<path> (<owner>):
// <severity> <kind> <name>: <reason>", worst first. Nothing is indented, so
// the report greps: grep ': hard ' is what does not run. A tree says a
// thing wherever it is reached and this report once: a line every
// architecture of a block was told already, in a block before it, is left
// out, and a block with nothing left prints nothing.
func renderText(w io.Writer, rep *check.Report, noGroup bool, prune, folds []string, st style) {
	told := map[string]bool{} // slice, architecture and line
	for _, b := range blocks(rep, noGroup, prune, folds) {
		var lines []*tline
		seen := map[string]bool{}
		var walk func(ts []*tline)
		walk = func(ts []*tline) {
			for _, t := range ts {
				if t.flat != "" && !t.context && !seen[t.flat] {
					seen[t.flat] = true
					news := false
					for _, a := range b.Arches {
						k := b.Slice + "\x00" + a + "\x00" + fold.Normalise(t.flat, a)
						news = news || !told[k]
						told[k] = true
					}
					if news {
						lines = append(lines, t)
					}
				}
				walk(t.kids)
			}
		}
		walk(b.Roots)
		if len(lines) == 0 {
			continue
		}
		slices.SortStableFunc(lines, func(x, y *tline) int {
			if x.sev != y.sev {
				return int(x.sev) - int(y.sev)
			}
			return strings.Compare(x.flat, y.flat)
		})
		fmt.Fprintln(w, st.header(b.Slice, b.Version, b.Arches))
		for _, t := range lines {
			fmt.Fprintln(w, st.sev(t.sev, t.flat))
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

// paint is how a part of a line is coloured.
type paint int

const (
	paintNone paint = iota
	paintDim
	paintDlopen
	paintHard
	paintSoft
	paintInfo
)

func paintOf(sev check.Severity) paint {
	switch sev {
	case check.Hard:
		return paintHard
	case check.Soft, check.Warning:
		return paintSoft
	}
	return paintInfo
}

func (s style) paint(p paint, text string) string {
	switch p {
	case paintDim, paintInfo:
		return s.wrap(s.dim, text)
	case paintDlopen:
		return s.wrap(s.dlopen, text)
	case paintHard:
		return s.wrap(s.red, text)
	case paintSoft:
		return s.wrap(s.yellow, text)
	}
	return text
}

// seg is a part of a line that is painted one way.
type seg struct {
	text  string
	paint paint
}

// tline is one line of a tree and the lines drawn under it. alert is a
// finding or an unanswered dlopen worse than info, which --prune never hides.
type tline struct {
	segs  []seg
	kids  []*tline
	alert bool
	// flat is the line as the text report prints it, for a finding or a
	// dlopen the cut does not answer, and sev its severity; "" for any
	// other line.
	flat string
	sev  check.Severity
	// context is a line a block draws only to hold what is under it: the
	// line itself belongs to a block of more architectures.
	context bool
	// at is where the line stands among the lines under its parent.
	at int
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

// say adds a part to the line.
func (t *tline) say(p paint, text string) *tline {
	if text != "" {
		t.segs = append(t.segs, seg{text, p})
	}
	return t
}

// plain is the line with no colour.
func (t *tline) plain() string {
	var b strings.Builder
	for _, s := range t.segs {
		b.WriteString(s.text)
	}
	return b.String()
}

// painted is the line as st colours it, a context line all dim.
func (t *tline) painted(st style) string {
	if t.context {
		return st.wrap(st.dim, t.plain())
	}
	var b strings.Builder
	for _, s := range t.segs {
		b.WriteString(st.paint(s.paint, s.text))
	}
	return b.String()
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
	var nodes func(ts []*tline) []*pathtree.Node
	nodes = func(ts []*tline) []*pathtree.Node {
		out := make([]*pathtree.Node, len(ts))
		for i, t := range ts {
			out[i] = &pathtree.Node{Line: t.painted(st), Kids: nodes(t.kids)}
		}
		return out
	}
	for _, line := range pathtree.Draw(nodes(roots), func(s string) string { return st.wrap(st.dim, s) }) {
		fmt.Fprintln(w, line)
	}
}

// renderTree draws every block as a tree: every start node the slice
// itself delivers, what it is and what loading it reached, lddtree style:
// each edge is "<kind> <name> -> <path> (<owner>)", what the loader links
// in itself first and dlopen edges after, the dynamic loader first among
// them and the rest by name, an interpreter is drawn
// with what loading it reaches, "!" is a finding and "?" a dlopen entry the
// cut does not answer, with what lookup made of it. Every node is drawn in
// full wherever it is reached, but for one already on the way down to it.
func renderTree(w io.Writer, rep *check.Report, noGroup bool, prune, folds []string, st style) {
	for _, b := range blocks(rep, noGroup, prune, folds) {
		fmt.Fprintln(w, st.header(b.Slice, b.Version, b.Arches))
		drawTree(w, b.Roots, st)
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
func treeOf(rep *check.Report, c *check.Cut, s string, views map[*check.Cut]*view, prune, folds []string) []*tline {
	a := c.Arch
	// owner adds the slices delivering p to a line, dim.
	owner := func(t *tline, v *view, p string) *tline {
		o := slices.Clone(v.c.Owners[p])
		slices.Sort(o)
		if len(o) == 0 {
			return t
		}
		return t.say(paintNone, " ").say(paintDim, "("+strings.Join(o, ", ")+")")
	}
	// flat is a line of the text report about the file from, whose slices
	// are named unless s is one of them.
	flat := func(v *view, from string, sev check.Severity, kind, name, reason string) string {
		o := slices.Clone(v.c.Owners[from])
		slices.Sort(o)
		if len(o) > 0 && !slices.Contains(o, s) {
			from += " (" + strings.Join(o, ", ") + ")"
		}
		return fmt.Sprintf("%s: %s %s %s: %s", from, sev, kind, name, reason)
	}
	verdict := map[string]check.Item{}
	for _, it := range rep.Items {
		if it.Arch == a && (it.Kind == resolve.Dlopen || it.Kind == elf.PriorityStrings) {
			verdict[it.Path+"\x00"+it.Name] = it
		}
	}
	finding := func(v *view, f resolve.Finding) *tline {
		sev := check.Severity(f.Severity)
		t := &tline{alert: true, rank: rankFinding, name: f.Name, sev: sev}
		t.say(paintOf(sev), fmt.Sprintf("! %s %s: %s", f.Kind, f.Name, f.Reason))
		name, reason := f.Name, f.Reason
		if f.Via != nil {
			if f.Via.Feature != "" {
				name += " (" + f.Via.Feature + ", " + f.Via.Priority + ")"
			}
			if f.Kind != resolve.Dlopen {
				reason = fmt.Sprintf("in what dlopen %s loads: %s", f.Via.Soname, f.Reason)
			}
		}
		t.flat = flat(v, f.From, sev, f.Kind, name, reason)
		if f.Kind == resolve.Dlopen && f.Via != nil {
			t.group = group(f.Via.Priority)
		}
		return t
	}
	// visited is every file whose own start node was drawn.
	visited := map[string]bool{}
	// up holds the nodes on the way down to from: only a node among them is
	// not expanded again, which a dependency cycle needs to end.
	// lib is a file loaded as a library, whose PT_INTERP, as libc.so.6 has
	// one, the loader does not read. ld is the dynamic loader of the
	// program all this is loaded for, "" when it names none: it is drawn
	// once, as that program's interpreter, and an edge to it from further
	// down, as libc.so.6 needs it, is left out like a pruned library.
	var build func(v *view, x resolve.Start, from string, lib bool, up map[string]bool, ld string) []*tline
	// under is what is drawn under file p, reached from start x in v: p's
	// own start node when it has one, else what x's load did from p.
	under := func(v *view, x resolve.Start, p string, lib bool, up map[string]bool, ld string) []*tline {
		up[p] = true
		defer delete(up, p)
		if next, ok := v.starts[p]; ok {
			if v.c == c {
				visited[p] = true
			}
			return build(v, next, p, lib, up, ld)
		}
		return build(v, x, p, lib, up, ld)
	}
	build = func(v *view, x resolve.Start, from string, lib bool, up map[string]bool, ld string) []*tline {
		var out []*tline
		if !lib {
			ld = ""
			for _, l := range x.Links {
				if l.From == from && l.Kind == resolve.Interp {
					ld = l.To
				}
			}
		}
		for _, l := range x.Links {
			if l.From != from || lib && l.Kind == resolve.Interp {
				continue
			}
			t := &tline{rank: rankEdge, name: l.Name, to: l.To, note: l.Note != nil}
			text := " " + l.Name
			switch {
			case l.Note != nil && l.Note.Priority == elf.PriorityStrings:
				t.say(paintDlopen, elf.PriorityStrings)
			case l.Kind == resolve.Dlopen:
				t.say(paintDlopen, l.Kind)
			default:
				t.say(paintDim, l.Kind)
			}
			if l.Note != nil && l.Note.Priority != elf.PriorityStrings {
				text += " (" + l.Note.Feature + ", " + l.Note.Priority + ")"
			}
			hidden := pruned(prune, a, l.Name, l.To) || ld != "" && l.To == ld && l.Kind != resolve.Interp
			if l.To != l.Name {
				text += " -> " + l.To
			}
			owner(t.say(paintNone, text), v, l.To)
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
				t.say(paintNone, " ").say(paintDim, "(cycle)")
				out = append(out, t)
				continue
			}
			t.kids = under(v, x, l.To, l.Kind != resolve.Shebang && l.Kind != resolve.Env, up, ld)
			if hidden && !t.alerts() {
				continue
			}
			out = append(out, t)
		}
		for _, f := range v.res.Findings {
			if f.Start == x.Path && f.From == from {
				out = append(out, finding(v, f))
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
			kind, full := resolve.Dlopen, name
			if o.Entry.Feature != "" {
				full += " (" + o.Entry.Feature + ", " + o.Entry.Priority + ")"
			}
			if o.Entry.Priority == elf.PriorityStrings {
				text = fmt.Sprintf("? strings %s: %s", name, it.Reason)
				kind, full = elf.PriorityStrings, name
			}
			t := &tline{alert: it.Severity != check.Info, group: group(o.Entry.Priority), name: name, sev: it.Severity}
			switch {
			case it.Provider != "":
				// Delivered by a slice outside the cut: named as an
				// edge's owner is, with no reason to give.
				text, _, _ = strings.Cut(text, ": ")
				t.say(paintOf(it.Severity), text).say(paintNone, " ").say(paintDim, "("+it.Provider+")")
			case it.Reason == check.Undeclared:
				// The "?" and no owner say as much.
				text, _, _ = strings.Cut(text, ": ")
				t.say(paintOf(it.Severity), text)
			default:
				t.say(paintOf(it.Severity), text)
			}
			t.flat = flat(v, o.From, it.Severity, kind, full, it.Reason)
			if pc := rep.Cuts[check.Key{Slice: it.Provider, Arch: a}]; it.Provider != "" && pc != nil && pc.Res != nil && !up[it.ProviderPath] && !slices.Contains(folds, "missing") {
				pv := viewOf(views, pc)
				if px, ok := pv.starts[it.ProviderPath]; ok {
					up[it.ProviderPath] = true
					t.kids = build(pv, px, it.ProviderPath, true, up, ld)
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
	repeats := slices.Contains(folds, "repeats")
	// root is the line of start node x with what is under it. A link that
	// resolves is drawn where it is used; one that does not is drawn as a
	// root, with why.
	root := func(x resolve.Start) *tline {
		n := c.FS.Nodes[x.Path]
		visited[x.Path] = true
		if x.Kind == "symlink" {
			t := owner((&tline{}).say(paintNone, x.Path+" -> "+n.Target), v, x.Path).say(paintNone, ": symlink")
			for _, f := range v.res.Findings {
				if f.Start == x.Path {
					t.kids = append(t.kids, finding(v, f))
				}
			}
			return t
		}
		t := owner((&tline{}).say(paintNone, x.Path), v, x.Path).say(paintNone, ": "+describe(x, n))
		t.kids = build(v, x, x.Path, x.Kind == "lib", map[string]bool{x.Path: true}, "")
		if repeats {
			t.kids = foldRepeats(t.kids, map[string]bool{x.Path: true})
		}
		return t
	}
	// wrong reports whether x's own load left a finding or a dlopen worse
	// than info.
	wrong := func(x resolve.Start) bool {
		for _, f := range v.res.Findings {
			if f.Start == x.Path {
				return true
			}
		}
		for _, o := range v.res.Open {
			if it, ok := verdict[o.From+"\x00"+strings.Join(o.Entry.Soname, " or ")]; o.Start == x.Path && ok && it.Severity != check.Info {
				return true
			}
		}
		return false
	}
	var roots []*tline
	for _, x := range c.Res.Starts {
		if !slices.Contains(c.Owners[x.Path], s) {
			continue
		}
		if x.Kind == "symlink" {
			if t := root(x); len(t.kids) > 0 {
				roots = append(roots, t)
			}
			continue
		}
		roots = append(roots, root(x))
	}
	// A start node of another slice that nothing above reached is still
	// part of the cut: it is drawn when something is wrong with it, since
	// a finding is never left out. One of a named slice is drawn in that
	// slice's own block.
	for _, x := range c.Res.Starts {
		if visited[x.Path] || !wrong(x) || slices.ContainsFunc(c.Owners[x.Path], func(o string) bool { return slices.Contains(rep.Named, o) }) {
			continue
		}
		if t := root(x); t.alerts() {
			roots = append(roots, t)
		}
	}
	return roots
}

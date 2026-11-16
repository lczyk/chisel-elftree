package cli

import (
	"slices"
	"strconv"
	"strings"

	"github.com/lczyk/chisel-coverage/pkg/fold"

	"github.com/lczyk/chisel-elftree/internal/check"
)

// block is what one group of a named slice's architectures has in common:
// the lines of their trees that are the same on each, as a tree. Every
// report is drawn from blocks, so the text report, the tree and the json
// group the architectures the same way.
type block struct {
	Slice   string
	Version string // of the slice's package, after a space; "" when not known
	Arches  []string
	Roots   []*tline
}

// A line is told from the others by its chain: the lines from its root down
// to it, joined with chainSep. A line said twice under one parent has
// dupSep and its count after it.
const (
	chainSep = "\x1f"
	dupSep   = "\x1e"
)

// blocks builds every named slice's tree on every architecture, as treeOf
// draws it, and folds them: a line is the same on two architectures when it
// says the same at the same place in the tree, once what names the
// architecture is normalised, and the package is of one version. Every set
// of architectures that shares lines is a block, most architectures first,
// holding those lines under the lines above them, which are context where
// they belong to another block. With noGroup every architecture is a block
// of its own.
func blocks(rep *check.Report, noGroup bool, prune, folds []string) []block {
	views := map[*check.Cut]*view{}
	var out []block
	for _, s := range rep.Named {
		var arches []string
		var items [][]fold.Item
		lines := map[string]map[string]*tline{} // arch -> chain as the arch has it -> line
		for _, a := range rep.Arches {
			c := rep.Cuts[check.Key{Slice: s, Arch: a}]
			if c == nil || c.Res == nil || c.NoFile {
				continue
			}
			version := pkgVersion(rep, s, a)
			byChain := map[string]*tline{}
			var its []fold.Item
			var walk func(ts []*tline, key, raw string)
			walk = func(ts []*tline, key, raw string) {
				said := map[string]int{}
				for i, t := range ts {
					t.at = i
					p := t.plain()
					again := ""
					if n := said[p]; n > 0 {
						again = dupSep + strconv.Itoa(n)
					}
					said[p]++
					k := key + chainSep + fold.Normalise(p, a) + again
					r := raw + chainSep + p + again
					byChain[r] = t
					its = append(its, fold.Item{Key: k, Raw: r, Tag: version})
					walk(t.kids, k, r)
				}
			}
			walk(treeOf(rep, c, s, views, prune, folds), "", "")
			arches = append(arches, a)
			items = append(items, its)
			lines[a] = byChain
		}
		var groups []fold.Group
		if noGroup {
			for i, a := range arches {
				groups = append(groups, fold.Fold([]string{a}, [][]fold.Item{items[i]})...)
			}
		} else {
			groups = fold.Fold(arches, items)
		}
		for _, g := range groups {
			out = append(out, block{Slice: s, Version: pkgVersion(rep, s, g.Arches[0]), Arches: g.Arches, Roots: grow(g, lines)})
		}
	}
	return out
}

// upTo is the first n lines of a chain.
func upTo(chain string, n int) string {
	at := 0
	for i := 0; i <= n; i++ {
		j := strings.Index(chain[at:], chainSep)
		if j < 0 {
			return chain
		}
		at += j + len(chainSep)
	}
	return chain[:at-len(chainSep)]
}

// grow makes the tree of a group out of its entries, each the chain of one
// line: the line goes under the lines of its chain, in the order its
// architectures drew it. A line above it that is no entry of the group is
// drawn as context.
func grow(g fold.Group, lines map[string]map[string]*tline) []*tline {
	var roots []*tline
	made := map[string]*tline{} // chain as the first architecture has it -> line
	for _, e := range g.Entries {
		depth := strings.Count(e.Raw[0], chainSep)
		for d := 1; d <= depth; d++ {
			chain := upTo(e.Raw[0], d)
			t := made[chain]
			if t == nil {
				srcs := make([]*tline, len(g.Arches))
				for i, a := range g.Arches {
					srcs[i] = lines[a][upTo(e.Raw[i], d)]
				}
				t = shared(srcs, g.Arches[0])
				t.context = true
				made[chain] = t
				if d == 1 {
					roots = append(roots, t)
				} else {
					up := made[upTo(e.Raw[0], d-1)]
					up.kids = append(up.kids, t)
				}
			}
			if d == depth {
				t.context = false
			}
		}
	}
	var sort func(ts []*tline)
	sort = func(ts []*tline) {
		slices.SortStableFunc(ts, func(x, y *tline) int { return x.at - y.at })
		for _, t := range ts {
			sort(t.kids)
		}
	}
	sort(roots)
	return roots
}

// shared is the one line that stands for srcs, the same line on every
// architecture of a group: each part as it is when every architecture
// spells it the same, else with what names the architecture normalised.
func shared(srcs []*tline, arch string) *tline {
	first := srcs[0]
	t := &tline{alert: first.alert, sev: first.sev, group: first.group, rank: first.rank,
		name: first.name, to: first.to, note: first.note, at: first.at}
	same := func(of func(*tline) string) string {
		for _, x := range srcs[1:] {
			if of(x) != of(first) {
				return fold.Normalise(of(first), arch)
			}
		}
		return of(first)
	}
	t.flat = same(func(x *tline) string { return x.flat })
	parts := len(first.segs)
	for _, x := range srcs[1:] {
		if len(x.segs) != parts {
			return t.say(paintNone, same((*tline).plain))
		}
	}
	for i, sg := range first.segs {
		t.say(sg.paint, same(func(x *tline) string { return x.segs[i].text }))
	}
	return t
}

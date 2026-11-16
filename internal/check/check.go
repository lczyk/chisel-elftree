// Package check is the run: every named slice cut for real on every
// architecture through chisel-coverage's pool, each rootfs read and
// resolved while it exists, the dlopen targets missing from a cut looked
// up across the release, and the findings attributed to the slices they
// count against.
package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/lczyk/chisel-coverage/pkg/cut"
	"github.com/lczyk/chisel-coverage/pkg/pool"
	temprelease "github.com/lczyk/chisel-proxy/pkg/temp-release"

	"github.com/lczyk/chisel-elftree/internal/elf"
	"github.com/lczyk/chisel-elftree/internal/glob"
	"github.com/lczyk/chisel-elftree/internal/lookup"
	"github.com/lczyk/chisel-elftree/internal/manifest"
	"github.com/lczyk/chisel-elftree/internal/resolve"
	"github.com/lczyk/chisel-elftree/internal/rootfs"
	validatetrick "github.com/lczyk/chisel-elftree/pkg/validate-trick"
)

// Options configures a run.
type Options struct {
	Release string   // a release dir
	Arches  []string // the first is cut alone before the rest
	Named   []string // <package>_<slice>
	// Files, when set, are the start nodes of the named cuts to check, as
	// chisel globs on the path, or on the file name for a glob without a
	// slash; what they go on to is checked with them.
	Files   []string
	Jobs    int
	Cache   string
	Runner  *cut.Runner
	Keep    bool
	Log     io.Writer
	Verbose io.Writer
}

// Key names one cut.
type Key struct{ Slice, Arch string }

// Cut is what one cut of a slice on an arch found.
type Cut struct {
	Key
	Available bool
	Err       error // the cut failed for another reason
	Rejected  error // for a candidate: why it does not count, a cut failure included
	NoFile    bool  // Options.Files matched none of the cut's start nodes
	// Full is Res before Options.Files narrowed it, for drawing any
	// library on its own; Res when nothing narrowed it.
	Full     *resolve.Result
	Version  string
	Versions map[string]string // package -> version, of every deb the cut fetched
	Owners   map[string][]string
	FS       *rootfs.FS
	Res      *resolve.Result
}

// Severity of a reported item. Hard, soft and warning are resolve's.
type Severity int

const (
	Hard Severity = iota
	Soft
	Warning
	Info
)

func (s Severity) String() string { return [...]string{"hard", "soft", "warning", "info"}[s] }

// Item is one finding as reported, on one arch.
type Item struct {
	Arch     string     `json:"arch"`
	Against  string     `json:"against"` // the slice it counts against
	Named    bool       `json:"named"`   // Against is a named slice
	Reached  string     `json:"reached,omitempty"`
	Severity Severity   `json:"-"`
	Sev      string     `json:"severity"`
	Path     string     `json:"path"`
	Owner    string     `json:"owner,omitempty"` // the slice delivering Path, when not Against
	Kind     string     `json:"kind"`
	Name     string     `json:"name"`
	Reason   string     `json:"reason"`
	Feature  string     `json:"feature,omitempty"`
	Priority string     `json:"priority,omitempty"`
	Chains   [][]string `json:"chains,omitempty"`
	// for a dlopen a slice outside the cut delivers: the slice and the
	// file its cut loads
	Provider     string `json:"provider,omitempty"`
	ProviderPath string `json:"provider_path,omitempty"`
}

// Report is the outcome of a run.
type Report struct {
	Arches []string
	Named  []string
	Cuts   map[Key]*Cut
	Items  []Item
	Errors []error
	// Validations is how many times the validate trick asked chisel.
	Validations int
}

type run struct {
	ctx   context.Context
	opts  Options
	rel   *temprelease.Release
	mu    sync.Mutex
	cuts  map[Key]*Cut
	added map[string]bool // packages given the manifest slice in rel
	index lookup.Index
	trick *validatetrick.Prober
	// answers is the validate trick's declarers of each target asked about.
	answers map[string]answer
	// declared is the targets one probe for many did not clear, so each
	// is asked about on its own.
	declared map[string]bool
	named    map[string]bool
	wants    map[string]*want
	// per Files glob: whether it matched any path of a named cut, and any
	// start node
	fileAny, fileStart map[string]bool
}

type answer struct {
	hits []validatetrick.Hit
	err  error
}

// Run cuts and checks the named slices.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if len(opts.Named) == 0 || len(opts.Arches) == 0 {
		return nil, errors.New("nothing to check")
	}
	rel, err := temprelease.Copy(opts.Release)
	if err != nil {
		return nil, err
	}
	if !opts.Keep {
		defer rel.Remove()
	}
	r := &run{ctx: ctx, opts: opts, rel: rel, cuts: map[Key]*Cut{}, added: map[string]bool{},
		answers: map[string]answer{}, declared: map[string]bool{}, named: map[string]bool{}, fileAny: map[string]bool{}, fileStart: map[string]bool{}}
	for _, s := range opts.Named {
		r.named[s] = true
		if err := r.addManifest(s); err != nil {
			return nil, err
		}
	}
	p, err := pool.New(ctx, pool.Options{Jobs: opts.Jobs, Cache: opts.Cache, Runner: opts.Runner, Keep: opts.Keep,
		Name: "elftree", Temp: "chisel-elftree-*", Log: opts.Log, Verbose: opts.Verbose})
	if err != nil {
		return nil, err
	}
	defer p.Close()
	// The lead architecture alone first, so the rest find the arch: all
	// debs and the suite indexes cached.
	for _, arches := range [][]string{opts.Arches[:1], opts.Arches[1:]} {
		if err := p.Pass(r.groups(opts.Named, arches), r.done); err != nil {
			return nil, err
		}
	}
	// A group stops once its lead finds the package missing, so the rest of
	// its slices were never cut: they are not available either.
	for _, a := range opts.Arches {
		for _, sl := range opts.Named {
			if _, ok := r.cuts[Key{sl, a}]; ok {
				continue
			}
			pkg, _, _ := strings.Cut(sl, "_")
			for k, c := range r.cuts {
				if lp, _, _ := strings.Cut(k.Slice, "_"); k.Arch == a && lp == pkg && !c.Available {
					r.cuts[Key{sl, a}] = &Cut{Key: Key{sl, a}}
					break
				}
			}
		}
	}
	if err := r.filesMatched(); err != nil {
		return nil, err
	}
	rep := &Report{Arches: opts.Arches, Named: opts.Named, Cuts: r.cuts}
	if err := r.lookup(p, rep); err != nil {
		return nil, err
	}
	p.Summary()
	r.attribute(rep)
	if r.trick != nil {
		rep.Validations = r.trick.Validations()
	}
	return rep, nil
}

func (r *run) addManifest(slice string) error {
	pkg, _, _ := strings.Cut(slice, "_")
	if r.added[pkg] {
		return nil
	}
	r.added[pkg] = true
	return manifest.Add(r.rel.Dir, pkg)
}

// groups is one group per (package, arch), led by its first slice, so a
// package missing on an arch costs one cut.
func (r *run) groups(sls []string, arches []string) []pool.Group {
	var out []pool.Group
	for _, arch := range arches {
		index := map[string]int{}
		for _, s := range sls {
			pkg, _, _ := strings.Cut(s, "_")
			u := pool.Unit{
				Release: r.rel.Dir, Arch: arch, Slice: s,
				With: []string{pkg + "_" + manifest.Slice},
				Dir:  filepath.Join(arch, s),
				Tag:  Key{s, arch},
			}
			if gi, ok := index[pkg]; ok {
				out[gi].Rest = append(out[gi].Rest, u)
				continue
			}
			index[pkg] = len(out)
			out = append(out, pool.Group{Lead: u})
		}
	}
	return out
}

// done reads one finished cut while its rootfs exists.
func (r *run) done(pc pool.Cut) bool {
	k := pc.Tag.(Key)
	c := &Cut{Key: k}
	defer func() {
		r.mu.Lock()
		r.cuts[k] = c
		r.mu.Unlock()
	}()
	if pc.Err != nil {
		var ce *cut.Error
		if errors.As(pc.Err, &ce) && errors.Is(ce.Err, cut.ErrNotAvailable) {
			return false
		}
		c.Available = true
		c.Err = pc.Err
		return true
	}
	c.Available = true
	c.Version = pc.Result.Version
	c.Versions = map[string]string{}
	for _, d := range pc.Result.Debs {
		c.Versions[d.Name] = d.Version
	}
	owners, err := manifest.Origins(pc.Root)
	if err != nil {
		c.Err = fmt.Errorf("%s on %s: reading the manifest: %w", k.Slice, k.Arch, err)
		return true
	}
	fs, err := rootfs.Read(pc.Root, manifest.Own)
	if err != nil {
		c.Err = fmt.Errorf("%s on %s: %w", k.Slice, k.Arch, err)
		return true
	}
	c.Owners, c.FS = owners, fs
	c.Res = resolve.Check(fs, resolve.Arches[k.Arch])
	c.Full = c.Res
	if r.named[k.Slice] && len(r.opts.Files) > 0 {
		r.only(c)
	}
	return true
}

// only keeps of a named cut's result the start nodes Files match, those
// they go on to however many hops on, and what was found from them, so no
// lookup is made for the rest.
func (r *run) only(c *Cut) {
	full := *c.Res
	full.Starts, full.Findings, full.Open = slices.Clone(full.Starts), slices.Clone(full.Findings), slices.Clone(full.Open)
	full.Foreign = slices.Clone(full.Foreign)
	full.Unreadable = maps.Clone(full.Unreadable)
	c.Full = &full
	res := c.Res
	byPath := map[string]resolve.Start{}
	for _, st := range res.Starts {
		byPath[st.Path] = st
	}
	keep := map[string]bool{}
	var queue []string
	r.mu.Lock()
	for _, g := range r.opts.Files {
		for p := range c.FS.Nodes {
			if glob.File(g, p) {
				r.fileAny[g] = true
			}
		}
		for _, st := range res.Starts {
			if glob.File(g, st.Path) && !keep[st.Path] {
				r.fileStart[g] = true
				keep[st.Path] = true
				queue = append(queue, st.Path)
			}
		}
	}
	if r.opts.Verbose != nil {
		matched := "none"
		if len(queue) > 0 {
			matched = strings.Join(queue, ",")
		}
		fmt.Fprintf(r.opts.Verbose, "%s %s %s file %s\n", cut.Stamp(), c.Arch, c.Slice, matched)
	}
	r.mu.Unlock()
	c.NoFile = len(queue) == 0
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, e := range byPath[p].Exec {
			if _, ok := byPath[e]; ok && !keep[e] {
				keep[e] = true
				queue = append(queue, e)
			}
		}
	}
	res.Starts = slices.DeleteFunc(res.Starts, func(st resolve.Start) bool { return !keep[st.Path] })
	res.Findings = slices.DeleteFunc(res.Findings, func(f resolve.Finding) bool { return !keep[f.Start] })
	res.Open = slices.DeleteFunc(res.Open, func(o resolve.Open) bool { return !keep[o.Start] })
	res.Foreign = slices.DeleteFunc(res.Foreign, func(p string) bool { return !glob.AnyFile(r.opts.Files, p) })
	for p := range res.Unreadable {
		if !glob.AnyFile(r.opts.Files, p) {
			delete(res.Unreadable, p)
		}
	}
}

// filesMatched fails a run whose Files glob matched nothing any named cut
// has, or nothing that is a start node.
func (r *run) filesMatched() error {
	for _, g := range r.opts.Files {
		switch {
		case !r.fileAny[g]:
			return fmt.Errorf("--file %s: matches no file of the cuts", g)
		case !r.fileStart[g]:
			return fmt.Errorf("--file %s: not an executable, library, script or symlink", g)
		}
	}
	return nil
}

// want is one dlopen note entry left open by a cut, to be settled by a
// slice elsewhere in the release.
type want struct {
	arch    string
	sonames []string
	cands   []string // to try, in order
	tried   map[string]bool
	trick   []string // targets whose validate trick answers are still to read
	// result
	provider string
	soname   string
	path     string // the file the provider's cut loads for soname
	rejected []string
	err      error
	done     bool
}

func wantKey(arch string, sonames []string) string { return arch + " " + strings.Join(sonames, ",") }

// lookup settles every open dlopen entry: a slice cut in this run that
// delivers it, else the shortlist's candidates, else the validate trick's,
// each confirmed by a cut of the candidate on its own.
func (r *run) lookup(p *pool.Pool, rep *Report) error {
	wants := map[string]*want{}
	var order []string
	for _, k := range r.sortedCuts() {
		c := r.cuts[k]
		if c.Res == nil {
			continue
		}
		for _, o := range c.Res.Open {
			wk := wantKey(k.Arch, o.Absent)
			if _, ok := wants[wk]; ok {
				continue
			}
			w := &want{arch: k.Arch, sonames: o.Absent, tried: map[string]bool{}}
			wants[wk] = w
			order = append(order, wk)
		}
	}
	if len(order) == 0 {
		return nil
	}
	ix, err := lookup.Read(r.opts.Release)
	if err != nil {
		return err
	}
	r.index = ix
	triplet := func(arch string) string { return resolve.Arches[arch].Triplet }
	dirs := func(arch string) []string { return resolve.Arches[arch].DefaultDirs() }
	for _, wk := range order {
		w := wants[wk]
		for _, s := range w.sonames {
			// A slice cut in this run that has the target.
			for _, k := range r.sortedCuts() {
				c := r.cuts[k]
				if k.Arch != w.arch || c.Owners == nil {
					continue
				}
				for _, t := range lookup.Targets(s, dirs(w.arch)) {
					for _, sl := range c.Owners[t] {
						if !slices.Contains(w.cands, sl) {
							w.cands = append(w.cands, sl)
						}
					}
				}
			}
		}
		for _, s := range w.sonames {
			for _, sl := range ix.Candidates(lookup.Shortlist(s, triplet(w.arch)), w.arch) {
				if !slices.Contains(w.cands, sl) {
					w.cands = append(w.cands, sl)
				}
			}
			w.trick = append(w.trick, lookup.Targets(s, dirs(w.arch))...)
		}
	}
	for round := 0; ; round++ {
		var units []Key
		var need, ahead []string
		pending := false
		for _, wk := range order {
			w := wants[wk]
			for !w.done {
				sl, t, ok := r.nextCandidate(w)
				if t != "" {
					if !slices.Contains(need, t) {
						need = append(need, t)
					}
					ahead = append(ahead, w.trick...)
					break
				}
				if !ok {
					w.done = true
					break
				}
				k := Key{sl, w.arch}
				if _, cut := r.cuts[k]; cut {
					r.settle(w, sl)
					continue
				}
				if !slices.Contains(units, k) {
					units = append(units, k)
				}
				pending = true
				break
			}
		}
		// Every target any want waits on is asked at once, then the wants
		// pick again with the answers in.
		if len(need) > 0 {
			r.probe(need, ahead)
			continue
		}
		if !pending {
			break
		}
		var groups []pool.Group
		for _, k := range units {
			if err := r.addManifest(k.Slice); err != nil {
				return err
			}
			groups = append(groups, r.groups([]string{k.Slice}, []string{k.Arch})...)
		}
		if err := p.Pass(groups, r.done); err != nil {
			return err
		}
		for _, k := range units {
			if _, ok := r.cuts[k]; !ok {
				r.cuts[k] = &Cut{Key: k}
			}
			for _, wk := range order {
				w := wants[wk]
				if !w.done && w.arch == k.Arch && slices.Contains(w.cands, k.Slice) && !w.tried[k.Slice] {
					r.settle(w, k.Slice)
				}
			}
		}
	}
	for _, wk := range order {
		w := wants[wk]
		if w.err != nil {
			rep.Errors = append(rep.Errors, w.err)
		}
	}
	r.wants = wants
	return nil
}

// nextCandidate is the next slice to try for w: from its list, else from
// the validate trick's answers. need is a target the answer for which is
// not in yet; nothing is picked until it is.
func (r *run) nextCandidate(w *want) (sl, need string, ok bool) {
	if w.provider != "" || w.err != nil {
		return "", "", false
	}
	for {
		for _, c := range w.cands {
			if !w.tried[c] {
				return c, "", true
			}
		}
		if len(w.trick) == 0 {
			return "", "", false
		}
		t := w.trick[0]
		a, ok := r.answers[t]
		if !ok {
			return "", t, false
		}
		if a.err != nil {
			w.err = a.err
			return "", "", false
		}
		w.trick = w.trick[1:]
		for _, h := range a.hits {
			if !slices.Contains(w.cands, h.Slice) {
				w.cands = append(w.cands, h.Slice)
			}
		}
	}
}

// probe asks the validate trick about every target. First all of them at
// once, with the ones in ahead, which the wants come to next if these give
// no provider: that settles the targets nothing declares, as most are. Then
// the targets left, as many at once as cuts run, each on a copy of the
// release of its own. A declared target of ahead waits until it is asked
// for, since a want settled before then never needs its declarers.
func (r *run) probe(targets, ahead []string) {
	if r.trick == nil {
		r.trick = &validatetrick.Prober{Bin: r.opts.Runner.Bin, Release: r.opts.Release}
	}
	var batch []string
	for _, t := range slices.Concat(targets, ahead) {
		if _, ok := r.answers[t]; !ok && !r.declared[t] && !slices.Contains(batch, t) {
			batch = append(batch, t)
		}
	}
	for _, t := range batch {
		r.declared[t] = true
	}
	for _, t := range r.trick.Undeclared(r.ctx, batch) {
		delete(r.declared, t)
		r.answers[t] = answer{}
		if r.opts.Verbose != nil {
			fmt.Fprintf(r.opts.Verbose, "%s validate %s none\n", cut.Stamp(), t)
		}
	}
	targets = slices.DeleteFunc(slices.Clone(targets), func(t string) bool { _, ok := r.answers[t]; return ok })
	n := r.opts.Jobs
	if n <= 0 {
		n = runtime.NumCPU()
	}
	queue := make(chan string, len(targets))
	for _, t := range targets {
		queue <- t
	}
	close(queue)
	var wg sync.WaitGroup
	for range min(n, len(targets)) {
		wg.Go(func() {
			for t := range queue {
				hits, err := r.trick.All(r.ctx, t)
				r.mu.Lock()
				r.answers[t] = answer{hits, err}
				r.mu.Unlock()
				if r.opts.Verbose == nil || err != nil {
					continue
				}
				var by []string
				for _, h := range hits {
					by = append(by, h.Slice)
				}
				if len(by) == 0 {
					by = []string{"none"}
				}
				r.mu.Lock()
				fmt.Fprintf(r.opts.Verbose, "%s validate %s %s\n", cut.Stamp(), t, strings.Join(by, ","))
				r.mu.Unlock()
			}
		})
	}
	wg.Wait()
}

// settle tries the cut of candidate sl for w: a dlopen of one of the
// sonames, resolved there as the loader would, must select a file sl
// itself delivers, loadable, with a sound closure of its own. A file a
// slice sl depends on delivers is that slice's to confirm, so it joins the
// candidates.
func (r *run) settle(w *want, sl string) {
	w.tried[sl] = true
	c := r.cuts[Key{sl, w.arch}]
	switch {
	case c == nil || !c.Available:
		w.rejected = append(w.rejected, sl+": not available on "+w.arch)
		return
	case c.Err != nil:
		w.rejected = append(w.rejected, sl+": does not cut on "+w.arch)
		return
	}
	a := resolve.Arches[w.arch]
	var why string
	for _, s := range w.sonames {
		sel, findings, reason, err := resolve.CheckProvider(c.FS, a, s)
		switch {
		case err != nil:
			w.err = fmt.Errorf("%s on %s: %w", sl, w.arch, err)
			return
		case reason != "":
			if why == "" {
				why = reason
			}
			continue
		}
		owners := c.owners(sel)
		if !slices.Contains(owners, sl) {
			for _, o := range owners {
				if !slices.Contains(w.cands, o) {
					w.cands = append(w.cands, o)
				}
			}
			why = sel + " comes from " + strings.Join(owners, ", ")
			continue
		}
		if len(findings) > 0 {
			f := findings[0]
			why = fmt.Sprintf("%s: %s %s: %s", f.From, f.Kind, f.Name, f.Reason)
			continue
		}
		w.provider, w.soname, w.path = sl, s, sel
		return
	}
	if why == "" {
		why = "does not deliver " + strings.Join(w.sonames, " or ")
	}
	w.rejected = append(w.rejected, sl+": "+why)
}

func (r *run) sortedCuts() []Key {
	keys := make([]Key, 0, len(r.cuts))
	for k := range r.cuts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b Key) int {
		if c := strings.Compare(a.Slice, b.Slice); c != 0 {
			return c
		}
		return strings.Compare(a.Arch, b.Arch)
	})
	return keys
}

// owners is the slices the manifest says deliver p, sorted.
func (c *Cut) owners(p string) []string {
	out := slices.Clone(c.Owners[p])
	slices.Sort(out)
	return out
}

// attribute turns every named cut's findings and open dlopen entries into
// items: a finding counts against a named slice when the start node it was
// found from (or a script that runs that start node) is delivered by a
// named slice, else against the slice delivering the file it is about,
// reached through the named slice that was cut.
func (r *run) attribute(rep *Report) {
	seen := map[string]int{}
	add := func(it Item, chain []string) {
		it.Sev = it.Severity.String()
		k := strings.Join([]string{it.Arch, it.Against, it.Path, it.Kind, it.Name, it.Reason, it.Sev}, "\x00")
		if i, ok := seen[k]; ok {
			if !slices.ContainsFunc(rep.Items[i].Chains, func(c []string) bool { return slices.Equal(c, chain) }) {
				rep.Items[i].Chains = append(rep.Items[i].Chains, chain)
			}
			return
		}
		seen[k] = len(rep.Items)
		it.Chains = [][]string{chain}
		rep.Items = append(rep.Items, it)
	}
	for _, k := range r.sortedCuts() {
		c := r.cuts[k]
		if c.Err != nil {
			if r.named[k.Slice] || !errors.Is(c.Err, cut.ErrNoContent) && !errors.Is(c.Err, cut.ErrEssentialNotAvailable) {
				rep.Errors = append(rep.Errors, c.Err)
			}
			continue
		}
		if !r.named[k.Slice] || c.Res == nil {
			continue
		}
		for p, err := range c.Res.Unreadable {
			rep.Errors = append(rep.Errors, fmt.Errorf("%s on %s: %s: %w", k.Slice, k.Arch, p, err))
		}
		if c.Res.Unsupported != "" {
			rep.Errors = append(rep.Errors, fmt.Errorf("%s on %s: unsupported: %s", k.Slice, k.Arch, c.Res.Unsupported))
		}
		// A start node run by a script, or reached through a symlink, is
		// also the failure of whoever delivers that script or link, however
		// many hops back.
		runBy := map[string][]string{}
		for _, st := range c.Res.Starts {
			for _, e := range st.Exec {
				runBy[e] = append(runBy[e], st.Path)
			}
		}
		origins := func(start string) []string {
			var out []string
			seen := map[string]bool{start: true}
			queue := []string{start}
			for len(queue) > 0 {
				p := queue[0]
				queue = queue[1:]
				for _, o := range c.owners(p) {
					if !slices.Contains(out, o) {
						out = append(out, o)
					}
				}
				for _, q := range runBy[p] {
					if !seen[q] {
						seen[q] = true
						queue = append(queue, q)
					}
				}
			}
			return out
		}
		against := func(start, from string) (string, bool, string) {
			starts := origins(start)
			if slices.Contains(starts, k.Slice) {
				return k.Slice, true, ""
			}
			for _, s := range starts {
				if r.named[s] {
					return s, true, ""
				}
			}
			if o := c.owners(from); len(o) > 0 {
				return o[0], false, k.Slice
			}
			if len(starts) > 0 {
				return starts[0], false, k.Slice
			}
			return k.Slice, true, ""
		}
		ownerNote := func(from, to string) string {
			o := c.owners(from)
			if len(o) == 0 || slices.Contains(o, to) {
				return ""
			}
			return strings.Join(o, ", ")
		}
		for _, f := range c.Res.Findings {
			to, named, reached := against(f.Start, f.From)
			it := Item{Arch: k.Arch, Against: to, Named: named, Reached: reached, Severity: Severity(f.Severity),
				Path: f.From, Owner: ownerNote(f.From, to), Kind: f.Kind, Name: f.Name, Reason: f.Reason}
			if f.Via != nil {
				it.Feature, it.Priority = f.Via.Feature, f.Via.Priority
				it.Reason = fmt.Sprintf("in what dlopen %s loads: %s", f.Via.Soname, f.Reason)
			}
			add(it, f.Chain)
		}
		for _, o := range c.Res.Open {
			w := r.wants[wantKey(k.Arch, o.Absent)]
			to, named, reached := against(o.Start, o.From)
			it := Item{Arch: k.Arch, Against: to, Named: named, Reached: reached, Path: o.From, Owner: ownerNote(o.From, to),
				Kind: "dlopen", Name: strings.Join(o.Entry.Soname, " or "), Feature: o.Entry.Feature, Priority: o.Entry.Priority}
			if o.Entry.Priority == elf.PriorityStrings {
				it.Kind = elf.PriorityStrings
			}
			if w == nil || w.provider == "" {
				// No slice delivers an absent alternative: what the ones
				// the cut has but cannot load left behind stands.
				for _, f := range o.Failed {
					fto, fnamed, freached := against(f.Start, f.From)
					fi := Item{Arch: k.Arch, Against: fto, Named: fnamed, Reached: freached, Severity: Severity(f.Severity),
						Path: f.From, Owner: ownerNote(f.From, fto), Kind: f.Kind, Name: f.Name, Reason: f.Reason,
						Feature: o.Entry.Feature, Priority: o.Entry.Priority}
					if f.Via != nil && f.Kind != resolve.Dlopen {
						fi.Reason = fmt.Sprintf("in what dlopen %s loads: %s", f.Via.Soname, f.Reason)
					}
					add(fi, f.Chain)
				}
			}
			switch {
			case w != nil && w.provider != "":
				it.Severity, it.Reason = Info, "delivered by "+w.provider
				it.Provider, it.ProviderPath = w.provider, w.path
			case w != nil && w.err != nil:
				it.Severity, it.Reason = Hard, "lookup failed: "+w.err.Error()
			default:
				it.Severity, it.Reason = Soft, "no slice declares it"
				if w != nil && len(w.rejected) > 0 {
					it.Reason = "no slice delivers it (" + strings.Join(w.rejected, "; ") + ")"
				}
				switch o.Entry.Priority {
				case "required":
					it.Severity = Hard
				case elf.PriorityStrings:
					it.Severity = Info
				}
			}
			add(it, o.Chain)
		}
	}
	// A finding that counts against a named slice is not shown again under
	// the reached slice it was also found from.
	twin := func(it Item) string {
		return strings.Join([]string{it.Arch, it.Path, it.Kind, it.Name, it.Reason, it.Sev}, "\x00")
	}
	named := map[string]bool{}
	for _, it := range rep.Items {
		if it.Named {
			named[twin(it)] = true
		}
	}
	rep.Items = slices.DeleteFunc(rep.Items, func(it Item) bool { return !it.Named && named[twin(it)] })
}

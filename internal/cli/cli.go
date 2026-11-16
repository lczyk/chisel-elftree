// Package cli is chisel-elftree's command line: flags, the run, the text,
// tree and json reports, and the exit code.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/lczyk/chisel-coverage/pkg/cache"
	"github.com/lczyk/chisel-coverage/pkg/cut"
	"github.com/lczyk/chisel-coverage/pkg/packageslicesfile"
	"github.com/lczyk/chisel-coverage/pkg/pool"
	"github.com/lczyk/chisel-coverage/pkg/release"
	"gopkg.in/yaml.v3"

	"github.com/lczyk/chisel-elftree/internal/check"
	"github.com/lczyk/chisel-elftree/internal/manifest"
	"github.com/lczyk/chisel-elftree/internal/resolve"
	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

type options struct {
	Release     string   `long:"release" value-name:"<dir|name>" default:"." description:"chisel-releases checkout, or a release name like ubuntu-26.04 fetched by chisel into its cache"`
	Arches      []string `long:"arch" value-name:"<a>[,<a>...]" description:"architectures to check; \"all\" for every one (default: host)"`
	Slices      []string `long:"slice" value-name:"<s>[,<s>...]" description:"only these slices, bare or <package>_<slice> (default: all)"`
	Files       []string `long:"file" value-name:"<glob>[,...]" description:"only the files matching, and what they go on to, are checked (chisel glob syntax)"`
	Prune       []string `long:"prune" value-name:"<glob>[,...]" description:"leave the libraries matching by name or path out of the tree and the info lines; a finding in one still shows (chisel glob syntax)"`
	Fold        []string `long:"fold" value-name:"<what>[,...]" description:"with --tree, what not to draw: \"missing\" is what a dlopen outside the cut would load, \"repeats\" a library drawn already, as lddtree does"`
	NoStrings   bool     `long:"no-strings" description:"do not scan the files' strings for library names no link table or dlopen note has"`
	Tree        bool     `short:"T" long:"tree" description:"draw each named slice's graph instead of the findings only"`
	JSON        bool     `long:"json" description:"machine-readable output, unpruned"`
	FailMissing bool     `long:"fail-missing" description:"exit 1 on a hard finding, or an unresolvable required dlopen, counting against a named slice"`
	Strict      bool     `long:"strict" description:"with --fail-missing, any unresolvable dlopen counting against a named slice fails too"`
	FailReached bool     `long:"fail-reached" description:"with --fail-missing, findings counting only against reached slices fail too"`
	NoGroup     bool     `long:"no-group" description:"one block per architecture with its real paths, instead of folding architectures with the same result"`
	Keep        bool     `long:"keep" description:"keep the temp releases and rootfs dirs"`
	Jobs        int      `short:"j" long:"jobs" value-name:"<n>" default:"-1" description:"cuts to run at once; -1 for one per cpu"`
	Verbose     []bool   `short:"v" long:"verbose" description:"one line per cut on stderr; twice also streams chisel's output"`
	Version     bool     `long:"version" description:"print the version and exit"`

	help bool // -h or --help was given
}

const longHelp = `lddtree for chisel slices. each slice named is cut with the real chisel,
essentials and all, on every architecture asked for, and every file the cut
delivers is followed the way the kernel and the dynamic loader would.

what a cut is read for, the start nodes:
- executable: an ELF program, static or with an interpreter
- shared library: an ELF library, loaded on its own as dlopen would
- script: a file starting with #!
- symlink: followed to where it points

what is followed from them, the edges, as --tree names them:
- interp: an executable's PT_INTERP, the loader itself
- needed: DT_NEEDED, searched for as ld.so does (rpath, runpath, hwcaps, ...)
- filter, auxiliary: DT_FILTER and DT_AUXILIARY
- preload: /etc/ld.so.preload
- version: a symbol version a needed library must define
- shebang, env: a script's interpreter, and the command env runs
- dlopen: an entry of the ELF's .note.dlopen, as the FDO spec has it
- strings: a library's name among the file's strings that nothing above
explains, likely a dlopen with no note; never more than a warning
- symlink: a link's target

what is found, by severity:
- hard: it does not run or load as cut, or a required dlopen is not delivered
- soft: no slice in the release delivers a recommended or suggested dlopen
- warning: the loader carries on, but something is off
- info: a slice delivers a dlopen target, but it is not an essential

a finding counts against the named slice whose file it starts from, else it
is shown as reached via that slice, against the slice delivering the file.
config-driven loading (nsswitch, pam, openssl.cnf, gconv) is not followed.

a package may be given as the path of its file, slices/<package>.yaml, and
--slice picks its slices as in the other chisel tools. --file narrows the
check to the start nodes matching, and --prune leaves known libraries such as
libc.so.6 or ld-linux-* out of what is drawn. both take chisel's globs: ? and
* stop at a slash, ** does not. a glob with a slash matches a whole path, one
without a file name (and, for --prune, a library's name as asked for), and
--prune @ld is the arch's dynamic loader, whatever its name there. the "chisel" binary is found on PATH, or set
CHISEL=/path/to/chisel. "version" and "help" as the first argument are
--version and --help.`

// folds are what --fold takes.
var folds = []string{"missing", "repeats"}

func newParser(o *options) *flags.Parser {
	p := flags.NewNamedParser("chisel-elftree", flags.HelpFlag|flags.PassDoubleDash)
	p.Usage = "[flags] <package>..."
	p.LongDescription = longHelp
	if _, err := p.AddGroup("flags", "", o); err != nil {
		panic(err)
	}
	return p
}

// parseArgs parses the command line as the other chisel tools do: list flags
// take comma-separated values and may repeat, -h, --help and --version work
// wherever they land, and a package given as the path of its file is the
// package. Help is not an error: the usage goes to help and o.help is set.
func parseArgs(args []string, help io.Writer) (o options, pkgs []string, err error) {
	p := newParser(&o)
	pkgs, err = p.ParseArgs(args)
	if err != nil {
		var fe *flags.Error
		if errors.As(err, &fe) && fe.Type == flags.ErrHelp {
			p.WriteHelp(help)
			o.help = true
			return o, nil, nil
		}
		return o, nil, err
	}
	for _, l := range []*[]string{&o.Arches, &o.Slices, &o.Files, &o.Prune, &o.Fold} {
		*l = splitLists(*l)
	}
	for _, f := range o.Fold {
		if !slices.Contains(folds, f) {
			return o, nil, fmt.Errorf("--fold %s: not one of %s", f, strings.Join(folds, ", "))
		}
	}
	for i, pkg := range pkgs {
		pkgs[i] = packageslicesfile.Package(pkg)
	}
	return o, pkgs, nil
}

// splitLists splits every value of a repeatable list flag on commas and drops
// the blanks, so --arch amd64,arm64 and --arch amd64 --arch arm64 are the same.
func splitLists(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// Main runs the tool and returns its exit code: 0 ran fine, 1 a failure with
// --fail-missing, 2 a usage error or a failed cut, 130 interrupted.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _, _ = parseArgs([]string{"--help"}, stderr)
		return 2
	}
	switch args[0] {
	case "version":
		args = []string{"--version"}
	case "help":
		args = []string{"--help"}
	}
	o, pkgs, err := parseArgs(args, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if o.help {
		return 0
	}
	if o.Version {
		fmt.Fprintln(stdout, "chisel-elftree", version())
		return 0
	}
	if len(pkgs) == 0 {
		fmt.Fprintln(stderr, "error: no packages given")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := &cut.Runner{Bin: cut.Binary()}
	var verbose io.Writer
	if len(o.Verbose) > 0 {
		verbose = stderr
	}
	if len(o.Verbose) > 1 {
		runner.Verbose = stderr
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	rel, err := release.Resolve(ctx, o.Release, cache.Dir(), runner.Fetch, logf)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rootfs.Strings = !o.NoStrings
	arches, err := pool.ResolveArches(o.Arches)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for _, a := range arches {
		if _, ok := resolve.Arches[a]; !ok {
			fmt.Fprintln(stderr, "error: no loader model for", a)
			return 2
		}
	}
	named, err := selected(rel, pkgs, o.Slices)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep, err := check.Run(ctx, check.Options{Release: rel, Arches: arches, Named: named, Files: o.Files, Jobs: o.Jobs,
		Cache: cache.Dir(), Runner: runner, Keep: o.Keep, Log: stderr, Verbose: verbose})
	if err != nil {
		if ctx.Err() != nil {
			return 130
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	switch {
	case o.JSON:
		renderJSON(stdout, rep)
	case o.Tree:
		renderTree(stdout, rep, o.Prune, o.Fold, styleFor(stdout))
	default:
		renderText(stdout, rep, o.NoGroup, o.Prune, styleFor(stdout))
	}
	if len(o.Verbose) > 0 && rep.Validations > 0 {
		fmt.Fprintf(stderr, "%s %d validations\n", cut.Stamp(), rep.Validations)
	}
	for _, e := range rep.Errors {
		fmt.Fprintln(stderr, styleFor(stderr).wrap(colours.red, "error:"), e)
	}
	if len(rep.Errors) > 0 {
		return 2
	}
	if o.FailMissing && fails(rep, o.Strict, o.FailReached) {
		return 1
	}
	return 0
}

// selected is the slices to check, <package>_<slice>, as --slice keeps them
// of the packages given, each package read from wherever chisel would.
func selected(rel string, pkgs, only []string) ([]string, error) {
	var files []*packageslicesfile.File
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		p, err := manifest.FindFile(rel, pkg)
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if len(doc.Content) == 0 {
			return nil, fmt.Errorf("%s: empty", p)
		}
		f := &packageslicesfile.File{Package: pkg}
		if ss := manifest.Value(doc.Content[0], "slices"); ss != nil {
			for i := 0; i+1 < len(ss.Content); i += 2 {
				f.Slices = append(f.Slices, packageslicesfile.Slice{Name: ss.Content[i].Value})
			}
		}
		files = append(files, f)
	}
	keep, err := packageslicesfile.Select(files, only)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		for _, s := range keep[f.Package] {
			out = append(out, f.Package+"_"+s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no slices to check")
	}
	return out, nil
}

func fails(rep *check.Report, strict, reached bool) bool {
	for _, it := range rep.Items {
		if !it.Named && !reached {
			continue
		}
		if it.Severity == check.Hard || strict && it.Severity == check.Soft {
			return true
		}
	}
	return false
}

// version is the module version the binary was built from.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}

func renderJSON(w io.Writer, rep *check.Report) {
	type linkOut struct {
		From   string   `json:"from"`
		Kind   string   `json:"kind"`
		Name   string   `json:"name"`
		To     string   `json:"to"`
		Owners []string `json:"owners,omitempty"`
		Hops   []string `json:"hops,omitempty"`
		Dlopen string   `json:"dlopen,omitempty"` // the soname whose dlopen loaded it
		// for a dlopen link: its note entry, and whether the loader had the
		// target loaded already
		Feature  string `json:"feature,omitempty"`
		Priority string `json:"priority,omitempty"`
		Reused   bool   `json:"reused,omitempty"`
	}
	type startOut struct {
		Path   string    `json:"path"`
		Kind   string    `json:"kind"`
		Owners []string  `json:"owners"`
		Exec   []string  `json:"exec,omitempty"`
		Links  []linkOut `json:"links"`
	}
	type cutOut struct {
		Slice     string     `json:"slice"`
		Arch      string     `json:"arch"`
		Available bool       `json:"available"`
		Version   string     `json:"version,omitempty"`
		NoFile    bool       `json:"no_file,omitempty"`
		Error     string     `json:"error,omitempty"`
		Starts    []startOut `json:"starts,omitempty"`
		Foreign   []string   `json:"foreign,omitempty"`
	}
	out := struct {
		Arches []string     `json:"arches"`
		Named  []string     `json:"named"`
		Cuts   []cutOut     `json:"cuts"`
		Items  []check.Item `json:"findings"`
	}{Arches: rep.Arches, Named: rep.Named, Items: rep.Items}
	if out.Items == nil {
		out.Items = []check.Item{}
	}
	for _, s := range rep.Named {
		for _, a := range rep.Arches {
			c := rep.Cuts[check.Key{Slice: s, Arch: a}]
			if c == nil {
				continue
			}
			co := cutOut{Slice: s, Arch: a, Available: c.Available, Version: c.Version, NoFile: c.NoFile}
			if c.Err != nil {
				co.Error = c.Err.Error()
			}
			if c.Res != nil {
				co.Foreign = c.Res.Foreign
				// The slice's own start nodes, and what they run or link to,
				// however many hops on.
				byPath := map[string]resolve.Start{}
				for _, st := range c.Res.Starts {
					byPath[st.Path] = st
				}
				keep := map[string]bool{}
				var queue []string
				for _, st := range c.Res.Starts {
					if slices.Contains(c.Owners[st.Path], s) {
						keep[st.Path] = true
						queue = append(queue, st.Path)
					}
				}
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
				for _, st := range c.Res.Starts {
					if !keep[st.Path] {
						continue
					}
					so := startOut{Path: st.Path, Kind: st.Kind, Owners: c.Owners[st.Path], Exec: st.Exec, Links: []linkOut{}}
					for _, l := range st.Links {
						lo := linkOut{From: l.From, Kind: l.Kind, Name: l.Name, To: l.To, Owners: c.Owners[l.To]}
						for _, h := range l.Hops {
							lo.Hops = append(lo.Hops, h.Link+" -> "+h.Target)
						}
						if l.Via != nil {
							lo.Dlopen = l.Via.Soname
						}
						if l.Note != nil {
							lo.Feature, lo.Priority, lo.Reused = l.Note.Feature, l.Note.Priority, l.Reused
						}
						so.Links = append(so.Links, lo)
					}
					co.Starts = append(co.Starts, so)
				}
			}
			out.Cuts = append(out.Cuts, co)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

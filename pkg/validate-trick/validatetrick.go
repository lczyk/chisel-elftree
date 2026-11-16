// Package validatetrick finds which slices of a chisel release declare a
// path, with chisel's own glob matching and without cutting anything.
//
// chisel validates a release whenever it loads one, offline, and two
// packages declaring overlapping paths fail that validation with an error
// naming both slices and both paths. So a copy of the release gets a probe
// package declaring the path as generated text, which conflicts with any
// extracted content of another package, and each conflict chisel reports
// names one declarer. That declarer's key is then deleted from the copy and
// the release validated again, until it validates: then nothing else
// declares the path.
package validatetrick

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// ProbePackage is the package the probe is declared in; ProbeSlice its one
// slice.
const (
	ProbePackage = "elftree-probe"
	ProbeSlice   = ProbePackage + "_probe"
)

// Hit is a slice declaring a target, under Key: the target itself or a
// glob covering it.
type Hit struct {
	Target string
	Slice  string // <package>_<slice>
	Key    string
}

// Prober asks chisel, at Bin, about the release at Release. Its methods may
// be called concurrently.
type Prober struct {
	Bin         string
	Release     string
	validations atomic.Int64
}

// Validations is how many times chisel was asked, for the curious.
func (p *Prober) Validations() int { return int(p.validations.Load()) }

// The messages chisel's release validation (internal/setup) fails with
// when two packages declare overlapping paths: a glob against a path, the
// same path, and a path with prefer relationships the other package is
// not part of.
var (
	globConflict   = regexp.MustCompile(`(?m)slices (\S+) and (\S+) conflict on (\S+) and (\S+)\s*$`)
	pathConflict   = regexp.MustCompile(`(?m)slices (\S+) and (\S+) conflict on (\S+)\s*$`)
	preferConflict = regexp.MustCompile(`(?m)package "([^"]+)" and "([^"]+)" conflict on (\S+) without prefer relationship`)
)

// Conflict is what one failed validation said: the declaring slice, its
// key and the probe's path it covers, or for a prefer conflict the packages
// and the path.
type Conflict struct {
	Slice    string
	Key      string
	Target   string
	Prefer   bool
	Packages []string
}

// Parse reads chisel's output for a conflict with the probe. ok is false
// when the output holds none, which is then another error.
func Parse(out string) (c Conflict, ok bool) {
	if m := globConflict.FindStringSubmatch(out); m != nil {
		return pick(m[1], m[3], m[2], m[4])
	}
	if m := preferConflict.FindStringSubmatch(out); m != nil {
		// chisel names a package of the prefer relationship and the one
		// outside it, which need not be the probe: the caller checks that
		// the path is its target.
		return Conflict{Key: m[3], Target: m[3], Prefer: true, Packages: []string{m[1], m[2]}}, true
	}
	if m := pathConflict.FindStringSubmatch(out); m != nil {
		return pick(m[1], m[3], m[2], m[3])
	}
	return Conflict{}, false
}

// pick takes the side of a conflict that is not the probe.
func pick(slice1, path1, slice2, path2 string) (Conflict, bool) {
	switch {
	case slice1 == ProbeSlice && slice2 != ProbeSlice:
		return Conflict{Slice: slice2, Key: path2, Target: path1}, true
	case slice2 == ProbeSlice && slice1 != ProbeSlice:
		return Conflict{Slice: slice1, Key: path1, Target: path2}, true
	}
	return Conflict{}, false
}

// Declarers is every slice declaring target, one at a time: the caller
// stops pulling once satisfied. Each call works on a copy of the release
// of its own, so the targets do not share what was deleted, and calls may
// run at once. Any failure
// other than a conflict with the probe, or a conflict that names a key the
// copy does not have, is an error and ends the sequence: never a silent
// "nothing declares it".
func (p *Prober) Declarers(ctx context.Context, target string) iter.Seq2[Hit, error] {
	return func(yield func(Hit, error) bool) {
		dir, err := linkCopy(p.Release)
		if err != nil {
			yield(Hit{}, err)
			return
		}
		defer os.RemoveAll(dir)
		if err := writeProbe(dir, target); err != nil {
			yield(Hit{}, err)
			return
		}
		for {
			out, err := p.validate(ctx, dir)
			if err == nil {
				return
			}
			if ctx.Err() != nil {
				yield(Hit{}, ctx.Err())
				return
			}
			c, ok := Parse(out)
			if !ok {
				yield(Hit{}, fmt.Errorf("chisel find --release %s: %w\n%s", dir, err, strings.TrimSpace(out)))
				return
			}
			if c.Prefer && c.Key != target {
				yield(Hit{}, fmt.Errorf("chisel find --release %s: a prefer conflict on %s, not on the probe's %s\n%s", dir, c.Key, target, strings.TrimSpace(out)))
				return
			}
			if c.Prefer {
				// A path with prefer relationships is a literal key in
				// every package that declares it, so string equality finds
				// them all, and the target is done.
				hits, err := literal(dir, c.Key)
				if err != nil {
					yield(Hit{}, err)
					return
				}
				for _, s := range hits {
					if !yield(Hit{Target: target, Slice: s, Key: c.Key}, nil) {
						return
					}
				}
				return
			}
			if !yield(Hit{Target: target, Slice: c.Slice, Key: c.Key}, nil) {
				return
			}
			if err := deleteKey(dir, c.Slice, c.Key); err != nil {
				yield(Hit{}, err)
				return
			}
		}
	}
}

// Undeclared is the targets no slice declares, found with one probe
// declaring them all: a validation that passes clears every target still in
// the probe, and one that fails names a target a slice declares, which
// leaves the probe before the next. So the targets nothing declares, as most
// are, cost one copy of the release and one validation between them. A
// target not returned is declared, or was not settled (chisel failed for
// something else, or ctx is done): Declarers says which, and by what.
func (p *Prober) Undeclared(ctx context.Context, targets []string) []string {
	left := slices.Clone(targets)
	if len(left) == 0 {
		return nil
	}
	dir, err := linkCopy(p.Release)
	if err != nil {
		return nil
	}
	defer os.RemoveAll(dir)
	for len(left) > 0 {
		if err := writeProbe(dir, left...); err != nil {
			return nil
		}
		out, err := p.validate(ctx, dir)
		if err == nil {
			return left
		}
		c, ok := Parse(out)
		i := slices.Index(left, c.Target)
		if !ok || i < 0 || ctx.Err() != nil {
			return nil
		}
		left = slices.Delete(left, i, i+1)
	}
	return nil
}

// All is every slice declaring target.
func (p *Prober) All(ctx context.Context, target string) ([]Hit, error) {
	var out []Hit
	for h, err := range p.Declarers(ctx, target) {
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

func (p *Prober) validate(ctx context.Context, dir string) (string, error) {
	p.validations.Add(1)
	cmd := exec.CommandContext(ctx, p.Bin, "find", "--release", dir, ProbePackage+"-nothing")
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// linkCopy makes a release dir chisel reads as src: chisel.yaml copied, and
// every slice definition file a symlink to its source, which deleteKey
// replaces with a file of its own before writing. Nothing else of src is
// read by chisel, so nothing else is copied.
func linkCopy(src string) (string, error) {
	src, err := filepath.Abs(src)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(src, "chisel.yaml"))
	if err != nil {
		return "", fmt.Errorf("%s is not a chisel release: %w", src, err)
	}
	dir, err := os.MkdirTemp("", "chisel-elftree-probe-*")
	if err != nil {
		return "", err
	}
	err = os.WriteFile(filepath.Join(dir, "chisel.yaml"), raw, 0644)
	for _, sub := range sliceDirs {
		if err != nil {
			break
		}
		root := filepath.Join(src, sub)
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipAll
				}
				return err
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			if d.IsDir() {
				return os.MkdirAll(filepath.Join(dir, rel), 0755)
			}
			return os.Symlink(p, filepath.Join(dir, rel))
		})
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func writeProbe(dir string, targets ...string) error {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// The text is unique, since chisel lets two packages declare the same
	// text at one path without a conflict.
	contents := map[string]any{}
	for _, t := range targets {
		contents[t] = map[string]any{"text": "chisel-elftree probe " + hex.EncodeToString(nonce)}
	}
	doc := map[string]any{
		"package": ProbePackage,
		"slices":  map[string]any{"probe": map[string]any{"contents": contents}},
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "slices"), 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "slices", ProbePackage+".yaml"), b, 0644)
}

var sliceDirs = []string{"slices", "bin-slices"}

// files lists the package files of the release at dir, by package name.
func files(dir string) (map[string]string, error) {
	out := map[string]string{}
	for _, sub := range sliceDirs {
		root := filepath.Join(dir, sub)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipAll
				}
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
				out[strings.TrimSuffix(filepath.Base(p), ".yaml")] = p
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readDoc(p string) (*yaml.Node, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: not a mapping", p)
	}
	return &doc, nil
}

func value(m *yaml.Node, key string) *yaml.Node {
	if m != nil && m.Kind == yaml.AliasNode {
		m = m.Alias
	}
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			if v.Kind == yaml.AliasNode {
				v = v.Alias
			}
			return v
		}
	}
	return nil
}

// deleteKey deletes key from the contents of slice in the release at dir.
func deleteKey(dir, slice, key string) error {
	pkg, name, ok := strings.Cut(slice, "_")
	if !ok {
		return fmt.Errorf("chisel named %q, which is not a slice", slice)
	}
	all, err := files(dir)
	if err != nil {
		return err
	}
	p, ok := all[pkg]
	if !ok {
		return fmt.Errorf("chisel named slice %s, whose package has no file", slice)
	}
	doc, err := readDoc(p)
	if err != nil {
		return err
	}
	contents := value(value(value(doc.Content[0], "slices"), name), "contents")
	if contents == nil || contents.Kind != yaml.MappingNode {
		return fmt.Errorf("chisel named %s on %s, which has no contents", slice, key)
	}
	for i := 0; i+1 < len(contents.Content); i += 2 {
		if contents.Content[i].Value == key {
			contents.Content = slices.Delete(contents.Content, i, i+2)
			out, err := yaml.Marshal(doc)
			if err != nil {
				return err
			}
			// p may be a link to the source release, which must not change:
			// the link goes and a file of the copy's own takes its place.
			if err := os.Remove(p); err != nil {
				return err
			}
			return os.WriteFile(p, out, 0644)
		}
	}
	return fmt.Errorf("chisel named %s on %s, which the copy no longer has", slice, key)
}

// literal is every slice but the probe with key among its contents keys,
// in package then slice order.
func literal(dir, key string) ([]string, error) {
	all, err := files(dir)
	if err != nil {
		return nil, err
	}
	pkgs := make([]string, 0, len(all))
	for pkg := range all {
		if pkg != ProbePackage {
			pkgs = append(pkgs, pkg)
		}
	}
	slices.Sort(pkgs)
	var out []string
	for _, pkg := range pkgs {
		doc, err := readDoc(all[pkg])
		if err != nil {
			return nil, err
		}
		ss := value(doc.Content[0], "slices")
		if ss == nil || ss.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(ss.Content); i += 2 {
			name := ss.Content[i].Value
			if c := value(value(ss, name), "contents"); c != nil && c.Kind == yaml.MappingNode && hasKey(c, key) {
				out = append(out, pkg+"_"+name)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("chisel reported a prefer conflict on %s, which no slice lists", key)
	}
	return out, nil
}

func hasKey(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return true
		}
	}
	return false
}

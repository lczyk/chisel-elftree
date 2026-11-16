// Package lookup holds what the provider lookup reads without chisel: every
// contents key of a release as written, and the shortlist of the literal
// keys a slice would write for a library. Nothing here evaluates a glob: a
// key is only ever compared as a string, and every candidate it gives is
// confirmed by a cut.
package lookup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Decl is a slice declaring a key, on Arch only when Arch is set.
type Decl struct {
	Slice string
	Arch  []string
}

// Index maps every contents key of a release, as written, to the slices
// declaring it.
type Index map[string][]Decl

// Read indexes the release at dir.
func Read(dir string) (Index, error) {
	ix := Index{}
	for _, sub := range []string{"slices", "bin-slices"} {
		root := filepath.Join(dir, sub)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipAll
				}
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".yaml") {
				return nil
			}
			if err := ix.add(p); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return ix, nil
}

type pathInfo struct {
	Arch yaml.Node `yaml:"arch"`
}

func (ix Index) add(p string) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var doc struct {
		Package string `yaml:"package"`
		Slices  map[string]struct {
			Contents map[string]*pathInfo `yaml:"contents"`
		} `yaml:"slices"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	for name, s := range doc.Slices {
		for key, info := range s.Contents {
			d := Decl{Slice: doc.Package + "_" + name}
			if info != nil {
				switch info.Arch.Kind {
				case yaml.ScalarNode:
					d.Arch = []string{info.Arch.Value}
				case yaml.SequenceNode:
					for _, c := range info.Arch.Content {
						d.Arch = append(d.Arch, c.Value)
					}
				}
			}
			ix[key] = append(ix[key], d)
		}
	}
	return nil
}

// Candidates is the slices declaring any of keys on arch, each once, in
// the order of keys.
func (ix Index) Candidates(keys []string, arch string) []string {
	var out []string
	for _, k := range keys {
		decls := slices.Clone(ix[k])
		slices.SortFunc(decls, func(a, b Decl) int { return strings.Compare(a.Slice, b.Slice) })
		for _, d := range decls {
			if d.Arch != nil && !slices.Contains(d.Arch, arch) {
				continue
			}
			if !slices.Contains(out, d.Slice) {
				out = append(out, d.Slice)
			}
		}
	}
	return out
}

// Shortlist is the keys a slice would most likely write for the library
// name on an arch with the multiarch triplet: the lib dirs as slices spell
// them, with each basename shape slices use for a soname. A name with a
// slash is taken as a path, alone.
func Shortlist(name, triplet string) []string {
	if strings.Contains(name, "/") {
		return []string{name}
	}
	dirs := []string{"/usr/lib/*-linux-*", "/lib/*-linux-*", "/usr/lib/" + triplet, "/lib/" + triplet}
	bases := []string{name}
	if stem, ver, ok := strings.Cut(name, ".so"); ok && stem != "" {
		if ver != "" {
			bases = append(bases, name+"*", name+".*")
		}
		bases = append(bases, stem+".so.*", stem+".so*")
	}
	var out []string
	for _, d := range dirs {
		for _, b := range bases {
			k := d + "/" + b
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	return out
}

// Targets is where the loader's default search would find name, given the
// arch's default dirs, each under every spelling merged-usr makes equal.
// A name with a slash is that path and its spellings.
func Targets(name string, dirs []string) []string {
	var out []string
	add := func(p string) {
		for _, q := range Spellings(p) {
			if !slices.Contains(out, q) {
				out = append(out, q)
			}
		}
	}
	if strings.Contains(name, "/") {
		add(name)
		return out
	}
	for _, d := range dirs {
		add(d + "/" + name)
	}
	return out
}

// merged are the top-level dirs ubuntu's merged-usr links into /usr.
var merged = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// Spellings is p and the path merged-usr makes it the same as.
func Spellings(p string) []string {
	for _, m := range merged {
		if p == m || strings.HasPrefix(p, m+"/") {
			return []string{p, "/usr" + p}
		}
		if u := "/usr" + m; p == u || strings.HasPrefix(p, u+"/") {
			return []string{p, strings.TrimPrefix(p, "/usr")}
		}
	}
	return []string{p}
}

// Package manifest has chisel say which slices every path of a cut comes
// from: a slice of the tool's own, added to a copy of the package's file,
// generates chisel's manifest, which is then read with chisel's own reader.
// It follows what chisel-diff does.
package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/canonical/chisel/public/manifest"
	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

// Slice is the slice Add gives a package, Dir where chisel writes the
// manifest, and File the manifest itself.
const (
	Slice = "elftree-manifest"
	Dir   = "/var/lib/chisel-elftree"
	File  = Dir + "/manifest.wall"
)

// sliceDirs are where chisel reads package files from.
var sliceDirs = []string{"slices", "bin-slices"}

// FindFile is the file of pkg in the release at dir.
func FindFile(dir, pkg string) (string, error) {
	var found string
	for _, sub := range sliceDirs {
		root := filepath.Join(dir, sub)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipAll
				}
				return err
			}
			if !d.IsDir() && filepath.Base(p) == pkg+".yaml" {
				found = p
				return fs.SkipAll
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		if found != "" {
			return found, nil
		}
	}
	return "", fmt.Errorf("package %s has no file in %s", pkg, dir)
}

// Add gives pkg, in the release at dir, the slice that has chisel write its
// manifest. It is for a copy of a release. The file is rewritten from its
// yaml nodes, so anchors and aliases stay. A package with the slice already
// is left as it is.
func Add(dir, pkg string) error {
	p, err := FindFile(dir, pkg)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a mapping", p)
	}
	root := doc.Content[0]
	all := Value(root, "slices")
	if all == nil {
		all = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "slices"}, all)
	}
	if all.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: slices is not a mapping", p)
	}
	if Value(all, Slice) != nil {
		return nil
	}
	var slice yaml.Node
	if err := yaml.Unmarshal([]byte("contents:\n  "+Dir+"/**: {generate: manifest}\n"), &slice); err != nil {
		return err
	}
	all.Content = append(all.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: Slice}, slice.Content[0])
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return os.WriteFile(p, out, 0644)
}

// Value is the value of key in mapping m, aliases followed, or nil.
func Value(m *yaml.Node, key string) *yaml.Node {
	if m == nil {
		return nil
	}
	if m.Kind == yaml.AliasNode {
		m = m.Alias
	}
	if m.Kind != yaml.MappingNode {
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

// Origins reads the manifest under root for the slices each path comes
// from: the path, without a trailing slash, to its slices as
// <package>_<slice>. A directory chisel made only to hold others is not in
// it.
func Origins(root string) (map[string][]string, error) {
	p := filepath.Join(root, File)
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	m, err := manifest.Read(dec)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	out := map[string][]string{}
	err = m.IteratePaths("", func(mp *manifest.Path) error {
		out[strings.TrimSuffix(mp.Path, "/")] = mp.Slices
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return out, nil
}

// Own reports whether the rootfs path p is the tool's own manifest dir or
// under it, so a listing can leave it out. The parents of the dir are left
// in: they hold, or may hold, what slices deliver.
func Own(p string) bool {
	return p == Dir || strings.HasPrefix(p, Dir+"/")
}

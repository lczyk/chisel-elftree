// Package rootfs reads a cut's root filesystem into memory: every entry with
// its kind, a symlink's target, an ELF file's loader metadata, a script's
// shebang, and the few text files the loader itself reads. Paths are then
// looked up the way the kernel walks them inside that root, symlinks and
// all, so the rootfs on disk can go once it is read.
package rootfs

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/lczyk/chisel-elftree/internal/elf"
)

// Kind is what an entry is.
type Kind int

const (
	Dir Kind = iota
	File
	Symlink
	Other
)

// Node is one entry of the rootfs.
type Node struct {
	Path    string
	Kind    Kind
	Mode    fs.FileMode
	Target  string    // a symlink's target as written
	ELF     *elf.File // a regular file that is an ELF file
	ELFErr  error     // an ELF file the reader could not read
	Shebang *Shebang  // a regular file starting with #!
	Text    string    // the loader's own text files, see loaderFile
}

// Shebang is the interpreter line of a script, split as the kernel splits
// it: the interpreter, and everything after it as one argument.
type Shebang struct {
	Interp string
	Arg    string
}

// FS is a rootfs in memory, keyed by absolute path, "/" itself included.
type FS struct {
	Nodes map[string]*Node
}

// Strings says whether an ELF file's strings are scanned for library names.
var Strings = true

// loaderFile reports whether the loader reads p itself, so its text is kept.
func loaderFile(p string) bool {
	return p == "/etc/ld.so.preload" || p == "/etc/ld.so.conf" ||
		strings.HasPrefix(p, "/etc/ld.so.conf.d/") && strings.HasSuffix(p, ".conf")
}

// Read walks root into an FS. skip, when set, leaves out an entry by its
// path in the rootfs (the tool's own manifest, say).
func Read(root string, skip func(string) bool) (*FS, error) {
	out := &FS{Nodes: map[string]*Node{"/": {Path: "/", Kind: Dir, Mode: fs.ModeDir | 0755}}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		abs := "/" + filepath.ToSlash(rel)
		if skip != nil && skip(abs) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		n := &Node{Path: abs, Mode: info.Mode()}
		switch {
		case d.IsDir():
			n.Kind = Dir
		case info.Mode()&fs.ModeSymlink != 0:
			n.Kind = Symlink
			if n.Target, err = os.Readlink(p); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			n.Kind = File
			if err := readFile(p, n); err != nil {
				return fmt.Errorf("%s: %w", abs, err)
			}
		default:
			n.Kind = Other
		}
		out.Nodes[abs] = n
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func readFile(p string, n *Node) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 4)
	k, _ := f.ReadAt(head, 0)
	head = head[:k]
	switch {
	case elf.Magic(head):
		if !Strings {
			n.ELF, n.ELFErr = elf.Read(f)
			break
		}
		// The strings scan wants the whole file, so the ELF reader takes
		// it from the same bytes. Neither keeps any of them.
		data, release, err := contents(f)
		if err != nil {
			return err
		}
		defer release()
		n.ELF, n.ELFErr = elf.ReadBytes(data)
		if n.ELF != nil {
			var names []string
			for _, s := range n.ELF.Unexplained(elf.Sonames(data)) {
				// The file's own name, a dev link's say, explains itself.
				if s != path.Base(n.Path) && !strings.HasPrefix(path.Base(n.Path), s+".") {
					names = append(names, s)
				}
			}
			n.ELF.Strings = names
		}
	case strings.HasPrefix(string(head), "#!"):
		line, _ := bufio.NewReader(f).ReadString('\n')
		n.Shebang = parseShebang(line)
	}
	if loaderFile(n.Path) {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n.Text = string(b)
	}
	return nil
}

// parseShebang splits a #! line the way linux's binfmt_script does: blanks
// after #! skipped, the interpreter up to the next blank, the rest trimmed
// as one argument.
func parseShebang(line string) *Shebang {
	line = strings.TrimPrefix(line, "#!")
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimLeft(line, " \t")
	if line == "" {
		return &Shebang{}
	}
	interp, arg, _ := strings.Cut(line, " ")
	if i := strings.IndexByte(interp, '\t'); i >= 0 {
		interp, arg = interp[:i], interp[i+1:]+" "+arg
	}
	return &Shebang{Interp: interp, Arg: strings.Trim(arg, " \t")}
}

// ErrLoop is a lookup that met too many symlinks, a loop as a rule.
var ErrLoop = errors.New("too many levels of symbolic links")

// Hop is one symlink followed on the way to a path.
type Hop struct {
	Link   string // the symlink's path
	Target string // its target as written
}

// Lookup walks p inside the rootfs as the kernel would, following every
// symlink, an absolute target from the root, and returns the path it ends
// at and the symlinks it followed. A component that is missing, a symlink
// loop, or a non-directory with more path after it is an error, returned
// with the hops so far.
func (f *FS) Lookup(p string) (string, []Hop, error) {
	if !strings.HasPrefix(p, "/") {
		return "", nil, fmt.Errorf("%s is not an absolute path", p)
	}
	var hops []Hop
	cur := "/"
	rest := split(p)
	for follows := 0; len(rest) > 0; {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		if n := f.Nodes[cur]; n == nil || n.Kind != Dir {
			return "", hops, fmt.Errorf("%s is not a directory", cur)
		}
		next := path.Join(cur, c)
		n := f.Nodes[next]
		if n == nil {
			return "", hops, fmt.Errorf("%s does not exist", next)
		}
		if n.Kind != Symlink {
			cur = next
			continue
		}
		follows++
		if follows > 40 {
			return "", hops, fmt.Errorf("%w at %s", ErrLoop, next)
		}
		hops = append(hops, Hop{Link: next, Target: n.Target})
		if strings.HasPrefix(n.Target, "/") {
			cur = "/"
		}
		rest = append(split(n.Target), rest...)
	}
	return cur, hops, nil
}

func split(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

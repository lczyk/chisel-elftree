package resolve

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

// TestOracle compares the resolver with the real loader. It needs a rootfs
// in $ELFTREE_ORACLE_DIR for the arch in $ELFTREE_ORACLE_ARCH, and in
// $ELFTREE_ORACLE_LIST the output of the arch's `ld.so --list` run inside
// that rootfs on its executables, each run headed by a line "== <path>".
// It skips without them.
func TestOracle(t *testing.T) {
	dir, arch, list := os.Getenv("ELFTREE_ORACLE_DIR"), os.Getenv("ELFTREE_ORACLE_ARCH"), os.Getenv("ELFTREE_ORACLE_LIST")
	if dir == "" || arch == "" || list == "" {
		t.Skip("ELFTREE_ORACLE_DIR, ELFTREE_ORACLE_ARCH and ELFTREE_ORACLE_LIST not set")
	}
	fs, err := rootfs.Read(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := Check(fs, Arches[arch])
	starts := map[string]Start{}
	for _, st := range res.Starts {
		starts[st.Path] = st
	}
	missing := map[string][]string{}
	for _, f := range res.Findings {
		if f.Severity == Hard && (f.Kind == Needed || f.Kind == Filter) {
			missing[f.Start] = append(missing[f.Start], f.Name)
		}
	}
	oracle := readOracle(t, list)
	compared, agreed := 0, 0
	for exe, want := range oracle {
		final, _, err := fs.Lookup(exe)
		if err != nil {
			continue
		}
		st, ok := starts[final]
		if !ok || st.Kind != "exec" {
			continue
		}
		compared++
		// ld.so --list prints the loader itself without "=>", so the
		// needs it answers are not compared.
		interp := ""
		for _, l := range st.Links {
			if l.Kind == Interp {
				interp = l.To
			}
		}
		got := map[string]string{}
		for _, l := range st.Links {
			if (l.Kind == Needed || l.Kind == Filter) && l.To != interp && l.Via == nil {
				got[l.Name] = l.To
			}
		}
		for _, m := range missing[final] {
			got[m] = "not found"
		}
		ok = true
		for name, p := range want {
			if p != "not found" {
				if f, _, err := fs.Lookup(p); err == nil {
					p = f
				}
			}
			if got[name] != p {
				ok = false
				t.Errorf("%s: %s: resolver %q, ld.so %q", exe, name, got[name], p)
			}
		}
		for name := range got {
			if _, ok2 := want[name]; !ok2 {
				ok = false
				t.Errorf("%s: %s: resolver %q, ld.so does not load it", exe, name, got[name])
			}
		}
		if ok {
			agreed++
		}
	}
	t.Logf("%d executables compared, %d agree", compared, agreed)
	if compared == 0 {
		t.Error("nothing compared")
	}
}

// readOracle reads `ld.so --list` runs: per executable, needed name to the
// path the loader took, or "not found". The vdso and the loader's own line
// have no "=>" and are left out.
func readOracle(t *testing.T, p string) map[string]map[string]string {
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]map[string]string{}
	var cur map[string]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if exe, ok := strings.CutPrefix(line, "== "); ok {
			cur = map[string]string{}
			out[exe] = cur
			continue
		}
		name, rest, ok := strings.Cut(line, " => ")
		if !ok || cur == nil || slices.Contains([]string{"statically", "not"}, name) {
			continue
		}
		target, _, _ := strings.Cut(rest, " (")
		cur[name] = strings.TrimSpace(target)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

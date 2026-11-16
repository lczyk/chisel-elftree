package cli

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	chiselelftree "github.com/lczyk/chisel-elftree"
)

func TestPruneList(t *testing.T) {
	for _, c := range []struct {
		vals, want []string
	}{
		{nil, []string{"@ld"}},
		{[]string{"libc.so.*"}, []string{"@ld", "libc.so.*"}},
		{[]string{"liba.so.1,libb.so.1", "@ld"}, []string{"@ld", "liba.so.1", "libb.so.1"}},
		{[]string{""}, nil},
		{[]string{"liba.so.1", "", "libb.so.1"}, []string{"libb.so.1"}},
		{[]string{"", "@ld"}, []string{"@ld"}},
	} {
		if got := pruneList(c.vals); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.vals, got, c.want)
		}
	}
}

// The values reach pruneList as given, an empty one too.
func TestParseArgsPrune(t *testing.T) {
	for _, c := range []struct {
		args, want []string
	}{
		{[]string{"x"}, []string{"@ld"}},
		{[]string{"--prune", "libc.so.*", "x"}, []string{"@ld", "libc.so.*"}},
		{[]string{"--prune=", "x"}, nil},
		{[]string{"--prune", "", "--prune", "libc.so.*", "x"}, []string{"libc.so.*"}},
	} {
		o, _, err := parseArgs(c.args, nil)
		if err != nil || !slices.Equal(o.Prune, c.want) {
			t.Errorf("%q: got %q, %v; want %q", c.args, o.Prune, err, c.want)
		}
	}
}

func TestFileVersion(t *testing.T) {
	if got := fileVersion("# a comment\n\n 1.2.3 \n4.5.6\n"); got != "1.2.3" {
		t.Errorf("got %q", got)
	}
	if got := fileVersion("# only a comment\n"); got != "" {
		t.Errorf("got %q", got)
	}
	// The tool's own VERSION file, whatever version it is at.
	if v := fileVersion(chiselelftree.VersionFile); strings.Count(v, ".") != 2 {
		t.Errorf("VERSION holds %q", v)
	}
}

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"version"}, {"--version"}} {
		out.Reset()
		if code := Main(args, &out, &out); code != 0 || !strings.Contains(out.String(), fileVersion(chiselelftree.VersionFile)) {
			t.Errorf("%q: %d %q", args, code, out.String())
		}
	}
}

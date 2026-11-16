package resolve

import (
	"os"
	"slices"
	"testing"

	"github.com/lczyk/chisel-elftree/internal/rootfs"
)

// TestIsolation lists the libraries of the rootfs in $ELFTREE_ISOLATION_DIR,
// for the arch in $ELFTREE_ISOLATION_ARCH (arm64 by default), that have a
// finding when loaded alone but none when some other start node loads
// them: what the tree, which draws every library alone, shows and the
// report, which judges in context, does not. It skips without the dir.
func TestIsolation(t *testing.T) {
	dir := os.Getenv("ELFTREE_ISOLATION_DIR")
	if dir == "" {
		t.Skip("ELFTREE_ISOLATION_DIR not set")
	}
	arch := os.Getenv("ELFTREE_ISOLATION_ARCH")
	if arch == "" {
		arch = "arm64"
	}
	fs, err := rootfs.Read(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := Check(fs, Arches[arch])
	for _, lib := range res.Starts {
		if lib.Kind != "lib" {
			continue
		}
		var alone []Finding
		for _, f := range res.Findings {
			if f.Start == lib.Path && f.Via == nil {
				alone = append(alone, f)
			}
		}
		if len(alone) == 0 {
			continue
		}
		for _, ctx := range res.Starts {
			if ctx.Path == lib.Path || !slices.ContainsFunc(ctx.Links, func(l Link) bool { return l.To == lib.Path && l.Kind != Dlopen }) {
				continue
			}
			clean := !slices.ContainsFunc(res.Findings, func(f Finding) bool {
				return f.Start == ctx.Path && slices.Contains(f.Chain, lib.Path)
			})
			if clean {
				for _, f := range alone {
					t.Logf("%s alone: %s %s %s: %s; fine under %s (%s)", lib.Path, f.Severity, f.Kind, f.Name, f.Reason, ctx.Path, ctx.Kind)
				}
				break
			}
		}
	}
}

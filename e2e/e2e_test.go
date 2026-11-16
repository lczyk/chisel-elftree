//go:build e2e

// Package e2e runs the tool for real: a real chisel against the real archive
// and a real release fetched by chisel. Gated behind the e2e build tag and
// CHISEL_ELFTREE_E2E because it needs the chisel binary and network access.
package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/lczyk/chisel-elftree/internal/cli"
)

const release = "ubuntu-26.04"

func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("CHISEL_ELFTREE_E2E") == "" {
		t.Skip("CHISEL_ELFTREE_E2E not set")
	}
	bin := os.Getenv("CHISEL")
	if bin == "" {
		bin = "chisel"
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Fatalf("chisel not found: %v", err)
	}
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := cli.Main(append([]string{"--release", release}, args...), &out, &errs)
	return code, out.String(), errs.String()
}

// TestDashTree cuts dash_bins on two architectures, folds them into one
// block and finds libc where the loader would.
func TestDashTree(t *testing.T) {
	requireE2E(t)
	code, out, errs := run(t, "--arch", "amd64,arm64", "dash", "--slice", "bins", "-T")
	if code != 0 {
		t.Fatalf("exit %d:\n%s%s", code, out, errs)
	}
	lines := strings.Split(out, "\n")
	if !strings.HasPrefix(lines[0], "dash_bins ") || !strings.HasSuffix(lines[0], " [amd64, arm64]") {
		t.Errorf("header %q:\n%s", lines[0], out)
	}
	for _, want := range []string{
		"/usr/bin/dash (dash_bins): executable\n",
		"needed libc.so.6 -> /usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	// The dynamic loader is left out unless asked for.
	if strings.Contains(out, "interp ") {
		t.Errorf("the loader is drawn:\n%s", out)
	}
	code, out, errs = run(t, "--arch", "amd64", "dash", "--slice", "bins", "-T", "--prune=")
	if code != 0 || !strings.Contains(out, "interp /lib64/ld-linux-x86-64.so.2 -> /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 (libc6_libs)") {
		t.Errorf("exit %d, no loader with --prune=:\n%s%s", code, out, errs)
	}
}

// TestDashJSON has nothing hard in dash_bins to fail on, and the json holds
// the same block as the tree.
func TestDashJSON(t *testing.T) {
	requireE2E(t)
	code, out, errs := run(t, "--arch", "amd64", "dash", "--slice", "bins", "--fail-missing", "--json")
	if code != 0 {
		t.Fatalf("exit %d:\n%s%s", code, out, errs)
	}
	var rep struct {
		Blocks []struct {
			Slice  string   `json:"slice"`
			Arches []string `json:"arches"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Blocks) != 1 || rep.Blocks[0].Slice != "dash_bins" || strings.Join(rep.Blocks[0].Arches, ",") != "amd64" {
		t.Errorf("blocks: %+v", rep.Blocks)
	}
}

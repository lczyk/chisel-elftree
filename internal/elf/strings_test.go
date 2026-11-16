package elf

import (
	"bytes"
	"math/rand"
	"regexp"
	"slices"
	"testing"
)

func TestSonames(t *testing.T) {
	data := []byte("\x00libcrypto.so.3\x00cannot load libfoo.so.1: %s\x00libx.so\x00libcrypto.so.3\x00lib.so\x00libnss_%s.so.2\x00/usr/lib/liby.so.1\x00libgcc_s.so.1")
	if got, want := Sonames(data), []string{"libcrypto.so.3", "libx.so", "libgcc_s.so.1"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestUnexplained(t *testing.T) {
	f := &File{Soname: "liba.so.1", Interp: "/lib/ld-linux-aarch64.so.1", Needed: []string{"libc.so.6"},
		Dlopen: []DlopenEntry{{Soname: []string{"libz.so.1"}}}}
	names := []string{"liba.so.1", "liba.so", "libc.so.6", "libz.so.1", "libcrypto.so.3"}
	if got := f.Unexplained(names); !slices.Equal(got, []string{"libcrypto.so.3"}) {
		t.Errorf("got %q", got)
	}
}

// sonameShape is the shape soname matches by hand.
var sonameShape = regexp.MustCompile(`^lib[A-Za-z0-9_+-][A-Za-z0-9_+.-]*\.so(\.[0-9]+)*$`)

// sonamesByByte is Sonames as its doc comment reads: every byte walked,
// every printable run tested. Sonames must agree with it on any input.
func sonamesByByte(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] >= 0x20 && data[i] < 0x7f {
			continue
		}
		if run := data[start:i]; len(run) >= 7 && len(run) < 256 && run[0] == 'l' && sonameShape.Match(run) && !seen[string(run)] {
			seen[string(run)] = true
			out = append(out, string(run))
		}
		start = i + 1
	}
	return out
}

func FuzzSonames(f *testing.F) {
	for _, s := range []string{
		"",
		"libx.so",
		"\x00libcrypto.so.3\x00cannot load libfoo.so.1: %s\x00libx.so\x00libcrypto.so.3\x00",
		"lib.so\x00libnss_%s.so.2\x00/usr/lib/liby.so.1\x00libgcc_s.so.1",
		"liba.so.so\x7flibb.so.1.2.3\tlibc.so.6\nlibd.so.",
		".so.so.so\x00.so",
		"lib" + string(bytes.Repeat([]byte("x"), 249)) + ".so\x00lib" + string(bytes.Repeat([]byte("x"), 250)) + ".so",
		"libstdc++.so.6\x00lib-a_b+c.so.10\x00libx.so.1a\x00libx.sox",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got := Sonames(data)
		if soname(data) != (len(data) >= 7 && len(data) < 256 && sonameShape.Match(data)) {
			t.Fatalf("soname(%q) = %v", data, soname(data))
		}
		if want := sonamesByByte(data); !slices.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
		for i, s := range got {
			if !sonameShape.MatchString(s) || !bytes.Contains(data, []byte(s)) || slices.Contains(got[:i], s) {
				t.Fatalf("%q in %q", s, got)
			}
		}
	})
}

// benchData is n bytes shaped like one kind of ELF content.
func benchData(kind string, n int) []byte {
	r := rand.New(rand.NewSource(1))
	out := make([]byte, 0, n)
	for len(out) < n {
		switch kind {
		case "code":
			// Bytes of any value, a name once in a long while.
			chunk := make([]byte, 64<<10)
			r.Read(chunk)
			out = append(append(out, chunk...), "\x00libcrypto.so.3\x00"...)
		case "strtab":
			// A string table: short symbols, a library name among them.
			if r.Intn(16) == 0 {
				out = append(out, "libfoo.so."...)
				out = append(out, byte('0'+r.Intn(10)), 0)
				continue
			}
			for k := 4 + r.Intn(24); k > 0; k-- {
				out = append(out, byte('a'+r.Intn(26)))
			}
			out = append(out, 0)
		case "messages":
			// Long printable runs that name a library without being one.
			out = append(out, "cannot load libfoo.so.1: %s (see /usr/lib/libbar.so.2 or .so files)\x00"...)
		case "zeros":
			out = append(out, make([]byte, 4096)...)
		}
	}
	return out[:n]
}

func BenchmarkSonames(b *testing.B) {
	for _, kind := range []string{"code", "strtab", "messages", "zeros"} {
		data := benchData(kind, 8<<20)
		b.Run(kind, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				Sonames(data)
			}
		})
		b.Run(kind+"/by-byte", func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				sonamesByByte(data)
			}
		})
	}
}

package elf

import "bytes"

// PriorityStrings is the priority of a dlopen entry made from a string of
// the file, not from a note: below the note's own, and never more than
// information.
const PriorityStrings = "strings"

// Sonames is the strings of data shaped like a library's name, each once,
// in order: a whole run of printable characters, as strings(1) cuts them,
// so the argument of a dlopen and not a word of a message.
func Sonames(data []byte) []string {
	var out []string
	var seen map[string]bool
	// Every name of the shape has ".so" in it, so only the runs around
	// one are looked at: the search for it is far faster than a walk of
	// every byte.
	for at := 0; ; {
		i := bytes.Index(data[at:], dotSo)
		if i < 0 {
			return out
		}
		start, end := at+i, at+i+len(dotSo)
		for start > at && printable(data[start-1]) {
			start--
		}
		for end < len(data) && printable(data[end]) {
			end++
		}
		if run := data[start:end]; soname(run) && !seen[string(run)] {
			if seen == nil {
				seen = map[string]bool{}
			}
			seen[string(run)] = true
			out = append(out, string(run))
		}
		at = end
	}
}

var dotSo = []byte(".so")

func printable(c byte) bool { return c >= 0x20 && c < 0x7f }

// soname reports whether run is shaped like a library's name: "lib", a
// stem of name bytes not starting with a dot, ".so", and any number of
// ".<digits>" after it. It is
// ^lib[A-Za-z0-9_+-][A-Za-z0-9_+.-]*\.so(\.[0-9]+)*$ by hand, since a
// file dense with names spends its whole scan here.
func soname(run []byte) bool {
	// The shortest name of the shape is "libx.so".
	if len(run) < 7 || len(run) >= 256 || run[0] != 'l' || run[1] != 'i' || run[2] != 'b' {
		return false
	}
	// The version: every trailing ".<digits>".
	end := len(run)
	for {
		i := end
		for i > 0 && run[i-1] >= '0' && run[i-1] <= '9' {
			i--
		}
		if i == end || i == 0 || run[i-1] != '.' {
			break
		}
		end = i - 1
	}
	if end < 7 || !bytes.Equal(run[end-3:end], dotSo) {
		return false
	}
	stem := run[3 : end-3]
	if stem[0] == '.' {
		return false
	}
	for _, c := range stem {
		if !nameByte[c] {
			return false
		}
	}
	return true
}

var nameByte = func() (t [256]bool) {
	for c := 0; c < 256; c++ {
		t[c] = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '+' || c == '.' || c == '-'
	}
	return
}()

// Unexplained is the names of names that neither the file's link table,
// its dlopen notes, its interpreter nor its own name account for.
func (f *File) Unexplained(names []string) []string {
	known := map[string]bool{}
	for _, l := range [][]string{f.Needed, f.Filter, f.Auxiliary} {
		for _, n := range l {
			known[n] = true
		}
	}
	for _, e := range f.Dlopen {
		for _, n := range e.Soname {
			known[n] = true
		}
	}
	var out []string
	for _, n := range names {
		if known[n] || f.Soname != "" && len(n) <= len(f.Soname) && f.Soname[:len(n)] == n || f.Interp != "" && len(f.Interp) >= len(n) && f.Interp[len(f.Interp)-len(n):] == n {
			continue
		}
		out = append(out, n)
	}
	return out
}

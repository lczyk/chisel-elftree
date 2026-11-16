// Package glob matches a path against a pattern in chisel's syntax, as a
// slice's contents keys are written: "?" is any one character but "/", "*"
// any run of characters without "/", and "**" any run at all. Nothing else
// is special.
package glob

import (
	"path"
	"strings"
)

// Match reports whether name matches pattern.
func Match(pattern, name string) bool {
	for len(pattern) > 0 {
		switch {
		case strings.HasPrefix(pattern, "**"):
			rest := strings.TrimLeft(pattern, "*")
			for i := 0; i <= len(name); i++ {
				if Match(rest, name[i:]) {
					return true
				}
			}
			return false
		case pattern[0] == '*':
			for i := 0; i <= len(name); i++ {
				if Match(pattern[1:], name[i:]) {
					return true
				}
				if i < len(name) && name[i] == '/' {
					return false
				}
			}
			return false
		case pattern[0] == '?':
			if name == "" || name[0] == '/' {
				return false
			}
		default:
			if name == "" || name[0] != pattern[0] {
				return false
			}
		}
		pattern, name = pattern[1:], name[1:]
	}
	return name == ""
}

// File reports whether the file at path p matches pattern: the whole path
// for a pattern with a slash, its last element for one without, so
// "libc.so.*" and "/usr/lib/*-linux-*/libc.so.*" both name libc.
func File(pattern, p string) bool {
	if strings.Contains(pattern, "/") {
		return Match(pattern, p)
	}
	return Match(pattern, path.Base(p))
}

// AnyFile reports whether the file at p matches any of patterns, as File.
func AnyFile(patterns []string, p string) bool {
	for _, g := range patterns {
		if File(g, p) {
			return true
		}
	}
	return false
}

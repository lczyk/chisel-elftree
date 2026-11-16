// Package elf reads what the dynamic loader reads of an ELF file, from its
// program headers rather than its section headers, so a section-stripped
// file is read the same as any other: the interpreter, the dynamic table
// (needed, filters, soname, rpath, runpath, flags, symbol versions) and the
// dlopen metadata notes.
package elf

import (
	"bytes"
	stdelf "debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Flags of DT_FLAGS_1 the loader acts on.
const (
	DF1NoOpen    = 0x00000040
	DF1NoDefLib  = 0x00000800
	DF1PIE       = 0x08000000
	verFlagWeak  = 0x2
	ntFDODlopen  = 0x407c0c0a
	dtAuxiliary  = 0x7ffffffd
	dtFilter     = 0x7fffffff
	dtVerdef     = 0x6ffffffc
	dtVerdefNum  = 0x6ffffffd
	dtVerneed    = 0x6ffffffe
	dtVerneedNum = 0x6fffffff
	dtFlags1     = 0x6ffffffb
)

// File is what was read of one ELF file.
type File struct {
	Class   stdelf.Class
	Data    binary.ByteOrder
	Machine stdelf.Machine
	Type    stdelf.Type
	OSABI   stdelf.OSABI

	Interp  string // PT_INTERP, "" when there is none
	Dynamic bool   // has a PT_DYNAMIC

	Needed    []string
	Filter    []string
	Auxiliary []string
	Soname    string
	// Rpath and Runpath are the colon-separated lists as written, nil when
	// the tag is absent. An empty element means the cwd to the loader.
	Rpath   []string
	Runpath []string
	Flags1  uint64

	Verneed []Verneed
	Verdef  []string // the version names the file defines

	Dlopen []DlopenEntry

	// Strings are the library names among the file's strings that nothing
	// above explains, set by whoever scans the file, see Sonames: a
	// dlopen the file may make with no note to say so.
	Strings []string
}

// Verneed is the versions a file needs from one of its dependencies.
type Verneed struct {
	File     string // the dependency's soname as needed
	Versions []VersionReq
}

// VersionReq is one version needed; a weak one missing is not fatal.
type VersionReq struct {
	Name string
	Weak bool
}

// DlopenEntry is one entry of an ELF dlopen metadata note: the sonames are
// alternatives, in order of preference.
type DlopenEntry struct {
	Feature     string   `json:"feature"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Soname      []string `json:"soname"`
}

// PIE reports whether the file is a position-independent executable, which
// the loader refuses to load as a library.
func (f *File) PIE() bool { return f.Flags1&DF1PIE != 0 }

// Executable reports whether the file is meant to be run: an ET_EXEC, or an
// ET_DYN that is a PIE or names an interpreter. An older toolchain makes
// PIEs without the PIE flag, and libc names one too and can be run, which
// is why a file can be both an executable and a Library.
func (f *File) Executable() bool {
	return f.Type == stdelf.ET_EXEC || f.Type == stdelf.ET_DYN && (f.PIE() || f.Interp != "")
}

// Library reports whether the loader would load the file as a shared
// object: a dynamic ET_DYN that is not a PIE.
func (f *File) Library() bool { return f.Type == stdelf.ET_DYN && f.Dynamic && !f.PIE() }

// Magic reports whether b starts like an ELF file.
func Magic(b []byte) bool { return bytes.HasPrefix(b, []byte(stdelf.ELFMAG)) }

// Read reads r as an ELF file.
func Read(r io.ReaderAt) (*File, error) { return read(r, nil) }

// ReadBytes reads data, a whole ELF file, as Read does, but without a copy
// of each table it looks at. Nothing of data is kept, so a mapping may go
// once it returns.
func ReadBytes(data []byte) (*File, error) { return read(bytes.NewReader(data), data) }

func read(r io.ReaderAt, data []byte) (*File, error) {
	ef, err := stdelf.NewFile(r)
	if err != nil {
		return nil, err
	}
	f := &File{Class: ef.Class, Data: ef.ByteOrder, Machine: ef.Machine, Type: ef.Type, OSABI: ef.OSABI}
	rd := &reader{r: r, data: data, bo: ef.ByteOrder, ef: ef}
	notes := map[string]bool{}
	for _, p := range ef.Progs {
		switch p.Type {
		case stdelf.PT_INTERP:
			b, err := rd.at(p.Off, p.Filesz)
			if err != nil {
				return nil, fmt.Errorf("interpreter: %w", err)
			}
			f.Interp = string(bytes.TrimRight(b, "\x00"))
		case stdelf.PT_DYNAMIC:
			f.Dynamic = true
			if err := rd.dynamic(f, p); err != nil {
				return nil, fmt.Errorf("dynamic table: %w", err)
			}
		case stdelf.PT_NOTE:
			b, err := rd.at(p.Off, p.Filesz)
			if err != nil {
				return nil, fmt.Errorf("note segment: %w", err)
			}
			if err := f.notes(b, p.Align, ef.ByteOrder, notes); err != nil {
				return nil, err
			}
		}
	}
	// A note section the linker did not map into a PT_NOTE segment is still
	// the producer's declaration; read it from the section headers when
	// there are any. One read both ways counts once.
	for _, s := range ef.Sections {
		if s.Type != stdelf.SHT_NOTE {
			continue
		}
		b, err := s.Data()
		if err != nil {
			continue
		}
		if err := f.notes(b, s.Addralign, ef.ByteOrder, notes); err != nil {
			return nil, err
		}
	}
	return f, nil
}

type reader struct {
	r    io.ReaderAt
	data []byte // the whole file, when it is in memory: at then copies nothing
	ef   *stdelf.File
	bo   binary.ByteOrder
}

const maxRead = 64 << 20

func (rd *reader) at(off, n uint64) ([]byte, error) {
	if n > maxRead {
		return nil, fmt.Errorf("%d bytes at %d is too much", n, off)
	}
	if rd.data != nil {
		// As ReadAt has it: a read that comes up short is an error.
		if size := uint64(len(rd.data)); n > 0 && (off > size || n > size-off) {
			return nil, io.EOF
		}
		if n == 0 {
			return nil, nil
		}
		return rd.data[off : off+n : off+n], nil
	}
	b := make([]byte, n)
	if _, err := rd.r.ReadAt(b, int64(off)); err != nil && !(errors.Is(err, io.EOF) && n == 0) {
		return nil, err
	}
	return b, nil
}

// offset translates a virtual address to a file offset through the PT_LOAD
// segments, and says how many bytes of the file follow it in its segment.
func (rd *reader) offset(vaddr uint64) (off, avail uint64, err error) {
	for _, p := range rd.ef.Progs {
		if p.Type == stdelf.PT_LOAD && vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Filesz {
			d := vaddr - p.Vaddr
			return p.Off + d, p.Filesz - d, nil
		}
	}
	return 0, 0, fmt.Errorf("address %#x is in no loaded segment", vaddr)
}

func (rd *reader) dynamic(f *File, p *stdelf.Prog) error {
	b, err := rd.at(p.Off, p.Filesz)
	if err != nil {
		return err
	}
	size := 16
	if f.Class == stdelf.ELFCLASS32 {
		size = 8
	}
	type tv struct{ tag, val uint64 }
	var tags []tv
	for i := 0; i+size <= len(b); i += size {
		var t tv
		if size == 16 {
			t = tv{rd.bo.Uint64(b[i:]), rd.bo.Uint64(b[i+8:])}
		} else {
			t = tv{uint64(rd.bo.Uint32(b[i:])), uint64(rd.bo.Uint32(b[i+4:]))}
		}
		if t.tag == uint64(stdelf.DT_NULL) {
			break
		}
		tags = append(tags, t)
	}
	var strtab, strsz, verneed, verneedNum, verdef, verdefNum uint64
	for _, t := range tags {
		switch t.tag {
		case uint64(stdelf.DT_STRTAB):
			strtab = t.val
		case uint64(stdelf.DT_STRSZ):
			strsz = t.val
		case dtVerneed:
			verneed = t.val
		case dtVerneedNum:
			verneedNum = t.val
		case dtVerdef:
			verdef = t.val
		case dtVerdefNum:
			verdefNum = t.val
		case dtFlags1:
			f.Flags1 = t.val
		}
	}
	if strtab == 0 {
		for _, t := range tags {
			switch t.tag {
			case uint64(stdelf.DT_NEEDED), dtFilter, dtAuxiliary, uint64(stdelf.DT_SONAME), uint64(stdelf.DT_RPATH), uint64(stdelf.DT_RUNPATH), dtVerneed, dtVerdef:
				return errors.New("string-valued tags without a string table")
			}
		}
		return nil
	}
	off, avail, err := rd.offset(strtab)
	if err != nil {
		return fmt.Errorf("string table: %w", err)
	}
	if strsz == 0 || strsz > avail {
		strsz = avail
	}
	strs, err := rd.at(off, strsz)
	if err != nil {
		return fmt.Errorf("string table: %w", err)
	}
	str := func(i uint64) (string, error) {
		if i >= uint64(len(strs)) {
			return "", fmt.Errorf("string %d past the string table", i)
		}
		s := strs[i:]
		if j := bytes.IndexByte(s, 0); j >= 0 {
			s = s[:j]
		}
		return string(s), nil
	}
	for _, t := range tags {
		var dst *[]string
		var list bool
		switch t.tag {
		case uint64(stdelf.DT_NEEDED):
			dst = &f.Needed
		case dtFilter:
			dst = &f.Filter
		case dtAuxiliary:
			dst = &f.Auxiliary
		case uint64(stdelf.DT_RPATH):
			dst, list = &f.Rpath, true
		case uint64(stdelf.DT_RUNPATH):
			dst, list = &f.Runpath, true
		case uint64(stdelf.DT_SONAME):
			s, err := str(t.val)
			if err != nil {
				return err
			}
			f.Soname = s
			continue
		default:
			continue
		}
		s, err := str(t.val)
		if err != nil {
			return err
		}
		if list {
			*dst = append(*dst, strings.Split(s, ":")...)
		} else {
			*dst = append(*dst, s)
		}
	}
	if verneed != 0 {
		if err := rd.verneeds(f, verneed, verneedNum, str); err != nil {
			return fmt.Errorf("version needs: %w", err)
		}
	}
	if verdef != 0 {
		if err := rd.verdefs(f, verdef, verdefNum, str); err != nil {
			return fmt.Errorf("version definitions: %w", err)
		}
	}
	return nil
}

// The version structures are the same size in both classes: Verneed and
// Vernaux are 16 bytes, Verdef 20 and Verdaux 8.
func (rd *reader) verneeds(f *File, vaddr, num uint64, str func(uint64) (string, error)) error {
	off, avail, err := rd.offset(vaddr)
	if err != nil {
		return err
	}
	b, err := rd.at(off, min(avail, maxRead))
	if err != nil {
		return err
	}
	pos := uint64(0)
	for i := uint64(0); i < num; i++ {
		if pos+16 > uint64(len(b)) {
			return errors.New("past the end")
		}
		cnt := uint64(rd.bo.Uint16(b[pos+2:]))
		file, err := str(uint64(rd.bo.Uint32(b[pos+4:])))
		if err != nil {
			return err
		}
		vn := Verneed{File: file}
		aux := pos + uint64(rd.bo.Uint32(b[pos+8:]))
		for j := uint64(0); j < cnt; j++ {
			if aux+16 > uint64(len(b)) {
				return errors.New("past the end")
			}
			flags := rd.bo.Uint16(b[aux+4:])
			name, err := str(uint64(rd.bo.Uint32(b[aux+8:])))
			if err != nil {
				return err
			}
			vn.Versions = append(vn.Versions, VersionReq{Name: name, Weak: flags&verFlagWeak != 0})
			next := uint64(rd.bo.Uint32(b[aux+12:]))
			if next == 0 {
				break
			}
			aux += next
		}
		f.Verneed = append(f.Verneed, vn)
		next := uint64(rd.bo.Uint32(b[pos+12:]))
		if next == 0 {
			break
		}
		pos += next
	}
	return nil
}

func (rd *reader) verdefs(f *File, vaddr, num uint64, str func(uint64) (string, error)) error {
	off, avail, err := rd.offset(vaddr)
	if err != nil {
		return err
	}
	b, err := rd.at(off, min(avail, maxRead))
	if err != nil {
		return err
	}
	pos := uint64(0)
	for i := uint64(0); i < num; i++ {
		if pos+20 > uint64(len(b)) {
			return errors.New("past the end")
		}
		cnt := rd.bo.Uint16(b[pos+6:])
		aux := pos + uint64(rd.bo.Uint32(b[pos+12:]))
		if cnt > 0 {
			if aux+8 > uint64(len(b)) {
				return errors.New("past the end")
			}
			name, err := str(uint64(rd.bo.Uint32(b[aux:])))
			if err != nil {
				return err
			}
			f.Verdef = append(f.Verdef, name)
		}
		next := uint64(rd.bo.Uint32(b[pos+16:]))
		if next == 0 {
			break
		}
		pos += next
	}
	return nil
}

// notes reads the notes in b, padded to align, and keeps the dlopen ones.
// seen holds the descriptors already read, so a note that is both in a
// segment and a section counts once.
func (f *File) notes(b []byte, align uint64, bo binary.ByteOrder, seen map[string]bool) error {
	if align != 8 {
		align = 4
	}
	pad := func(n uint64) uint64 { return (n + align - 1) &^ (align - 1) }
	for pos := uint64(0); pos+12 <= uint64(len(b)); {
		namesz := uint64(bo.Uint32(b[pos:]))
		descsz := uint64(bo.Uint32(b[pos+4:]))
		typ := bo.Uint32(b[pos+8:])
		name := pos + 12
		desc := name + pad(namesz)
		if name+namesz > uint64(len(b)) || desc > uint64(len(b)) || descsz > uint64(len(b))-desc {
			return nil
		}
		owner := string(bytes.TrimRight(b[name:name+namesz], "\x00"))
		if owner == "FDO" && typ == ntFDODlopen {
			raw := bytes.TrimRight(b[desc:desc+descsz], "\x00")
			if !seen[string(raw)] {
				seen[string(raw)] = true
				var entries []DlopenEntry
				if err := json.Unmarshal(raw, &entries); err != nil {
					return fmt.Errorf("dlopen note: %w", err)
				}
				for _, e := range entries {
					if e.Priority == "" {
						e.Priority = "recommended"
					}
					f.Dlopen = append(f.Dlopen, e)
				}
			}
		}
		pos = desc + pad(descsz)
	}
	return nil
}

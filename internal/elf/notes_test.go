package elf

import (
	"encoding/binary"
	"slices"
	"testing"
)

func note(bo binary.ByteOrder, align int, owner string, typ uint32, desc string) []byte {
	pad := func(b []byte) []byte {
		for len(b)%align != 0 {
			b = append(b, 0)
		}
		return b
	}
	name := pad(append([]byte(owner), 0))
	d := pad(append([]byte(desc), 0))
	out := make([]byte, 12)
	bo.PutUint32(out, uint32(len(owner)+1))
	bo.PutUint32(out[4:], uint32(len(desc)+1))
	bo.PutUint32(out[8:], typ)
	return append(append(out, name...), d...)
}

func TestNotes(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, align := range []int{4, 8} {
			b := note(bo, align, "GNU", 3, "build-id")
			b = append(b, note(bo, align, "FDO", ntFDODlopen, `[{"feature":"zstd","soname":["libzstd.so.1"]},{"soname":["a.so.2","a.so.1"],"priority":"suggested"}]`)...)
			f := &File{}
			if err := f.notes(b, uint64(align), bo, map[string]bool{}); err != nil {
				t.Fatal(err)
			}
			if len(f.Dlopen) != 2 || f.Dlopen[0].Priority != "recommended" || !slices.Equal(f.Dlopen[1].Soname, []string{"a.so.2", "a.so.1"}) {
				t.Errorf("%v %d: %+v", bo, align, f.Dlopen)
			}
		}
	}
}

// A note whose sizes run past the buffer, whatever the alignment, is not
// read, and nothing panics.
func TestNotesBounds(t *testing.T) {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b, 100)
	binary.LittleEndian.PutUint32(b[8:], ntFDODlopen)
	for _, align := range []uint64{0, 4, 8, 1 << 63, ^uint64(0)} {
		f := &File{}
		if err := f.notes(b, align, binary.LittleEndian, map[string]bool{}); err != nil || len(f.Dlopen) != 0 {
			t.Errorf("align %d: %v %v", align, err, f.Dlopen)
		}
	}
}

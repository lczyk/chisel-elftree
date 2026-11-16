//go:build unix

package rootfs

import (
	"os"
	"syscall"
)

// contents is the whole of f, mapped and not read, so a big file costs no
// heap. The bytes are gone once release is called.
func contents(f *os.File) (data []byte, release func(), err error) {
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Size() == 0 {
		return nil, func() {}, nil
	}
	data, err = syscall.Mmap(int(f.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return nil, nil, err
	}
	return data, func() { _ = syscall.Munmap(data) }, nil
}

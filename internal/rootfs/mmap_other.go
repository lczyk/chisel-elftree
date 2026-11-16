//go:build !unix

package rootfs

import (
	"io"
	"os"
)

// contents is the whole of f, read into memory where it cannot be mapped.
func contents(f *os.File) (data []byte, release func(), err error) {
	data, err = io.ReadAll(io.NewSectionReader(f, 0, 1<<62))
	return data, func() {}, err
}

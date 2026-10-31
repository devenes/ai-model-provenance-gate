//go:build unix

package inventory

import (
	"io/fs"
	"syscall"
)

func isHardLinkedFile(info fs.FileInfo) bool {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Nlink > 1
	}
	return false
}

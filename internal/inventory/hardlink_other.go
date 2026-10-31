//go:build !unix

package inventory

import "io/fs"

func isHardLinkedFile(_ fs.FileInfo) bool {
	return false
}

package cp

import (
	"io"
	"os"
)

func CopyFile(dst, src string, perm os.FileMode) error {
	srcF, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcF.Close() //nolint:errcheck
	dstF, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, perm)
	if err != nil {
		return err
	}
	defer dstF.Close() // nolint:errcheck
	if _, err = io.Copy(dstF, srcF); err != nil {
		return err
	}
	return dstF.Close()
}

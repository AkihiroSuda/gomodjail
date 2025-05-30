package ziputil

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// SelfExtractArchiveComment is the comment present in the End Of Central Directory Record.
const SelfExtractArchiveComment = "gomodjail-self-extract-archive"

func WriteFileWithPath(zw *zip.Writer, filePath, name string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	if err = WriteFile(zw, f, name); err != nil {
		return err
	}
	return f.Close()
}

func WriteFile(zw *zip.Writer, f fs.File, name string) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if sz := st.Size(); sz > math.MaxUint32 {
		return fmt.Errorf("file size must not exceed MaxUint32, got %d", sz)
	}
	fh, err := zip.FileInfoHeader(st)
	if err != nil {
		return err
	}
	if name != "" {
		fh.Name = name
	}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		return err
	}
	return nil
}

func FindSelfExtractArchive() (*zip.ReadCloser, error) {
	selfExe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	zr, err := zip.OpenReader(selfExe)
	if err != nil {
		if errors.Is(err, zip.ErrFormat) {
			return nil, nil
		}
		return nil, err
	}
	if zr.Comment != SelfExtractArchiveComment {
		return nil, fmt.Errorf("expected comment %q, got %q", SelfExtractArchiveComment, zr.Comment)
	}
	return zr, nil
}

func Unzip(dir string, zr *zip.ReadCloser) ([]fs.FileInfo, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	dirFile, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer dirFile.Close() //nolint:errcheck

	if err = flock(dirFile, unix.LOCK_EX); err != nil {
		slog.Warn("failed to lock dir", "path", dir, "error", err)
	} else {
		defer func() {
			if err = flock(dirFile, unix.LOCK_UN); err != nil {
				slog.Warn("failed to unlock dir", "path", dir, "error", err)
			}
		}()
	}

	res := make([]fs.FileInfo, len(zr.File))
	for i, f := range zr.File {
		if err := unzip1(dir, f); err != nil {
			return res, err
		}
		res[i] = f.FileInfo()
	}
	return res, nil
}

func unzip1(dir string, f *zip.File) error {
	fi := f.FileInfo()
	if !fi.Mode().IsRegular() {
		// No need to support directories
		return fmt.Errorf("unexpected non-regular file: %q", fs.FormatFileInfo(fi))
	}
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close() //nolint:errcheck
	baseName := filepath.Base(f.Name)
	if baseName != f.Name {
		return fmt.Errorf("unexpected file: %q", fs.FormatFileInfo(fi))
	}
	wPath := filepath.Join(dir, baseName)
	modTime := fi.ModTime()
	if st, err := os.Stat(wPath); err == nil && st.ModTime().Equal(modTime) && modTime.UnixNano() != 0 {
		// TODO: compare digest too (via xattr? fs-verity?)
		slog.Debug("already exists", "path", wPath, "modTime", modTime)
		return nil
	}

	// for atomicity
	wPathTmp := fmt.Sprintf("%s.pid-%d", wPath, os.Getpid())
	defer os.RemoveAll(wPathTmp) //nolint:errcheck

	w, err := os.OpenFile(wPathTmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode())
	if err != nil {
		return err
	}
	defer w.Close() //nolint:errcheck
	if _, err = io.Copy(w, r); err != nil {
		return err
	}
	for _, x := range []io.Closer{w, r} {
		if err = x.Close(); err != nil {
			return err
		}
	}
	if err = os.Chtimes(wPathTmp, modTime, modTime); err != nil {
		return err
	}
	if err = os.RemoveAll(wPath); err != nil {
		return err
	}
	if err = os.Rename(wPathTmp, wPath); err != nil {
		return err
	}
	return nil
}

func flock(f *os.File, flags int) error {
	fd := int(f.Fd())
	for {
		err := unix.Flock(fd, flags)
		if err == nil || err != unix.EINTR {
			return err
		}
	}
}

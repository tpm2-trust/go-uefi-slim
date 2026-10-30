package efivar

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// fsImmutable is FS_IMMUTABLE_FL of linux/fs.h.
const fsImmutable = 0x10

// liftImmutable clears path's immutable bit if it is set, and returns the
// function that sets it again. A file that is not there, or a file system
// without the bits, has none: nothing to lift, nothing to put back. The
// file is never created.
func liftImmutable(path string) (restore func() error, err error) {
	restore = func() error { return nil }
	set, err := setImmutable(path, false)
	if err != nil {
		return restore, err
	}
	if set {
		restore = func() error {
			_, err := setImmutable(path, true)
			if errors.Is(err, os.ErrNotExist) {
				return nil // removed: nothing left to mark
			}
			return err
		}
	}
	return restore, nil
}

// Immutable reports whether the variable's file carries the immutable bit.
func (s Store) Immutable(name string, guid GUID) (bool, error) {
	path, err := s.Path(name, guid)
	if err != nil {
		return false, err
	}
	flags, ok, err := getFlags(path)
	return ok && flags&fsImmutable != 0, err
}

// getFlags reads path's inode flags; ok is false where the file system has
// none.
func getFlags(path string) (flags uint32, ok bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	flags, err = unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("%s: %w", path, err)
	}
	return flags, true, nil
}

// setImmutable sets or clears path's immutable bit and reports whether it
// was set. A missing file has none.
func setImmutable(path string, on bool) (was bool, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && !on {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	was = flags&fsImmutable != 0
	want := flags &^ fsImmutable
	if on {
		want |= fsImmutable
	}
	if want != flags {
		if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(want)); err != nil {
			return was, fmt.Errorf("%s: the immutable bit: %w", path, err)
		}
	}
	return was, nil
}

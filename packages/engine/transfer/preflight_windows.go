//go:build windows

package transfer

import (
	"golang.org/x/sys/windows"
)

// freeSpace reports the bytes available to the caller on the filesystem
// containing path, via GetDiskFreeSpaceEx.
func freeSpace(path string) (int64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeBytesAvailable uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeBytesAvailable, nil, nil); err != nil {
		return 0, err
	}
	const maxInt64 = uint64(1<<63 - 1)
	if freeBytesAvailable > maxInt64 {
		freeBytesAvailable = maxInt64
	}
	return int64(freeBytesAvailable), nil
}

//go:build unix

package transfer

import (
	"syscall"
)

// freeSpace reports the bytes available to unprivileged callers on the
// filesystem containing path, via statfs.
func freeSpace(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	// Bavail * Bsize can overflow int64 on enormous filesystems; saturate.
	avail := uint64(st.Bavail) * uint64(st.Bsize)
	const maxInt64 = uint64(1<<63 - 1)
	if avail > maxInt64 {
		avail = maxInt64
	}
	return int64(avail), nil
}

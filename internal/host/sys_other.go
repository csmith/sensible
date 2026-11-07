//go:build !linux

package host

import "golang.org/x/sys/unix"

const (
	// The agent only runs on Linux, which has O_PATH and AT_EMPTY_PATH, but
	// the controller can be built elsewhere.
	openPath  = unix.O_RDONLY
	emptyPath = 0
)

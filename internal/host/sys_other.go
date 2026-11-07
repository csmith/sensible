//go:build !linux

package host

import "golang.org/x/sys/unix"

// The agent only runs on Linux, which has O_PATH, but the controller can be
// built elsewhere.
const openPath = unix.O_RDONLY

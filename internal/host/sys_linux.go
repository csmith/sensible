package host

import "golang.org/x/sys/unix"

// openPath opens a file only to refer to it, without reading it or
// following a link it is.
const openPath = unix.O_PATH

package host

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Sys is the agent's view of the machine it runs on. Paths are absolute.
// Links are only followed out of directories that only root or the agent
// can change; anywhere else, following one is an error.
type Sys interface {
	FileReader
	FileWriter
	Accounts
	// Run runs a command. A non-zero exit status isn't an error; it's
	// reported in the Result. Errors wrap exec.ErrNotFound if the program
	// doesn't exist.
	Run(ctx context.Context, cmd Cmd) (Result, error)
	Fetch(ctx context.Context, url string) ([]byte, error)
	Now() time.Time
}

type FileReader interface {
	ReadFile(path string) ([]byte, error)
	// Open opens a regular file to read.
	Open(path string) (io.ReadCloser, error)
	// Stat follows symlinks; Lstat doesn't.
	Stat(path string) (FileInfo, error)
	Lstat(path string) (FileInfo, error)
	// ReadDir returns the names of a directory's entries, sorted.
	ReadDir(path string) ([]string, error)
	Glob(pattern string) ([]string, error)
	Readlink(path string) (string, error)
}

type FileWriter interface {
	// WriteFile atomically replaces path, which must be in an existing
	// directory, or writes it in place if it's a mount point.
	WriteFile(path string, data []byte, opts WriteOptions) error
	// MkdirAll creates path and any missing parents, owned by whoever the
	// agent runs as.
	MkdirAll(path string, mode fs.FileMode) error
	Chown(path string, uid, gid int) error
	Chmod(path string, mode fs.FileMode) error
	// Symlink atomically creates or replaces path as a link to target.
	Symlink(target, path string) error
	RemoveAll(path string) error
	// RemoveDir removes an empty directory.
	RemoveDir(path string) error
}

type Accounts interface {
	// LookupUser returns an error wrapping fs.ErrNotExist for unknown users.
	LookupUser(name string) (UserInfo, error)
	// LookupGroup returns a group's GID, or an error wrapping
	// fs.ErrNotExist for unknown groups.
	LookupGroup(name string) (int, error)
	// PasswordHash returns the account's hash from /etc/shadow.
	PasswordHash(name string) (string, error)
}

type Cmd struct {
	Argv  []string
	Stdin string
	// Env is added to the agent's environment.
	Env map[string]string
	// User runs the command as that account, from its home directory if
	// that's a directory. Empty runs it as the agent's user.
	User string
	// Dir is where the command runs, in place of / or the user's home.
	Dir string
}

type Result struct {
	Stdout string
	Stderr string
	Code   int
}

type WriteOptions struct {
	UID  int
	GID  int
	Mode fs.FileMode
	// Validate, if set, is called with a path to the fully written
	// temporary file before it replaces the original. The path refers to
	// the file itself, under /proc, so it can't be redirected elsewhere. An
	// error aborts the write.
	Validate func(tmpPath string) error
}

type FileInfo struct {
	// Mode includes the type bits, e.g. fs.ModeDir.
	Mode    fs.FileMode
	UID     int
	GID     int
	Size    int64
	ModTime time.Time
}

func (i FileInfo) IsDir() bool     { return i.Mode.IsDir() }
func (i FileInfo) IsRegular() bool { return i.Mode.IsRegular() }
func (i FileInfo) IsSymlink() bool { return i.Mode&fs.ModeSymlink != 0 }

type UserInfo struct {
	Name string
	UID  int
	GID  int
	// Comment is the GECOS field.
	Comment string
	Home    string
	Shell   string
	// Groups are the names of every group the user is in, including its
	// primary group.
	Groups []string
}

// NewSys returns a Sys for the machine the agent runs on.
func NewSys() Sys {
	return &localSys{root: "/"}
}

// localSys implements Sys against the local filesystem. Tests root it in a
// temporary directory and fake its commands and downloads.
type localSys struct {
	root    string
	runner  func(ctx context.Context, cmd Cmd) (Result, error)
	fetcher func(ctx context.Context, url string) ([]byte, error)
	clock   func() time.Time
}

func (s *localSys) Run(ctx context.Context, cmd Cmd) (Result, error) {
	if s.runner != nil {
		return s.runner(ctx, cmd)
	}
	if len(cmd.Argv) == 0 {
		return Result{}, errors.New("empty command")
	}

	c := exec.CommandContext(ctx, cmd.Argv[0], cmd.Argv[1:]...)
	c.Dir = "/"
	c.Stdin = strings.NewReader(cmd.Stdin)
	env := environment()
	var home string
	if cmd.User != "" {
		u, err := s.LookupUser(cmd.User)
		if err != nil {
			return Result{}, err
		}
		gids, err := s.groupIDs(u)
		if err != nil {
			return Result{}, err
		}
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid:    uint32(u.UID),
			Gid:    uint32(u.GID),
			Groups: gids,
		}}
		env["HOME"], env["USER"], env["LOGNAME"] = u.Home, u.Name, u.Name
		home = u.Home
	}
	if dir := cmp.Or(cmd.Dir, home); dir != "" {
		d, err := s.openDir(dir)
		switch {
		case err == nil:
			defer func() { _ = d.Close() }()
			c.Dir = fdPath(d)
		case cmd.Dir != "":
			return Result{}, err
		}
		// Otherwise it's a home that isn't a real directory, e.g. because its
		// user replaced it with a link, and the command starts in /.
	}
	maps.Copy(env, cmd.Env)
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}

	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		res.Code = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("running %s: %w", cmd.Argv[0], err)
	}
	return res, nil
}

func environment() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	if env["PATH"] == "" {
		env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	// Commands' output is parsed, so mustn't be translated.
	env["LC_ALL"] = "C"
	return env
}

func (s *localSys) ReadFile(path string) ([]byte, error) {
	file, err := s.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(file)
}

func (s *localSys) Open(path string) (io.ReadCloser, error) {
	return confined(
		s,
		path,
		followLast,
		func(f fileOps) (io.ReadCloser, error) {
			// Opening a FIFO someone else put in place would block until they
			// opened its other end.
			file, err := f.open(f.name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
			if err != nil {
				return nil, err
			}
			if info, err := file.Stat(); err != nil {
				_ = file.Close()
				return nil, err
			} else if !info.Mode().IsRegular() {
				_ = file.Close()
				return nil, f.err("read", f.name, errNotRegular)
			}
			return file, nil
		},
	)
}

func (s *localSys) WriteFile(path string, data []byte, opts WriteOptions) error {
	return confinedErr(
		s,
		path,
		lastAsIs,
		func(f fileOps) error {
			tmp := tempName(f.name)
			file, err := f.open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			committed := false
			defer func() {
				if !committed {
					_ = unix.Unlinkat(f.dir, tmp, 0)
				}
			}()

			err = writeTemp(file, data, opts)
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			if err := f.rename(tmp, f.name); errors.Is(err, unix.EBUSY) {
				// A bind mount, such as Docker's /etc/hosts, can't be
				// replaced, only written to.
				return f.writeInPlace(data, opts)
			} else if err != nil {
				return err
			}
			committed = true
			if d, err := f.open(".", unix.O_RDONLY|unix.O_DIRECTORY, 0); err == nil {
				_ = d.Sync()
				_ = d.Close()
			}
			return nil
		},
	)
}

func writeTemp(file *os.File, data []byte, opts WriteOptions) error {
	if _, err := file.Write(data); err != nil {
		return err
	}
	// Changing the owner can clear the mode's setuid bits, so it goes first.
	if err := file.Chown(opts.UID, opts.GID); err != nil {
		return err
	}
	if err := file.Chmod(opts.Mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if opts.Validate == nil {
		return nil
	}
	// The validator runs as another process, so it's given the agent's
	// descriptor for the file rather than a path that could be redirected.
	return opts.Validate(fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd()))
}

func (f fileOps) writeInPlace(data []byte, opts WriteOptions) error {
	file, err := f.open(f.name, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return f.err("write", f.name, errNotRegular)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 && !f.trusted {
		return f.err("write", f.name, errHardLinked)
	}
	if err := file.Chown(opts.UID, opts.GID); err != nil {
		return err
	}
	if err := file.Chmod(opts.Mode); err != nil {
		return err
	}
	if _, err := file.WriteAt(data, 0); err != nil {
		return err
	}
	if err := file.Truncate(int64(len(data))); err != nil {
		return err
	}
	return file.Sync()
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func (s *localSys) Stat(path string) (FileInfo, error) {
	return confined(s, path, followLast, fileOps.stat)
}

func (s *localSys) Lstat(path string) (FileInfo, error) {
	return confined(s, path, lastAsIs, fileOps.stat)
}

func fileInfo(info fs.FileInfo, err error) (FileInfo, error) {
	if err != nil {
		return FileInfo{}, err
	}
	res := FileInfo{Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		res.UID, res.GID = int(st.Uid), int(st.Gid)
	}
	return res, nil
}

func (s *localSys) ReadDir(path string) ([]string, error) {
	return confined(
		s,
		path,
		followLast,
		func(f fileOps) ([]string, error) {
			d, err := f.open(f.name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err != nil {
				return nil, err
			}
			defer func() { _ = d.Close() }()
			names, err := d.Readdirnames(-1)
			slices.Sort(names)
			return names, err
		},
	)
}

// Glob matches as filepath.Glob does, a component at a time, so it only
// follows the links other operations would.
func (s *localSys) Glob(pattern string) ([]string, error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, err
	}
	parts := components(pattern)
	matches := []string{"/"}
	for i, part := range parts {
		var next []string
		for _, dir := range matches {
			if !strings.ContainsAny(part, `*?[\`) {
				path := filepath.Join(dir, part)
				// Later components fail to match if this is missing.
				if i < len(parts)-1 {
					next = append(next, path)
				} else if _, err := s.Lstat(path); err == nil {
					next = append(next, path)
				}
				continue
			}
			names, err := s.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, name := range names {
				if ok, _ := filepath.Match(part, name); ok {
					next = append(next, filepath.Join(dir, name))
				}
			}
		}
		matches = next
	}
	return matches, nil
}

func (s *localSys) MkdirAll(path string, mode fs.FileMode) error {
	parts := components(path)
	for i := range parts {
		err := confinedErr(
			s,
			"/"+strings.Join(parts[:i+1], "/"),
			followLast,
			func(f fileOps) error {
				err := unix.Mkdirat(f.dir, f.name, uint32(mode.Perm()))
				if !errors.Is(err, unix.EEXIST) {
					return f.err("mkdir", f.name, err)
				}
				info, err := f.stat()
				if err == nil && !info.IsDir() {
					return f.err("mkdir", f.name, unix.ENOTDIR)
				}
				return err
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *localSys) Chown(path string, uid, gid int) error {
	return confinedErr(
		s,
		path,
		lastAsIs,
		func(f fileOps) error {
			file, _, err := f.openToChange("lchown")
			if err != nil {
				return err
			}
			defer func() { _ = file.Close() }()
			return f.err("lchown", f.name, unix.Fchownat(int(file.Fd()), "", uid, gid, emptyPath))
		},
	)
}

func (s *localSys) Chmod(path string, mode fs.FileMode) error {
	return confinedErr(
		s,
		path,
		followLast,
		func(f fileOps) error {
			// fchmod doesn't take an O_PATH descriptor, so the file is changed
			// through /proc, which refers to the one opened rather than
			// resolving its path again.
			file, info, err := f.openToChange("chmod")
			if err != nil {
				return err
			}
			defer func() { _ = file.Close() }()
			if info.Mode()&fs.ModeSymlink != 0 {
				return f.err("chmod", f.name, errUntrustedLink)
			}
			if err := os.Chmod(fdPath(file), mode); err != nil {
				return f.err("chmod", f.name, errors.Unwrap(err))
			}
			return nil
		},
	)
}

func (s *localSys) Symlink(target, path string) error {
	return confinedErr(
		s,
		path,
		lastAsIs,
		func(f fileOps) error {
			tmp := tempName(f.name)
			if err := unix.Symlinkat(target, f.dir, tmp); err != nil {
				return f.err("symlink", tmp, err)
			}
			if err := f.rename(tmp, f.name); err != nil {
				_ = unix.Unlinkat(f.dir, tmp, 0)
				return err
			}
			return nil
		},
	)
}

func tempName(path string) string {
	return filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.sensible-%d", filepath.Base(path), rand.Uint64()))
}

func (s *localSys) Readlink(path string) (string, error) {
	return confined(
		s,
		path,
		lastAsIs,
		func(f fileOps) (string, error) {
			target, err := readlinkat(f.dir, f.name)
			return target, f.err("readlink", f.name, err)
		},
	)
}

func (s *localSys) RemoveAll(path string) error {
	return confinedErr(
		s,
		path,
		lastAsIs,
		func(f fileOps) error {
			return f.err("unlinkat", f.name, removeAllAt(f.dir, f.name))
		},
	)
}

func (s *localSys) RemoveDir(path string) error {
	return confinedErr(
		s,
		path,
		lastAsIs,
		func(f fileOps) error {
			return f.err("unlinkat", f.name, unix.Unlinkat(f.dir, f.name, unix.AT_REMOVEDIR))
		},
	)
}

func (s *localSys) LookupUser(name string) (UserInfo, error) {
	passwd, err := s.ReadFile("/etc/passwd")
	if err != nil {
		return UserInfo{}, err
	}
	entry, ok := parsePasswd(string(passwd))[name]
	if !ok {
		return UserInfo{}, fmt.Errorf("user %s: %w", name, fs.ErrNotExist)
	}
	groups, err := s.groups()
	if err != nil {
		return UserInfo{}, err
	}

	u := UserInfo{
		Name:    name,
		UID:     entry.UID,
		GID:     entry.GID,
		Comment: entry.Comment,
		Home:    entry.Home,
		Shell:   entry.Shell,
	}
	for _, g := range groups {
		if g.gid == entry.GID || slices.Contains(g.members, name) {
			u.Groups = append(u.Groups, g.name)
		}
	}
	return u, nil
}

func (s *localSys) LookupGroup(name string) (int, error) {
	groups, err := s.groups()
	if err != nil {
		return 0, err
	}
	for _, g := range groups {
		if g.name == name {
			return g.gid, nil
		}
	}
	return 0, fmt.Errorf("group %s: %w", name, fs.ErrNotExist)
}

func (s *localSys) PasswordHash(name string) (string, error) {
	data, err := s.ReadFile("/etc/shadow")
	if err != nil {
		return "", err
	}
	for line := range strings.Lines(string(data)) {
		fields := strings.Split(strings.TrimRight(line, "\n"), ":")
		if len(fields) >= 2 && fields[0] == name {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("shadow entry for %s: %w", name, fs.ErrNotExist)
}

func (s *localSys) Fetch(ctx context.Context, url string) ([]byte, error) {
	if s.fetcher != nil {
		return s.fetcher(ctx, url)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", url, res.Status)
	}
	return io.ReadAll(res.Body)
}

func (s *localSys) Now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// openDir opens a directory for a command to start in. The command is given
// the descriptor's path under /proc, so the directory can't be swapped for a
// link before it starts.
func (s *localSys) openDir(path string) (*os.File, error) {
	return confined(
		s,
		path,
		followLast,
		func(f fileOps) (*os.File, error) {
			return f.open(f.name, openPath|unix.O_DIRECTORY, 0)
		},
	)
}

// resolution says what confine does with a link at the end of a path.
type resolution int

const (
	// lastAsIs leaves it for the operation to act on, e.g. to replace it.
	lastAsIs resolution = iota
	followLast
)

// confined runs op on path. Links are only followed out of directories that
// only root or the agent could change, so someone else can't redirect the
// agent anywhere, even to another of their own files.
func confined[T any](s *localSys, path string, last resolution, op func(f fileOps) (T, error)) (T, error) {
	f, err := s.confine(path, last)
	if err != nil {
		var zero T
		return zero, err
	}
	defer func() { _ = unix.Close(f.dir) }()
	return op(f)
}

func confinedErr(s *localSys, path string, last resolution, op func(f fileOps) error) error {
	_, err := confined(
		s,
		path,
		last,
		func(f fileOps) (struct{}, error) {
			return struct{}{}, op(f)
		},
	)
	return err
}

var (
	errUntrustedLink = errors.New("won't follow a link someone else could change")
	errHardLinked    = errors.New("won't change a file with other links where someone else could have linked it")
	errNotRegular    = errors.New("not a regular file")
)

// maxLinks is the most links confine follows for one path, as for the kernel.
const maxLinks = 40

// confine opens the directory that path's last component is in, one
// component at a time and without following links in directories someone
// else could change. Links in other directories are followed, including a
// last one if last is followLast. A missing last component is left for the
// operation to report.
func (s *localSys) confine(path string, last resolution) (fileOps, error) {
	w := &walker{sys: s, dir: -1, todo: components(path)}
	err := w.restart()
	for err == nil && len(w.todo) > 0 {
		var done bool
		if done, err = w.step(last); done {
			break
		}
	}
	if err != nil {
		if w.dir >= 0 {
			_ = unix.Close(w.dir)
		}
		return fileOps{}, err
	}

	f := fileOps{dir: w.dir, name: ".", path: path, trusted: w.trusted}
	if len(w.todo) > 0 {
		f.name = w.todo[0]
	}
	return f, nil
}

// walker is confine's progress through a path.
type walker struct {
	sys     *localSys
	dir     int
	trusted bool
	// at is dir's path, which contains no links.
	at    string
	todo  []string
	links int
}

// step moves past the next component, and reports whether dir is now the
// directory the last one is in.
func (w *walker) step(last resolution) (bool, error) {
	name, final := w.todo[0], len(w.todo) == 1
	if final && last == lastAsIs {
		return true, nil
	}
	fd, err := unix.Openat(w.dir, name, openPath|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if final {
			return true, nil
		}
		return false, w.fail(name, err)
	}
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	kind := st.Mode & unix.S_IFMT
	if err == nil && kind == unix.S_IFDIR && !final {
		_ = unix.Close(w.dir)
		w.dir, w.trusted = fd, w.trusted && trustedDir(&st)
		w.at = filepath.Join(w.at, name)
		w.todo = w.todo[1:]
		return false, nil
	}
	_ = unix.Close(fd)
	switch {
	case err != nil:
		return false, w.fail(name, err)
	case kind == unix.S_IFLNK:
		return false, w.follow(name)
	case final:
		return true, nil
	default:
		return false, w.fail(name, unix.ENOTDIR)
	}
}

// follow replaces the link name with its target, resolved again from the
// root.
func (w *walker) follow(name string) error {
	if !w.trusted {
		return w.fail(name, errUntrustedLink)
	}
	if w.links++; w.links > maxLinks {
		return w.fail(name, unix.ELOOP)
	}
	target, err := readlinkat(w.dir, name)
	if err != nil {
		return w.fail(name, err)
	}
	if !filepath.IsAbs(target) {
		// at contains no links, so its .. is the same by name.
		target = filepath.Join(w.at, target)
	}
	w.todo = append(components(target), w.todo[1:]...)
	return w.restart()
}

func (w *walker) restart() error {
	if w.dir >= 0 {
		_ = unix.Close(w.dir)
	}
	var err error
	w.dir, w.trusted, err = w.sys.openRoot()
	w.at = "/"
	return err
}

func (w *walker) fail(name string, err error) error {
	return &fs.PathError{Op: "open", Path: filepath.Join(w.at, name), Err: err}
}

func (s *localSys) openRoot() (int, bool, error) {
	fd, err := unix.Open(s.root, openPath|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, &fs.PathError{Op: "open", Path: "/", Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, false, &fs.PathError{Op: "stat", Path: "/", Err: err}
	}
	return fd, trustedDir(&st), nil
}

// trustedDir reports whether only root or the agent could change what's in
// the directory.
func trustedDir(st *unix.Stat_t) bool {
	if st.Mode&0o022 != 0 {
		return false
	}
	return st.Uid == 0 || int(st.Uid) == os.Geteuid()
}

func components(path string) []string {
	clean := strings.Trim(filepath.Clean("/"+path), "/")
	if clean == "" {
		return nil
	}
	return strings.Split(clean, "/")
}

// fileOps acts on name in dir, which confine opened, without following a
// link there.
type fileOps struct {
	dir  int
	name string
	// path is the path asked for, for errors.
	path string
	// trusted is whether only root or the agent could change dir or any
	// directory on the way to it.
	trusted bool
}

func (f fileOps) open(name string, flag int, perm uint32) (*os.File, error) {
	fd, err := unix.Openat(f.dir, name, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if err != nil {
		return nil, f.err("open", name, err)
	}
	return os.NewFile(uintptr(fd), f.pathOf(name)), nil
}

func (f fileOps) stat() (FileInfo, error) {
	file, err := f.open(f.name, openPath, 0)
	if err != nil {
		return FileInfo{}, err
	}
	defer func() { _ = file.Close() }()
	return fileInfo(file.Stat())
}

// openToChange opens name to change its owner or mode. Where someone else
// could change dir, they could have hard linked another's file into it, so a
// file with more than one link is refused.
func (f fileOps) openToChange(op string) (*os.File, fs.FileInfo, error) {
	file, err := f.open(f.name, openPath, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err == nil && !f.trusted && !info.IsDir() {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			err = f.err(op, f.name, errHardLinked)
		}
	}
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func (f fileOps) rename(from, to string) error {
	if err := unix.Renameat(f.dir, from, f.dir, to); err != nil {
		return &os.LinkError{Op: "rename", Old: f.pathOf(from), New: f.pathOf(to), Err: err}
	}
	return nil
}

func (f fileOps) pathOf(name string) string {
	if name == f.name {
		return f.path
	}
	return filepath.Join(filepath.Dir(f.path), name)
}

// err returns nil if err is.
func (f fileOps) err(op, name string, err error) error {
	if err == nil {
		return nil
	}
	return &fs.PathError{Op: op, Path: f.pathOf(name), Err: err}
}

func readlinkat(dir int, name string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dir, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

func removeAllAt(dir int, name string) error {
	err := unix.Unlinkat(dir, name, 0)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.EISDIR) {
		return err
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	d := os.NewFile(uintptr(fd), name)
	names, err := d.Readdirnames(-1)
	for _, n := range names {
		if err == nil {
			err = removeAllAt(fd, n)
		}
	}
	_ = d.Close()
	if err != nil {
		return err
	}
	err = unix.Unlinkat(dir, name, unix.AT_REMOVEDIR)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func fdPath(f *os.File) string {
	return "/proc/self/fd/" + strconv.Itoa(int(f.Fd()))
}

func (s *localSys) groupIDs(u UserInfo) ([]uint32, error) {
	var gids []uint32
	for _, g := range u.Groups {
		gid, err := s.LookupGroup(g)
		if err != nil {
			return nil, err
		}
		gids = append(gids, uint32(gid))
	}
	return gids, nil
}

type group struct {
	name    string
	gid     int
	members []string
}

func (s *localSys) groups() ([]group, error) {
	data, err := s.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	var groups []group
	for line := range strings.Lines(string(data)) {
		fields := strings.Split(strings.TrimRight(line, "\n"), ":")
		if len(fields) < 4 {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		g := group{name: fields[0], gid: gid}
		if fields[3] != "" {
			g.members = strings.Split(fields[3], ",")
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// parsePasswd parses /etc/passwd, ignoring malformed lines.
func parsePasswd(data string) map[string]PasswdUser {
	users := map[string]PasswdUser{}
	for line := range strings.Lines(data) {
		fields := strings.Split(strings.TrimRight(line, "\n"), ":")
		if len(fields) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(fields[2])
		gid, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil {
			continue
		}
		users[fields[0]] = PasswdUser{UID: uid, GID: gid, Comment: fields[4], Home: fields[5], Shell: fields[6]}
	}
	return users
}

// runOK runs a command, returning an error including its output if it exits
// non-zero.
func runOK(ctx context.Context, sys Sys, cmd Cmd) (Result, error) {
	res, err := sys.Run(ctx, cmd)
	if err != nil {
		return res, err
	}
	if res.Code != 0 {
		return res, fmt.Errorf("%s exited with status %d: %s", strings.Join(cmd.Argv, " "), res.Code, output(res))
	}
	return res, nil
}

func output(res Result) string {
	out := strings.TrimSpace(res.Stderr)
	if out == "" {
		out = strings.TrimSpace(res.Stdout)
	}
	const limit = 4000
	if len(out) > limit {
		out = "…" + out[len(out)-limit:]
	}
	return out
}

func argv(args ...string) Cmd {
	return Cmd{Argv: args}
}

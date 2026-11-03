package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Sys is the agent's view of the machine it runs on. Paths are absolute.
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
	// directory.
	WriteFile(path string, data []byte, opts WriteOptions) error
	// MkdirAll creates path and any missing parents, owned by whoever the
	// agent runs as.
	MkdirAll(path string, mode fs.FileMode) error
	Chown(path string, uid, gid int) error
	Chmod(path string, mode fs.FileMode) error
	// Symlink atomically creates or replaces path as a link to target.
	Symlink(target, path string) error
	RemoveAll(path string) error
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
	// User runs the command as that account, from its home directory if it
	// exists. Empty runs it as the agent's user.
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
	// Validate, if set, is called with the path of the fully written
	// temporary file before it replaces the original. An error aborts the
	// write.
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
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
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
		if info, err := os.Stat(u.Home); err == nil && info.IsDir() {
			c.Dir = u.Home
		}
	}
	if cmd.Dir != "" {
		c.Dir = s.path(cmd.Dir)
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
	return os.ReadFile(s.path(path))
}

func (s *localSys) WriteFile(path string, data []byte, opts WriteOptions) error {
	dir, name := filepath.Split(s.path(path))
	f, err := os.CreateTemp(dir, "."+name+".sensible-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// Changing the owner can clear the mode's setuid bits, so it goes first.
	if err := f.Chown(opts.UID, opts.GID); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(opts.Mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if opts.Validate != nil {
		if err := opts.Validate(filepath.Join(filepath.Dir(path), filepath.Base(tmp))); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, s.path(path)); err != nil {
		return err
	}
	committed = true
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func (s *localSys) Stat(path string) (FileInfo, error) {
	return fileInfo(os.Stat(s.path(path)))
}

func (s *localSys) Lstat(path string) (FileInfo, error) {
	return fileInfo(os.Lstat(s.path(path)))
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
	entries, err := os.ReadDir(s.path(path))
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names, nil
}

func (s *localSys) Glob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(s.path(pattern))
	if err != nil || s.root == "/" {
		return matches, err
	}
	for i, m := range matches {
		matches[i] = "/" + strings.TrimPrefix(strings.TrimPrefix(m, s.root), "/")
	}
	return matches, nil
}

func (s *localSys) MkdirAll(path string, mode fs.FileMode) error {
	return os.MkdirAll(s.path(path), mode)
}

func (s *localSys) Chown(path string, uid, gid int) error {
	return os.Lchown(s.path(path), uid, gid)
}

func (s *localSys) Chmod(path string, mode fs.FileMode) error {
	return os.Chmod(s.path(path), mode)
}

func (s *localSys) Symlink(target, path string) error {
	full := s.path(path)
	tmp := filepath.Join(filepath.Dir(full), fmt.Sprintf(".%s.sensible-%d", filepath.Base(full), time.Now().UnixNano()))
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *localSys) Readlink(path string) (string, error) {
	return os.Readlink(s.path(path))
}

func (s *localSys) RemoveAll(path string) error {
	return os.RemoveAll(s.path(path))
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

	u := UserInfo{Name: name, UID: entry.UID, GID: entry.GID, Home: entry.Home, Shell: entry.Shell}
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

func (s *localSys) path(p string) string {
	if s.root == "/" {
		return p
	}
	return filepath.Join(s.root, p)
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
		users[fields[0]] = PasswdUser{UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}
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

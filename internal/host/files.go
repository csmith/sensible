package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	defaultFileMode fs.FileMode = 0o644
	defaultDirMode  fs.FileMode = 0o755
	modeBits                    = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky
)

func (r File) Check(ctx context.Context, sys Sys) (Change, error) {
	owner, err := resolveOwnership(sys, r.Owner, r.Group)
	if err != nil {
		return Change{}, err
	}
	info, err := sys.Lstat(r.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return drift("create file\n" + r.contentDiff("")), nil
	}
	if err != nil {
		return Change{}, err
	}
	switch {
	case info.IsSymlink():
		target, _ := sys.Readlink(r.Path)
		return drift(fmt.Sprintf("replace symlink to %s with a file\n", target) + r.contentDiff("")), nil
	case !info.IsRegular():
		return Change{}, fmt.Errorf("%s exists and isn't a regular file", r.Path)
	}

	current, err := sys.ReadFile(r.Path)
	if err != nil {
		return Change{}, err
	}
	diff := owner.diff(info, r.Mode) + r.contentDiff(string(current))
	return Change{InSync: diff == "", Diff: diff}, nil
}

// contentDiff describes replacing current with the file's content, keeping
// secrets out of it.
func (r File) contentDiff(current string) string {
	switch {
	case current == r.Content:
		return ""
	case r.Hidden:
		return "content hidden\n"
	}
	if diff := unifiedDiff(r.mask(current), r.mask(r.Content)); diff != "" {
		return diff
	}
	return "change secret values\n"
}

func (r File) mask(content string) string {
	// Longest first, so a secret containing another is masked whole.
	secrets := slices.SortedFunc(
		slices.Values(r.Secrets),
		func(a, b string) int { return len(b) - len(a) },
	)
	for _, s := range secrets {
		if s != "" {
			content = strings.ReplaceAll(content, s, "(secret)")
		}
	}
	return content
}

func (r File) Apply(ctx context.Context, sys Sys) error {
	owner, err := resolveOwnership(sys, r.Owner, r.Group)
	if err != nil {
		return err
	}
	opts := owner.writeOptions(sys, r.Path, r.Mode)
	if len(r.Validate) > 0 {
		opts.Validate = func(tmp string) error {
			cmd := Cmd{}
			for _, arg := range r.Validate {
				cmd.Argv = append(cmd.Argv, strings.ReplaceAll(arg, "%s", tmp))
			}
			_, err := runOK(ctx, sys, cmd)
			return err
		}
	}
	if err := sys.WriteFile(r.Path, []byte(r.Content), opts); err != nil {
		return err
	}
	noteAptSourceChange(ctx, r.Path)
	return nil
}

func (r Dir) Check(ctx context.Context, sys Sys) (Change, error) {
	owner, err := resolveOwnership(sys, r.Owner, r.Group)
	if err != nil {
		return Change{}, err
	}
	info, err := sys.Lstat(r.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return drift("create directory\n"), nil
	}
	if err != nil {
		return Change{}, err
	}
	if !info.IsDir() {
		return Change{}, fmt.Errorf("%s exists and isn't a directory", r.Path)
	}
	diff := owner.diff(info, r.Mode)
	return Change{InSync: diff == "", Diff: diff}, nil
}

func (r Dir) Apply(ctx context.Context, sys Sys) error {
	owner, err := resolveOwnership(sys, r.Owner, r.Group)
	if err != nil {
		return err
	}
	info, err := sys.Lstat(r.Path)
	isNew := errors.Is(err, fs.ErrNotExist)
	if isNew {
		if err := sys.MkdirAll(r.Path, defaultDirMode); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	if owner.uid >= 0 || owner.gid >= 0 {
		if err := sys.Chown(r.Path, owner.uid, owner.gid); err != nil {
			return err
		}
	}
	mode := r.Mode
	if mode == 0 && isNew {
		mode = defaultDirMode
	}
	if mode != 0 && (isNew || info.Mode&modeBits != mode) {
		return sys.Chmod(r.Path, mode)
	}
	return nil
}

func (r Absent) Check(ctx context.Context, sys Sys) (Change, error) {
	info, err := sys.Lstat(r.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Change{InSync: true}, nil
	}
	if err != nil {
		return Change{}, err
	}
	switch {
	case info.IsDir():
		return drift("remove directory and its contents\n"), nil
	case info.IsSymlink():
		return drift("remove symlink\n"), nil
	default:
		return drift("remove file\n"), nil
	}
}

func (r Absent) Apply(ctx context.Context, sys Sys) error {
	if err := sys.RemoveAll(r.Path); err != nil {
		return err
	}
	noteAptSourceChange(ctx, r.Path)
	return nil
}

func (r Symlink) Check(ctx context.Context, sys Sys) (Change, error) {
	info, err := sys.Lstat(r.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return drift(fmt.Sprintf("create symlink to %s\n", r.Target)), nil
	}
	if err != nil {
		return Change{}, err
	}
	if !info.IsSymlink() {
		return Change{}, fmt.Errorf("%s exists and isn't a symlink", r.Path)
	}
	target, err := sys.Readlink(r.Path)
	if err != nil {
		return Change{}, err
	}
	if target != r.Target {
		return drift(fmt.Sprintf("target: %s → %s\n", target, r.Target)), nil
	}
	return Change{InSync: true}, nil
}

func (r Symlink) Apply(ctx context.Context, sys Sys) error {
	return sys.Symlink(r.Target, r.Path)
}

func (r LineInFile) Check(ctx context.Context, sys Sys) (Change, error) {
	current, _, err := readForEdit(sys, r.Path)
	if err != nil {
		return Change{}, err
	}
	updated, err := r.edit(current)
	if err != nil {
		return Change{}, err
	}
	diff := unifiedDiff(current, updated)
	return Change{InSync: diff == "", Diff: diff}, nil
}

func (r LineInFile) Apply(ctx context.Context, sys Sys) error {
	current, info, err := readForEdit(sys, r.Path)
	if err != nil {
		return err
	}
	updated, err := r.edit(current)
	if err != nil {
		return err
	}
	return writeEdited(sys, r.Path, updated, info)
}

// edit replaces the last line matching Regexp, as Ansible's lineinfile does.
func (r LineInFile) edit(content string) (string, error) {
	re, err := regexp.Compile(r.Regexp)
	if err != nil {
		return "", fmt.Errorf("regexp: %w", err)
	}
	var before *regexp.Regexp
	if r.InsertBefore != "" {
		if before, err = regexp.Compile(r.InsertBefore); err != nil {
			return "", fmt.Errorf("insert_before: %w", err)
		}
	}

	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	match, insert, exact := -1, -1, false
	for i, line := range lines {
		switch {
		case re.MatchString(line):
			match = i
		case before != nil && insert < 0 && before.MatchString(line):
			insert = i
		}
		exact = exact || line == r.Line
	}

	switch {
	case match >= 0 && lines[match] == r.Line:
		return content, nil
	case match >= 0:
		lines[match] = r.Line
	case exact:
		return content, nil
	case insert >= 0:
		lines = append(lines[:insert], append([]string{r.Line}, lines[insert:]...)...)
	default:
		lines = append(lines, r.Line)
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func (r CommentOut) Check(ctx context.Context, sys Sys) (Change, error) {
	edits, err := r.edits(sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, e := range edits {
		diff.WriteString("--- " + e.path + "\n" + unifiedDiff(e.old, e.new))
	}
	return Change{InSync: len(edits) == 0, Diff: diff.String()}, nil
}

func (r CommentOut) Apply(ctx context.Context, sys Sys) error {
	edits, err := r.edits(sys)
	if err != nil {
		return err
	}
	for _, e := range edits {
		if err := writeEdited(sys, e.path, e.new, e.info); err != nil {
			return err
		}
	}
	return nil
}

type fileEdit struct {
	path     string
	old, new string
	info     FileInfo
}

func (r CommentOut) edits(sys Sys) ([]fileEdit, error) {
	re, err := regexp.Compile(r.Regexp)
	if err != nil {
		return nil, fmt.Errorf("regexp: %w", err)
	}
	paths, err := sys.Glob(r.Glob)
	if err != nil {
		return nil, err
	}

	var edits []fileEdit
	for _, path := range paths {
		info, err := sys.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsRegular() {
			continue
		}
		data, err := sys.ReadFile(path)
		if err != nil {
			return nil, err
		}
		old := string(data)
		var updated strings.Builder
		for line := range strings.Lines(old) {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") && re.MatchString(strings.TrimSuffix(line, "\n")) {
				updated.WriteString("# ")
			}
			updated.WriteString(line)
		}
		if updated.String() != old {
			edits = append(edits, fileEdit{path: path, old: old, new: updated.String(), info: info})
		}
	}
	return edits, nil
}

func (r Download) Check(ctx context.Context, sys Sys) (Change, error) {
	info, err := sys.Lstat(r.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return drift(fmt.Sprintf("download %s\n", r.URL)), nil
	}
	if err != nil {
		return Change{}, err
	}
	if !info.IsRegular() {
		return Change{}, fmt.Errorf("%s exists and isn't a regular file", r.Path)
	}
	data, err := sys.ReadFile(r.Path)
	if err != nil {
		return Change{}, err
	}
	diff := ownership{uid: -1, gid: -1}.diff(info, r.Mode)
	if sum := sha256.Sum256(data); !strings.EqualFold(hex.EncodeToString(sum[:]), r.SHA256) {
		diff += fmt.Sprintf("checksum differs: download %s\n", r.URL)
	}
	return Change{InSync: diff == "", Diff: diff}, nil
}

func (r Download) Apply(ctx context.Context, sys Sys) error {
	data, err := sys.Fetch(ctx, r.URL)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); !strings.EqualFold(hex.EncodeToString(sum[:]), r.SHA256) {
		return fmt.Errorf("%s has SHA-256 %x, expected %s", r.URL, sum, r.SHA256)
	}
	return sys.WriteFile(r.Path, data, ownership{uid: -1, gid: -1}.writeOptions(sys, r.Path, r.Mode))
}

func (r OwnedDir) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.undeclared(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, path := range extra {
		diff.WriteString("remove " + path + "\n")
	}
	return Change{InSync: len(extra) == 0, Diff: diff.String()}, nil
}

func (r OwnedDir) Apply(ctx context.Context, sys Sys) error {
	extra, err := r.undeclared(ctx, sys)
	if err != nil {
		return err
	}
	for _, path := range extra {
		if err := sys.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func (r OwnedDir) undeclared(ctx context.Context, sys Sys) ([]string, error) {
	return undeclaredIn(sys, state(ctx).declared, r.Path, r.Recursive)
}

// undeclaredIn lists the entries in dir that aren't declared, looking inside
// declared directories if recursive is set.
func undeclaredIn(sys Sys, declared map[string]bool, dir string, recursive bool) ([]string, error) {
	names, err := sys.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var extra []string
	for _, name := range names {
		path := filepath.Join(dir, name)
		if !declared[path] {
			extra = append(extra, path)
			continue
		}
		if !recursive {
			continue
		}
		info, err := sys.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			inner, err := undeclaredIn(sys, declared, path, true)
			if err != nil {
				return nil, err
			}
			extra = append(extra, inner...)
		}
	}
	return extra, nil
}

// undeclaredInGroups lists the entries in dir that aren't declared, and the
// undeclared entries in each declared directory in dir.
func undeclaredInGroups(sys Sys, declared map[string]bool, dir string) ([]string, error) {
	extra, err := undeclaredIn(sys, declared, dir, false)
	if err != nil {
		return nil, err
	}
	names, err := sys.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		if !declared[path] {
			continue
		}
		inner, err := undeclaredIn(sys, declared, path, false)
		if err != nil {
			return nil, err
		}
		extra = append(extra, inner...)
	}
	return extra, nil
}

// ownership is a resolved owner and group, with -1 for those not managed.
type ownership struct {
	uid, gid int
}

// resolveOwnership accepts names or numeric IDs. An empty group with a named
// owner means the owner's primary group.
func resolveOwnership(sys Sys, owner, group string) (ownership, error) {
	o := ownership{uid: -1, gid: -1}
	if owner != "" {
		var err error
		if o.uid, o.gid, err = resolveUser(sys, owner); err != nil {
			return o, err
		}
	}
	if group != "" {
		var err error
		if o.gid, err = resolveGroup(sys, group); err != nil {
			return o, err
		}
	}
	return o, nil
}

// resolveUser returns the user's UID, and its primary GID if it was named
// rather than numbered, or -1 otherwise.
func resolveUser(sys Sys, owner string) (int, int, error) {
	if id, err := strconv.Atoi(owner); err == nil {
		return id, -1, nil
	}
	u, err := sys.LookupUser(owner)
	if errors.Is(err, fs.ErrNotExist) {
		return -1, -1, fmt.Errorf("user %s doesn't exist yet: %w", owner, ErrNotYetCheckable)
	}
	if err != nil {
		return -1, -1, err
	}
	return u.UID, u.GID, nil
}

func resolveGroup(sys Sys, group string) (int, error) {
	if id, err := strconv.Atoi(group); err == nil {
		return id, nil
	}
	gid, err := sys.LookupGroup(group)
	if errors.Is(err, fs.ErrNotExist) {
		return -1, fmt.Errorf("group %s doesn't exist yet: %w", group, ErrNotYetCheckable)
	}
	return gid, err
}

func (o ownership) diff(info FileInfo, mode fs.FileMode) string {
	var diff strings.Builder
	if o.uid >= 0 && info.UID != o.uid {
		fmt.Fprintf(&diff, "owner: %d → %d\n", info.UID, o.uid)
	}
	if o.gid >= 0 && info.GID != o.gid {
		fmt.Fprintf(&diff, "group: %d → %d\n", info.GID, o.gid)
	}
	if mode != 0 && info.Mode&modeBits != mode {
		fmt.Fprintf(&diff, "mode: %s → %s\n", formatMode(info.Mode&modeBits), formatMode(mode))
	}
	return diff.String()
}

// writeOptions keeps the existing file's owner and mode where they're not
// managed.
func (o ownership) writeOptions(sys Sys, path string, mode fs.FileMode) WriteOptions {
	opts := WriteOptions{UID: o.uid, GID: o.gid, Mode: mode}
	info, err := sys.Lstat(path)
	exists := err == nil && info.IsRegular()
	if opts.UID < 0 && exists {
		opts.UID = info.UID
	}
	if opts.GID < 0 && exists {
		opts.GID = info.GID
	}
	if opts.Mode == 0 {
		opts.Mode = defaultFileMode
		if exists {
			opts.Mode = info.Mode & modeBits
		}
	}
	return opts
}

func formatMode(m fs.FileMode) string {
	octal := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		octal |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		octal |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		octal |= 0o1000
	}
	return fmt.Sprintf("%04o", octal)
}

func readForEdit(sys Sys, path string) (string, FileInfo, error) {
	info, err := sys.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", info, fmt.Errorf("%s doesn't exist yet: %w", path, ErrNotYetCheckable)
	}
	if err != nil {
		return "", info, err
	}
	data, err := sys.ReadFile(path)
	return string(data), info, err
}

func writeEdited(sys Sys, path, content string, info FileInfo) error {
	return sys.WriteFile(path, []byte(content), WriteOptions{UID: info.UID, GID: info.GID, Mode: info.Mode & modeBits})
}

// noteAptSourceChange makes the next package install refresh apt's index if
// path is one of its sources.
func noteAptSourceChange(ctx context.Context, path string) {
	if strings.HasPrefix(path, "/etc/apt/sources.list") {
		state(ctx).aptSourcesChanged = true
	}
}

func drift(diff string) Change {
	return Change{Diff: diff}
}

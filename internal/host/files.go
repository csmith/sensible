package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	defaultFileMode fs.FileMode = 0o644
	defaultDirMode  fs.FileMode = 0o755
	modeBits                    = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky
)

// MarshalJSON sends content that isn't UTF-8, such as a program, as
// base64, as a JSON string would mangle it.
func (r File) MarshalJSON() ([]byte, error) {
	type plain File
	v := struct {
		plain
		Binary []byte `json:"binary,omitempty"`
	}{plain: plain(r)}
	if !utf8.ValidString(r.Content) {
		v.Content, v.Binary = "", []byte(r.Content)
	}
	return json.Marshal(v)
}

func (r *File) UnmarshalJSON(data []byte) error {
	type plain File
	var v struct {
		plain
		Binary []byte `json:"binary,omitempty"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*r = File(v.plain)
	if v.Binary != nil {
		r.Content = string(v.Binary)
	}
	return nil
}

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
	case !utf8.ValidString(current) || !utf8.ValidString(r.Content):
		return "change binary content\n"
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

func (r Disowned) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.Leftovers(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	change := leftoverWarning(ctx, r.ID(), extra, "no longer managed")
	stale, err := r.staleRecords(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	for _, path := range stale {
		change.InSync = false
		change.Diff += "forget record of " + path + "\n"
	}
	return change, nil
}

// Apply forgets the records of files that have changed or gone since they
// were written. It never removes the files themselves.
func (r Disowned) Apply(ctx context.Context, sys Sys) error {
	stale, err := r.staleRecords(ctx, sys)
	if err != nil {
		return err
	}
	for _, path := range stale {
		if err := sys.RemoveAll(r.recordPath(path)); err != nil {
			return err
		}
	}
	return nil
}

func (r Disowned) Leftovers(ctx context.Context, sys Sys) ([]string, error) {
	declared := state(ctx).declared
	var extra []string
	check := func(path string) error {
		if declared[path] || slices.Contains(extra, path) {
			return nil
		}
		ok, err := r.matches(sys, path)
		if ok {
			extra = append(extra, path)
		}
		return err
	}
	for _, pattern := range r.Paths {
		matches, err := sys.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, path := range matches {
			if err := check(path); err != nil {
				return nil, err
			}
		}
	}
	if r.Records != "" {
		recorded, err := recordedPaths(sys, r.Records)
		if err != nil {
			return nil, err
		}
		for _, path := range recorded {
			_, err := sys.Lstat(path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err == nil {
				err = check(path)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return extra, nil
}

// staleRecords lists the paths r covers that nothing declares, whose
// WrittenRecord no longer matches what's there.
func (r Disowned) staleRecords(ctx context.Context, sys Sys) ([]string, error) {
	if r.Records == "" {
		return nil, nil
	}
	recorded, err := recordedPaths(sys, r.Records)
	if err != nil {
		return nil, err
	}
	declared := state(ctx).declared
	var stale []string
	for _, path := range recorded {
		if declared[path] || declared[r.recordPath(path)] {
			continue
		}
		info, err := sys.Lstat(path)
		ok := false
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, err
		case r.Dirs:
			ok = info.IsDir()
		case info.IsRegular():
			if ok, err = isRecorded(sys, r.recordPath(path), path); err != nil {
				return nil, err
			}
		}
		if !ok {
			stale = append(stale, path)
		}
	}
	return stale, nil
}

// recordedPaths lists the paths of the WrittenRecords in dir.
func recordedPaths(sys Sys, dir string) ([]string, error) {
	names, err := sys.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, name := range names {
		if path, err := url.QueryUnescape(name); err == nil && filepath.IsAbs(path) {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func (r Disowned) recordPath(path string) string {
	return recordPath(r.Records, path)
}

func (r Disowned) matches(sys Sys, path string) (bool, error) {
	if r.Header == "" && r.Target == "" && r.Records == "" {
		return true, nil
	}
	info, err := sys.Lstat(path)
	if err != nil {
		return false, err
	}
	switch {
	case r.Dirs:
		if !info.IsDir() {
			return false, nil
		}
		names, err := sys.ReadDir(path)
		return len(names) == 0, err
	case r.Header != "" && info.IsRegular():
		return hasHeader(sys, path, r.Header)
	case r.Records != "" && info.IsRegular():
		return isRecorded(sys, r.recordPath(path), path)
	case r.Target != "" && info.IsSymlink():
		target, err := sys.Readlink(path)
		return err == nil && target == r.Target, err
	default:
		return false, nil
	}
}

// hasHeader reports whether path is a regular file that starts with header.
func hasHeader(sys Sys, path, header string) (bool, error) {
	info, err := sys.Lstat(path)
	if err != nil || !info.IsRegular() {
		return false, err
	}
	content, err := sys.ReadFile(path)
	return err == nil && strings.HasPrefix(string(content), header), err
}

// Prune runs Notify itself, as handlers only follow an apply.
func (r Disowned) Prune(ctx context.Context, sys Sys, item string) error {
	remove := sys.RemoveAll
	if r.Dirs {
		remove = sys.RemoveDir
	}
	if err := remove(item); err != nil {
		return err
	}
	if r.Records != "" {
		if err := sys.RemoveAll(r.recordPath(item)); err != nil {
			return err
		}
	}
	for _, h := range r.Notify {
		if err := h.Apply(ctx, sys); err != nil {
			return fmt.Errorf("removed, but %s failed: %w", h.ID(), err)
		}
	}
	return nil
}

func (r KeptLeftovers) Check(ctx context.Context, sys Sys) (Change, error) {
	if !r.External {
		return Change{InSync: true}, nil
	}
	var missing []string
	for _, pattern := range r.Paths {
		matches, err := sys.Glob(pattern)
		if err != nil {
			return Change{}, err
		}
		if len(matches) == 0 {
			missing = append(missing, pattern)
		}
	}
	if len(r.Packages) > 0 {
		installed, err := installedPackages(ctx, sys)
		if err != nil {
			return Change{}, err
		}
		for _, pattern := range r.Packages {
			match := func(name string) bool {
				ok, _ := filepath.Match(pattern, name)
				return ok
			}
			if !slices.ContainsFunc(installed, match) {
				missing = append(missing, "package "+pattern)
			}
		}
	}
	if len(missing) == 0 {
		return Change{InSync: true}, nil
	}
	return Change{
		InSync:  true,
		Warning: strings.Join(missing, "\n") + "\nmissing, but expected from outside sensible\n",
	}, nil
}

func (r KeptLeftovers) Apply(context.Context, Sys) error { return nil }

// WrittenDir holds the records WrittenRecord makes.
const WrittenDir = "/var/lib/sensible/written"

// WrittenRecord records f in WrittenDir, for a Disowned with Records to
// tell it from a file written by hand.
func WrittenRecord(f File) File {
	return WrittenRecordIn(WrittenDir, f)
}

// WrittenRecordIn records f in dir, for a Disowned with Records, which must
// exist.
func WrittenRecordIn(dir string, f File) File {
	return File{
		Path:    recordPath(dir, f.Path),
		Content: contentSum([]byte(f.Content)) + "\n",
		Owner:   "root",
		Group:   "root",
		Mode:    0o600,
		Hidden:  true,
	}
}

// DirRecordIn records the directory at path in dir, for a Disowned with
// Records and Dirs, which must exist.
func DirRecordIn(dir, path string) File {
	return WrittenRecordIn(dir, File{Path: path})
}

func recordPath(dir, path string) string {
	return filepath.Join(dir, url.QueryEscape(path))
}

// RecordedFile returns the path of the file recorded by the WrittenRecord at
// path, if path is one in WrittenDir or a directory under it.
func RecordedFile(path string) (string, bool) {
	if !strings.HasPrefix(path, WrittenDir+"/") {
		return "", false
	}
	file, err := url.QueryUnescape(filepath.Base(path))
	return file, err == nil && filepath.IsAbs(file)
}

// isRecorded reports whether path is as the WrittenRecord at record says.
func isRecorded(sys Sys, record, path string) (bool, error) {
	sum, err := sys.ReadFile(record)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	content, err := sys.ReadFile(path)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(sum)) == contentSum(content), nil
}

func contentSum(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
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
	if r.Absent && errors.Is(err, ErrNotYetCheckable) {
		return Change{InSync: true}, nil
	}
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
	if r.Absent {
		var kept strings.Builder
		for line := range strings.Lines(content) {
			if !re.MatchString(strings.TrimSuffix(line, "\n")) {
				kept.WriteString(line)
			}
		}
		return kept.String(), nil
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
	remove, keep, err := r.undeclared(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	change := leftoverWarning(ctx, r.ID(), keep, "sensible didn't write these")
	var diff strings.Builder
	for _, path := range remove {
		diff.WriteString("remove " + path + "\n")
	}
	change.InSync, change.Diff = len(remove) == 0, diff.String()
	return change, nil
}

func (r OwnedDir) Apply(ctx context.Context, sys Sys) error {
	remove, _, err := r.undeclared(ctx, sys)
	if err != nil {
		return err
	}
	for _, path := range remove {
		if err := sys.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func (r OwnedDir) Leftovers(ctx context.Context, sys Sys) ([]string, error) {
	_, keep, err := r.undeclared(ctx, sys)
	return keep, err
}

// Prune runs Notify itself, as handlers only follow an apply.
func (r OwnedDir) Prune(ctx context.Context, sys Sys, item string) error {
	if err := sys.RemoveAll(item); err != nil {
		return err
	}
	for _, h := range r.Notify {
		if err := h.Apply(ctx, sys); err != nil {
			return fmt.Errorf("removed, but %s failed: %w", h.ID(), err)
		}
	}
	return nil
}

// undeclared splits the undeclared entries into those apply removes, and
// those that don't start with Header, which it keeps.
func (r OwnedDir) undeclared(ctx context.Context, sys Sys) (remove, keep []string, err error) {
	extra, err := undeclaredIn(sys, state(ctx).declared, r.Path, r.Recursive)
	if err != nil || r.Header == "" {
		return extra, nil, err
	}
	for _, path := range extra {
		ok, err := hasHeader(sys, path, r.Header)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			remove = append(remove, path)
		} else {
			keep = append(keep, path)
		}
	}
	return remove, keep, nil
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

const (
	// previewLimit is the most lines or entries a preview shows.
	previewLimit = 200
	// previewWidth is the most characters of a line a preview shows.
	previewWidth = 200
)

// previewPath describes what's at path for prune to show: the start of a
// text file, a directory's entries, or what anything else is. The second
// result says what was left out.
func previewPath(sys Sys, path string) ([]string, string, error) {
	info, err := sys.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	switch {
	case info.IsSymlink():
		target, err := sys.Readlink(path)
		if err != nil {
			return nil, "", err
		}
		return []string{"link to " + target}, "", nil
	case info.IsDir():
		return previewDir(sys, path)
	case info.IsRegular():
		return previewFile(sys, path, info.Size)
	default:
		return []string{fileKind(info.Mode)}, "", nil
	}
}

func previewFile(sys Sys, path string, size int64) ([]string, string, error) {
	f, err := sys.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	head, err := r.Peek(r.Size())
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "", err
	}
	if isBinary(head, len(head) == r.Size()) {
		return []string{fmt.Sprintf("binary, %s, %s", byteSize(size), http.DetectContentType(head))}, "", nil
	}

	var lines []string
	var line []byte
	more, partial := 0, false
	for {
		chunk, err := r.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, "", err
		}
		// Enough bytes for previewWidth characters, however wide they are.
		if len(lines) < previewLimit && len(line) < previewWidth*utf8.UTFMax {
			line = append(line, chunk...)
		}
		partial = partial || len(chunk) > 0
		if partial && (bytes.HasSuffix(chunk, []byte("\n")) || errors.Is(err, io.EOF)) {
			if len(lines) < previewLimit {
				lines = append(lines, previewLine(line))
			} else {
				more++
			}
			line, partial = line[:0], false
		}
		if errors.Is(err, io.EOF) {
			return lines, moreOf(more, "line"), nil
		}
	}
}

// isBinary reports whether head, the start of a file, isn't text. If the
// file goes on, head may end part way through a character.
func isBinary(head []byte, goesOn bool) bool {
	if bytes.IndexByte(head, 0) >= 0 {
		return true
	}
	for i := 0; i < utf8.UTFMax && i < len(head); i++ {
		if utf8.Valid(head[:len(head)-i]) {
			return false
		}
		if !goesOn {
			break
		}
	}
	return len(head) > 0
}

func previewLine(line []byte) string {
	s := strings.TrimRight(string(line), "\r\n")
	if utf8.RuneCountInString(s) <= previewWidth {
		return s
	}
	return string([]rune(s)[:previewWidth]) + "…"
}

func previewDir(sys Sys, dir string) ([]string, string, error) {
	var lines []string
	more := 0
	var walk func(rel string) error
	walk = func(rel string) error {
		names, err := sys.ReadDir(filepath.Join(dir, rel))
		if err != nil {
			return err
		}
		for _, name := range names {
			entry := filepath.Join(rel, name)
			path := filepath.Join(dir, entry)
			info, err := sys.Lstat(path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			line := entry
			switch {
			case info.IsDir():
				line += "/"
			case info.IsSymlink():
				target, err := sys.Readlink(path)
				if err != nil {
					return err
				}
				line += " → " + target
			default:
			}
			if len(lines) < previewLimit {
				lines = append(lines, line)
			} else {
				more++
			}
			if info.IsDir() {
				if err := walk(entry); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, "", err
	}
	return lines, moreOf(more, "entry"), nil
}

func fileKind(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeNamedPipe != 0:
		return "named pipe"
	case mode&fs.ModeSocket != 0:
		return "socket"
	case mode&fs.ModeCharDevice != 0:
		return "character device"
	case mode&fs.ModeDevice != 0:
		return "block device"
	default:
		return "special file"
	}
}

func moreOf(n int, what string) string {
	switch {
	case n == 0:
		return ""
	case n == 1:
		return "1 more " + what
	case strings.HasSuffix(what, "y"):
		return fmt.Sprintf("%d more %sies", n, strings.TrimSuffix(what, "y"))
	default:
		return fmt.Sprintf("%d more %ss", n, what)
	}
}

func byteSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d bytes", n)
	}
	size, unit := float64(n)/1024, "KiB"
	for _, next := range []string{"MiB", "GiB", "TiB"} {
		if size < 1024 {
			break
		}
		size, unit = size/1024, next
	}
	return fmt.Sprintf("%.1f %s", size, unit)
}

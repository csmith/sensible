package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/url"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

func (r Service) Check(ctx context.Context, sys Sys) (Change, error) {
	st, err := r.state(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, action := range r.actions(st) {
		diff.WriteString(action + "\n")
	}
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

// Apply unmasks a unit before anything else, and checks its state again
// afterwards, as unmasking can leave it enabled.
func (r Service) Apply(ctx context.Context, sys Sys) error {
	st, err := r.state(ctx, sys)
	if err != nil {
		return err
	}
	if st.masked && !r.Masked {
		if _, err := runOK(ctx, sys, argv("systemctl", "unmask", r.Name)); err != nil {
			return err
		}
		if st, err = r.state(ctx, sys); err != nil {
			return err
		}
	}
	for _, action := range r.actions(st) {
		cmd := []string{"systemctl", action}
		if action == "stop" {
			// Or they'd start it again.
			cmd = append(cmd, st.triggers...)
		}
		if _, err := runOK(ctx, sys, argv(append(cmd, r.Name)...)); err != nil {
			return err
		}
	}
	return nil
}

type unitState struct {
	masked, enabled, running bool
	// skipped is set when the unit was last started but didn't run, as a
	// condition failed, so starting it again would change nothing.
	skipped bool
	// triggers are the units, such as sockets, that start it.
	triggers []string
}

// actions are the systemctl commands that take the unit from st to the
// wanted state, in order.
func (r Service) actions(st unitState) []string {
	var actions []string
	if r.Masked {
		if !st.masked {
			actions = append(actions, "mask")
		}
		if st.running {
			actions = append(actions, "stop")
		}
		return actions
	}
	if st.masked {
		actions = append(actions, "unmask")
	}
	if st.enabled != r.Enabled {
		actions = append(actions, map[bool]string{true: "enable", false: "disable"}[r.Enabled])
	}
	if st.running != r.Enabled && !(r.Enabled && st.skipped) {
		actions = append(actions, map[bool]string{true: "start", false: "stop"}[r.Enabled])
	}
	return actions
}

func (r Service) state(ctx context.Context, sys Sys) (unitState, error) {
	props, err := unitProperties(
		ctx,
		sys,
		r.Name,
		"LoadState",
		"ActiveState",
		"ConditionResult",
		"ConditionTimestampMonotonic",
		"TriggeredBy",
	)
	if err != nil {
		return unitState{}, err
	}
	st := unitState{
		running: isRunning(props["ActiveState"]),
		skipped: props["ActiveState"] == "inactive" &&
			props["ConditionResult"] == "no" &&
			props["ConditionTimestampMonotonic"] != "0",
		triggers: strings.Fields(props["TriggeredBy"]),
	}
	switch props["LoadState"] {
	case "masked":
		st.masked = true
		return st, nil
	case "not-found":
		// A unit can be masked before it's installed.
		if r.Masked {
			return st, nil
		}
		return unitState{}, fmt.Errorf("unit %s doesn't exist yet: %w", r.Name, ErrNotYetCheckable)
	}
	res, err := sys.Run(ctx, argv("systemctl", "is-enabled", "--quiet", r.Name))
	if err != nil {
		return unitState{}, err
	}
	st.enabled = res.Code == 0
	return st, nil
}

func (r ServiceAction) Check(ctx context.Context, sys Sys) (Change, error) {
	return drift(r.Action + "\n"), nil
}

// Apply starts the unit instead of reloading it if it isn't running, as
// reloading would fail.
func (r ServiceAction) Apply(ctx context.Context, sys Sys) error {
	action := r.Action
	switch action {
	case "restart":
	case "reload":
		props, err := unitProperties(ctx, sys, r.Name, "LoadState", "ActiveState")
		if err != nil {
			return err
		}
		if !isRunning(props["ActiveState"]) {
			action = "start"
		}
	default:
		return fmt.Errorf("unknown service action %q", r.Action)
	}
	_, err := runOK(ctx, sys, argv("systemctl", action, r.Name))
	return err
}

// UnitsDir is where the system's own unit files go.
const UnitsDir = "/etc/systemd/system"

func (r SystemdUnits) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.undeclared(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, path := range extra {
		diff.WriteString("stop, disable and remove " + path + "\n")
	}
	return Change{InSync: len(extra) == 0, Diff: diff.String()}, nil
}

func (r SystemdUnits) Apply(ctx context.Context, sys Sys) error {
	extra, err := r.undeclared(ctx, sys)
	if err != nil || len(extra) == 0 {
		return err
	}
	for _, path := range extra {
		if _, err := runOK(ctx, sys, argv("systemctl", "disable", "--now", filepath.Base(path))); err != nil {
			return err
		}
	}
	for _, path := range extra {
		if err := sys.RemoveAll(path); err != nil {
			return err
		}
	}
	_, err = runOK(ctx, sys, argv("systemctl", "daemon-reload"))
	return err
}

func (r SystemdUnits) undeclared(ctx context.Context, sys Sys) ([]string, error) {
	if r.Prefix == "" {
		return nil, errors.New("systemd units need a prefix")
	}
	extra, err := undeclaredIn(sys, state(ctx).declared, UnitsDir, false)
	if err != nil {
		return nil, err
	}
	var units []string
	for _, path := range extra {
		if !strings.HasPrefix(filepath.Base(path), r.Prefix) {
			continue
		}
		info, err := sys.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.IsRegular() {
			units = append(units, path)
		}
	}
	return units, nil
}

func unitProperties(ctx context.Context, sys Sys, name string, names ...string) (map[string]string, error) {
	res, err := runOK(ctx, sys, argv("systemctl", "show", "--property="+strings.Join(names, ","), name))
	if err != nil {
		return nil, err
	}
	props := map[string]string{}
	for line := range strings.Lines(res.Stdout) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	return props, nil
}

func isRunning(activeState string) bool {
	return activeState == "active" || activeState == "activating" || activeState == "reloading"
}

func (r User) Check(ctx context.Context, sys Sys) (Change, error) {
	u, exists, err := r.lookup(sys)
	if err != nil {
		return Change{}, err
	}
	var changes []string
	switch {
	case r.Absent && exists:
		changes = []string{"remove user\n"}
	case r.Absent:
	case !exists:
		changes, err = r.creation(sys)
	default:
		changes, err = r.modifications(sys, u)
	}
	if err != nil {
		return Change{}, err
	}
	return Change{InSync: len(changes) == 0, Diff: strings.Join(changes, "")}, nil
}

func (r User) Apply(ctx context.Context, sys Sys) error {
	u, exists, err := r.lookup(sys)
	if err != nil {
		return err
	}
	switch {
	case r.Absent && exists:
		_, err = runOK(ctx, sys, argv("userdel", r.Name))
		return err
	case r.Absent:
		return nil
	case !exists:
		err = r.create(ctx, sys)
	default:
		err = r.modify(ctx, sys, u)
	}
	if err != nil {
		return err
	}
	return r.applyPassword(ctx, sys)
}

func (r User) lookup(sys Sys) (UserInfo, bool, error) {
	u, err := sys.LookupUser(r.Name)
	if errors.Is(err, fs.ErrNotExist) {
		return u, false, nil
	}
	return u, err == nil, err
}

func (r User) creation(sys Sys) ([]string, error) {
	if err := r.checkGroupsExist(sys, r.Groups); err != nil {
		return nil, err
	}
	changes := []string{"create user\n"}
	if r.Home != "" {
		changes = append(changes, "home: "+r.Home+"\n")
	}
	if r.Shell != "" {
		changes = append(changes, "shell: "+r.Shell+"\n")
	}
	if len(r.Groups) > 0 {
		changes = append(changes, "groups: + "+strings.Join(r.Groups, ", ")+"\n")
	}
	if r.Password != "" {
		changes = append(changes, "set password\n")
	}
	return changes, nil
}

func (r GroupMembers) Check(_ context.Context, sys Sys) (Change, error) {
	extra, err := r.extra(sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, m := range extra {
		diff.WriteString("- " + m + "\n")
	}
	return Change{InSync: len(extra) == 0, Diff: diff.String()}, nil
}

func (r GroupMembers) Apply(ctx context.Context, sys Sys) error {
	extra, err := r.extra(sys)
	if err != nil {
		return err
	}
	for _, m := range extra {
		if _, err := runOK(ctx, sys, argv("gpasswd", "--delete", m, r.Group)); err != nil {
			return err
		}
	}
	return nil
}

// extra lists the group's members that aren't in Members. A group that
// doesn't exist has none.
func (r GroupMembers) extra(sys Sys) ([]string, error) {
	data, err := sys.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	for line := range strings.Lines(string(data)) {
		fields := strings.Split(strings.TrimRight(line, "\n"), ":")
		if len(fields) < 4 || fields[0] != r.Group || fields[3] == "" {
			continue
		}
		return slices.DeleteFunc(
			strings.Split(fields[3], ","),
			func(m string) bool { return slices.Contains(r.Members, m) },
		), nil
	}
	return nil, nil
}

func (r User) modifications(sys Sys, u UserInfo) ([]string, error) {
	missing := r.missingGroups(u)
	if err := r.checkGroupsExist(sys, missing); err != nil {
		return nil, err
	}
	var changes []string
	if r.Home != "" && u.Home != r.Home {
		changes = append(changes, fmt.Sprintf("home: %s → %s\n", u.Home, r.Home))
	}
	if r.Shell != "" && u.Shell != r.Shell {
		changes = append(changes, fmt.Sprintf("shell: %s → %s\n", u.Shell, r.Shell))
	}
	if len(missing) > 0 {
		changes = append(changes, "groups: + "+strings.Join(missing, ", ")+"\n")
	}
	if r.Managed && !isMarked(u.Comment) {
		changes = append(changes, fmt.Sprintf("comment: %q → %q\n", u.Comment, marked(u.Comment)))
	}
	if r.Password != "" {
		hash, err := sys.PasswordHash(r.Name)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if !r.passwordMatches(hash) {
			changes = append(changes, "change password\n")
		}
	}
	return changes, nil
}

func (r User) checkGroupsExist(sys Sys, groups []string) error {
	for _, g := range groups {
		if _, err := sys.LookupGroup(g); errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("group %s doesn't exist yet: %w", g, ErrNotYetCheckable)
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (r User) create(ctx context.Context, sys Sys) error {
	args := []string{"useradd", "--create-home"}
	if r.System {
		args = append(args, "--system")
	}
	if r.Home != "" {
		args = append(args, "--home-dir", r.Home)
	}
	if r.Shell != "" {
		args = append(args, "--shell", r.Shell)
	}
	if len(r.Groups) > 0 {
		args = append(args, "--groups", strings.Join(r.Groups, ","))
	}
	if r.Managed {
		args = append(args, "--comment", marked(""))
	}
	_, err := runOK(ctx, sys, argv(append(args, r.Name)...))
	return err
}

func (r User) modify(ctx context.Context, sys Sys, u UserInfo) error {
	args := []string{"usermod"}
	if r.Home != "" && u.Home != r.Home {
		args = append(args, "--home", r.Home)
	}
	if r.Shell != "" && u.Shell != r.Shell {
		args = append(args, "--shell", r.Shell)
	}
	if missing := r.missingGroups(u); len(missing) > 0 {
		args = append(args, "--append", "--groups", strings.Join(missing, ","))
	}
	if r.Managed && !isMarked(u.Comment) {
		args = append(args, "--comment", marked(u.Comment))
	}
	if len(args) == 1 {
		return nil
	}
	_, err := runOK(ctx, sys, argv(append(args, r.Name)...))
	return err
}

func (r User) applyPassword(ctx context.Context, sys Sys) error {
	if r.Password == "" {
		return nil
	}
	if hash, err := sys.PasswordHash(r.Name); err == nil && r.passwordMatches(hash) {
		return nil
	}
	// chpasswd takes the hash on stdin, keeping it out of the process list.
	_, err := runOK(ctx, sys, Cmd{Argv: []string{"chpasswd", "--encrypted"}, Stdin: r.Name + ":" + r.Password + "\n"})
	return err
}

func (r User) missingGroups(u UserInfo) []string {
	var missing []string
	for _, g := range r.Groups {
		if !slices.Contains(u.Groups, g) {
			missing = append(missing, g)
		}
	}
	return missing
}

// passwordMatches treats any hash starting with "!" as locked.
func (r User) passwordMatches(hash string) bool {
	if r.Password == "!" {
		return strings.HasPrefix(hash, "!")
	}
	return hash == r.Password
}

// accountMarker marks sensible's accounts. It goes in the GECOS field's
// fifth, "other", part, leaving the full name that programs such as display
// managers read alone.
const accountMarker = "managed by sensible"

func isMarked(gecos string) bool {
	parts := strings.Split(gecos, ",")
	return len(parts) >= 5 && parts[4] == accountMarker
}

func marked(gecos string) string {
	parts := strings.Split(gecos, ",")
	for len(parts) < 5 {
		parts = append(parts, "")
	}
	parts[4] = accountMarker
	return strings.Join(parts, ",")
}

func (r Users) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.Leftovers(ctx, sys)
	return leftoverWarning(ctx, r.ID(), extra, "no role declares these"), err
}

func (r Users) Apply(context.Context, Sys) error {
	return nil
}

// Leftovers lists each undeclared account as "user <name>", followed by
// " and <home>" if the account owns its home, as only then does userdel
// remove it.
func (r Users) Leftovers(ctx context.Context, sys Sys) ([]string, error) {
	data, err := sys.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	minUID, maxUID, err := userUIDs(sys)
	if err != nil {
		return nil, err
	}
	declared := state(ctx).users
	accounts := parsePasswd(string(data))
	var extra []string
	for _, name := range slices.Sorted(maps.Keys(accounts)) {
		u := accounts[name]
		system := u.UID < minUID || u.UID > maxUID
		if declared[name] || !isMarked(u.Comment) || system && !slices.Contains(r.System, name) {
			continue
		}
		item := "user " + name
		if info, err := sys.Stat(u.Home); err == nil && info.IsDir() && info.UID == u.UID && u.Home != "/" {
			item += " and " + u.Home
		}
		extra = append(extra, item)
	}
	return extra, nil
}

// Prune deletes the account, and its home and mail spool if it listed the
// home. It fails if the account has processes running, rather than killing
// them.
func (r Users) Prune(ctx context.Context, sys Sys, item string) error {
	rest, ok := strings.CutPrefix(item, "user ")
	name, home, _ := strings.Cut(rest, " ")
	if !ok || name == "" {
		return fmt.Errorf("%q isn't an account", item)
	}
	args := []string{"userdel"}
	// userdel refuses to remove a home the account doesn't own, but only
	// after deleting the account.
	if home != "" {
		args = append(args, "--remove")
	}
	_, err := runOK(ctx, sys, argv(append(args, name)...))
	return err
}

// userUIDs returns the range of UIDs useradd gives accounts that aren't
// system accounts.
func userUIDs(sys Sys) (int, int, error) {
	minUID, maxUID := 1000, 60000
	data, err := sys.ReadFile("/etc/login.defs")
	if errors.Is(err, fs.ErrNotExist) {
		return minUID, maxUID, nil
	} else if err != nil {
		return 0, 0, err
	}
	for line := range strings.Lines(string(data)) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		switch fields[0] {
		case "UID_MIN":
			minUID = n
		case "UID_MAX":
			maxUID = n
		default:
		}
	}
	return minUID, maxUID, nil
}

func (r GitCheckout) Check(ctx context.Context, sys Sys) (Change, error) {
	if err := r.checkOwner(sys); err != nil {
		return Change{}, err
	}
	cur, err := r.current(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	if cur.head == "" {
		return drift(fmt.Sprintf("clone %s at %s\n", r.Repo, r.Commit)), nil
	}
	var diff strings.Builder
	if cur.origin != r.Repo {
		fmt.Fprintf(&diff, "origin: %s → %s\n", cur.origin, r.Repo)
	}
	if cur.head != r.Commit {
		fmt.Fprintf(&diff, "commit: %s → %s\n", cur.head, r.Commit)
	}
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

func (r GitCheckout) Apply(ctx context.Context, sys Sys) error {
	if err := r.checkOwner(sys); err != nil {
		return err
	}
	cur, err := r.current(ctx, sys)
	if err != nil {
		return err
	}
	switch {
	case !cur.exists:
		err = r.init(ctx, sys)
	case cur.origin == "":
		_, err = runOK(ctx, sys, r.git("remote", "add", "origin", r.Repo))
	case cur.origin != r.Repo:
		_, err = runOK(ctx, sys, r.git("remote", "set-url", "origin", r.Repo))
	}
	if err != nil {
		return err
	}

	// A shallow fetch of a commit needs it named exactly.
	if _, err := runOK(ctx, sys, r.git("fetch", "--quiet", "--depth", "1", "origin", r.Commit)); err != nil {
		return err
	}
	_, err = runOK(ctx, sys, r.git("checkout", "--quiet", "--force", "--detach", r.Commit))
	return err
}

func (r GitCheckout) init(ctx context.Context, sys Sys) error {
	if err := sys.MkdirAll(r.Path, defaultDirMode); err != nil {
		return err
	}
	owner, err := resolveOwnership(sys, r.Owner, "")
	if err != nil {
		return err
	}
	if owner.uid >= 0 {
		if err := sys.Chown(r.Path, owner.uid, owner.gid); err != nil {
			return err
		}
	}
	if _, err := runOK(ctx, sys, r.git("init", "--quiet")); err != nil {
		return err
	}
	_, err = runOK(ctx, sys, r.git("remote", "add", "origin", r.Repo))
	return err
}

func (r GitCheckout) checkOwner(sys Sys) error {
	if r.Owner == "" {
		return nil
	}
	_, err := resolveOwnership(sys, r.Owner, "")
	return err
}

// gitState is what's at a GitCheckout's path. head is empty if there are no
// commits, as after a failed first fetch.
type gitState struct {
	exists       bool
	head, origin string
}

func (r GitCheckout) current(ctx context.Context, sys Sys) (gitState, error) {
	if _, err := sys.Lstat(filepath.Join(r.Path, ".git")); errors.Is(err, fs.ErrNotExist) {
		return gitState{}, nil
	} else if err != nil {
		return gitState{}, err
	}
	// No commits exits 1 with no output.
	head, err := runOK(ctx, sys, r.git("rev-parse", "--verify", "--quiet", "HEAD"))
	if err != nil && head.Code != 1 {
		return gitState{}, notYetIfMissing(err)
	}
	// A missing origin exits 1 with no output.
	origin, err := sys.Run(ctx, r.git("config", "--get", "remote.origin.url"))
	if err != nil {
		return gitState{}, err
	}
	return gitState{
		exists: true,
		head:   strings.TrimSpace(head.Stdout),
		origin: strings.TrimSpace(origin.Stdout),
	}, nil
}

func (r GitCheckout) git(args ...string) Cmd {
	return Cmd{Argv: append([]string{"git"}, args...), User: r.Owner, Dir: r.Path}
}

func (r Command) Check(ctx context.Context, sys Sys) (Change, error) {
	if r.User != "" {
		if _, err := sys.LookupUser(r.User); errors.Is(err, fs.ErrNotExist) {
			return Change{}, fmt.Errorf("user %s doesn't exist yet: %w", r.User, ErrNotYetCheckable)
		} else if err != nil {
			return Change{}, err
		}
	}
	if len(r.Watch) > 0 {
		switch now, owed := state(ctx).triggered(r.ID(), r.Watch); {
		case now:
			return drift("run " + strings.Join(r.ApplyArgv, " ") + "\n"), nil
		case owed:
			return drift("run " + strings.Join(r.ApplyArgv, " ") + ", owed from an earlier change\n"), nil
		}
		return Change{InSync: true}, nil
	}
	res, err := sys.Run(ctx, Cmd{Argv: r.CheckArgv, User: r.User, Env: r.Env})
	// A check that can't run, e.g. `paru --version` before paru is
	// installed, means the command needs applying.
	if err != nil && !errors.Is(err, exec.ErrNotFound) {
		return Change{}, err
	}
	if err == nil && res.Code == 0 {
		return Change{InSync: true}, nil
	}
	return drift("run " + strings.Join(r.ApplyArgv, " ") + "\n"), nil
}

func (r Command) Apply(ctx context.Context, sys Sys) error {
	// Commands can install packages, as paru's build does.
	cmd := Cmd{Argv: r.ApplyArgv, User: r.User, Env: r.Env}
	if len(r.Packages) == 0 {
		res, err := runOK(ctx, sys, cmd)
		return explainStaleSyncDB(res, err)
	}
	res, err := runPacman(ctx, sys, cmd)
	return explainStaleSyncDB(res, err)
}

func (r TailscaleSet) Check(ctx context.Context, sys Sys) (Change, error) {
	prefs, err := tailscalePrefs(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, name := range slices.Sorted(maps.Keys(r.Settings)) {
		want := r.Settings[name]
		read, ok := tailscaleSettings[name]
		if !ok {
			fmt.Fprintf(&diff, "%s: can't be checked; will set %s\n", name, want)
			continue
		}
		if got := read(prefs); got != want {
			fmt.Fprintf(&diff, "%s: %s → %s\n", name, got, want)
		}
	}
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

func (r TailscaleSet) Apply(ctx context.Context, sys Sys) error {
	if _, err := tailscalePrefs(ctx, sys); err != nil {
		return err
	}
	args := []string{"tailscale", "set"}
	for _, name := range slices.Sorted(maps.Keys(r.Settings)) {
		args = append(args, "--"+name+"="+r.Settings[name])
	}
	_, err := runOK(ctx, sys, argv(args...))
	return err
}

// TailscaleRecords holds a TailscaleRecord for each setting sensible has
// given `tailscale set`.
const TailscaleRecords = "/var/lib/sensible/tailscale"

// TailscaleRecord records that the named setting is set, so
// DisownedTailscale can find it once nothing declares it.
func TailscaleRecord(name string) File {
	return File{Path: recordPath(TailscaleRecords, name), Owner: "root", Group: "root", Mode: 0o600, Hidden: true}
}

func (r DisownedTailscale) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.Leftovers(ctx, sys)
	return leftoverWarning(ctx, r.ID(), extra, "no longer in tailscale.settings, so left as they are"), err
}

func (r DisownedTailscale) Apply(context.Context, Sys) error {
	return nil
}

// Leftovers lists each undeclared setting as "tailscale setting <name>".
func (r DisownedTailscale) Leftovers(ctx context.Context, sys Sys) ([]string, error) {
	names, err := sys.ReadDir(TailscaleRecords)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	declared := state(ctx).declared
	var extra []string
	for _, file := range names {
		name, err := url.QueryUnescape(file)
		if err != nil || declared[recordPath(TailscaleRecords, name)] {
			continue
		}
		extra = append(extra, "tailscale setting "+name)
	}
	return extra, nil
}

// Prune resets the setting to its default and forgets it. It only forgets
// it if Tailscale is no longer installed, and fails for settings whose
// default isn't known.
func (r DisownedTailscale) Prune(ctx context.Context, sys Sys, item string) error {
	name, ok := strings.CutPrefix(item, "tailscale setting ")
	if !ok || name == "" {
		return fmt.Errorf("%q isn't a tailscale setting", item)
	}
	value, ok := tailscaleDefaults[name]
	if !ok {
		return fmt.Errorf(
			"sensible doesn't know the default for --%s; reset it with `tailscale set`, then ignore it here",
			name,
		)
	}
	_, err := runOK(ctx, sys, argv("tailscale", "set", "--"+name+"="+value))
	if err != nil && !errors.Is(err, exec.ErrNotFound) {
		return err
	}
	return sys.RemoveAll(recordPath(TailscaleRecords, name))
}

// tailscaleDefaults are the values of `tailscale set` flags on a Linux host
// that's never been given them.
var tailscaleDefaults = map[string]string{
	"accept-dns":                 "true",
	"accept-routes":              "false",
	"advertise-connector":        "false",
	"advertise-exit-node":        "false",
	"advertise-routes":           "",
	"exit-node":                  "",
	"exit-node-allow-lan-access": "false",
	"hostname":                   "",
	"operator":                   "",
	"relay-server-port":          "",
	"shields-up":                 "false",
	"snat-subnet-routes":         "true",
	"ssh":                        "false",
	"stateful-filtering":         "false",
	"update-check":               "true",
	"webclient":                  "false",
}

// tailscaleSettings reads `tailscale set` flags' current values from
// `tailscale debug prefs`.
var tailscaleSettings = map[string]func(prefs map[string]any) string{
	"accept-dns":                 pref("CorpDNS"),
	"accept-routes":              pref("RouteAll"),
	"auto-update":                pref("AutoUpdate", "Apply"),
	"exit-node-allow-lan-access": pref("ExitNodeAllowLANAccess"),
	"hostname":                   pref("Hostname"),
	"operator":                   pref("OperatorUser"),
	"relay-server-port":          pref("RelayServerPort"),
	"shields-up":                 pref("ShieldsUp"),
	"ssh":                        pref("RunSSH"),
	"webclient":                  pref("RunWebClient"),
	"advertise-exit-node": func(prefs map[string]any) string {
		routes, _ := prefs["AdvertiseRoutes"].([]any)
		return strconv.FormatBool(slices.Contains(routes, any("0.0.0.0/0")) && slices.Contains(routes, any("::/0")))
	},
}

func pref(path ...string) func(map[string]any) string {
	return func(prefs map[string]any) string {
		var v any = prefs
		for _, key := range path {
			m, ok := v.(map[string]any)
			if !ok {
				return ""
			}
			v = m[key]
		}
		switch v := v.(type) {
		case nil:
			return ""
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return fmt.Sprint(v)
		}
	}
}

// tailscalePrefs returns Tailscale's preferences, failing if it isn't logged
// in.
func tailscalePrefs(ctx context.Context, sys Sys) (map[string]any, error) {
	res, err := runOK(ctx, sys, argv("tailscale", "status", "--json"))
	if err != nil {
		return nil, notYetIfMissing(err)
	}
	var status struct {
		BackendState string `json:"BackendState"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &status); err != nil {
		return nil, fmt.Errorf("parsing tailscale status: %w", err)
	}
	if status.BackendState != "Running" {
		return nil, fmt.Errorf(
			"tailscale isn't running (%s); log in manually with `sudo tailscale up`, then run this again",
			status.BackendState,
		)
	}

	res, err = runOK(ctx, sys, argv("tailscale", "debug", "prefs"))
	if err != nil {
		return nil, err
	}
	var prefs map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &prefs); err != nil {
		return nil, fmt.Errorf("parsing tailscale prefs: %w", err)
	}
	return prefs, nil
}

// notYetIfMissing marks a failure to find a program as something an earlier
// change, such as installing a package, may fix.
func notYetIfMissing(err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("%w: %w", err, ErrNotYetCheckable)
	}
	return err
}

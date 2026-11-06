package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

func (r Service) Check(ctx context.Context, sys Sys) (Change, error) {
	enabled, running, err := r.state(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	if enabled != r.Enabled {
		diff.WriteString(map[bool]string{true: "enable\n", false: "disable\n"}[r.Enabled])
	}
	if running != r.Running {
		diff.WriteString(map[bool]string{true: "start\n", false: "stop\n"}[r.Running])
	}
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

func (r Service) Apply(ctx context.Context, sys Sys) error {
	enabled, running, err := r.state(ctx, sys)
	if err != nil {
		return err
	}
	if enabled != r.Enabled {
		action := map[bool]string{true: "enable", false: "disable"}[r.Enabled]
		if _, err := runOK(ctx, sys, argv("systemctl", action, r.Name)); err != nil {
			return err
		}
	}
	if running != r.Running {
		action := map[bool]string{true: "start", false: "stop"}[r.Running]
		if _, err := runOK(ctx, sys, argv("systemctl", action, r.Name)); err != nil {
			return err
		}
	}
	return nil
}

func (r Service) state(ctx context.Context, sys Sys) (enabled, running bool, err error) {
	props, err := unitProperties(ctx, sys, r.Name)
	if err != nil {
		return false, false, err
	}
	if props["LoadState"] == "not-found" {
		return false, false, fmt.Errorf("unit %s doesn't exist yet: %w", r.Name, ErrNotYetCheckable)
	}
	res, err := sys.Run(ctx, argv("systemctl", "is-enabled", "--quiet", r.Name))
	if err != nil {
		return false, false, err
	}
	return res.Code == 0, isRunning(props["ActiveState"]), nil
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
		props, err := unitProperties(ctx, sys, r.Name)
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

func (r SystemdReload) Check(ctx context.Context, _ Sys) (Change, error) {
	modified := state(ctx).modified
	if slices.ContainsFunc(r.Watch, func(id string) bool { return modified[id] }) {
		return drift("reload, as unit files change\n"), nil
	}
	return Change{InSync: true}, nil
}

func (r SystemdReload) Apply(ctx context.Context, sys Sys) error {
	_, err := runOK(ctx, sys, argv("systemctl", "daemon-reload"))
	return err
}

func (r ServiceRestart) Check(ctx context.Context, _ Sys) (Change, error) {
	modified := state(ctx).modified
	if slices.ContainsFunc(r.Watch, func(id string) bool { return modified[id] }) {
		return drift("restart, as its config changes\n"), nil
	}
	return Change{InSync: true}, nil
}

func (r ServiceRestart) Apply(ctx context.Context, sys Sys) error {
	_, err := runOK(ctx, sys, argv("systemctl", "restart", r.Name))
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

func unitProperties(ctx context.Context, sys Sys, name string) (map[string]string, error) {
	res, err := runOK(ctx, sys, argv("systemctl", "show", "--property=LoadState,ActiveState", name))
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

func (r GitCheckout) Check(ctx context.Context, sys Sys) (Change, error) {
	if err := r.checkOwner(sys); err != nil {
		return Change{}, err
	}
	head, origin, err := r.current(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	if head == "" {
		return drift(fmt.Sprintf("clone %s at %s\n", r.Repo, r.Commit)), nil
	}
	var diff strings.Builder
	if origin != r.Repo {
		fmt.Fprintf(&diff, "origin: %s → %s\n", origin, r.Repo)
	}
	if head != r.Commit {
		fmt.Fprintf(&diff, "commit: %s → %s\n", head, r.Commit)
	}
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

func (r GitCheckout) Apply(ctx context.Context, sys Sys) error {
	if err := r.checkOwner(sys); err != nil {
		return err
	}
	head, origin, err := r.current(ctx, sys)
	if err != nil {
		return err
	}
	if head == "" {
		if err := r.init(ctx, sys); err != nil {
			return err
		}
	} else if origin != r.Repo {
		if _, err := runOK(ctx, sys, r.git("remote", "set-url", "origin", r.Repo)); err != nil {
			return err
		}
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

// current returns HEAD and the origin URL, with an empty HEAD if there's no
// checkout.
func (r GitCheckout) current(ctx context.Context, sys Sys) (string, string, error) {
	if _, err := sys.Lstat(filepath.Join(r.Path, ".git")); errors.Is(err, fs.ErrNotExist) {
		return "", "", nil
	} else if err != nil {
		return "", "", err
	}
	head, err := runOK(ctx, sys, r.git("rev-parse", "HEAD"))
	if err != nil {
		return "", "", notYetIfMissing(err)
	}
	// A missing origin exits 1 with no output.
	origin, err := sys.Run(ctx, r.git("config", "--get", "remote.origin.url"))
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(head.Stdout), strings.TrimSpace(origin.Stdout), nil
}

func (r GitCheckout) git(args ...string) Cmd {
	return Cmd{Argv: append([]string{"git", "-C", r.Path}, args...), User: r.Owner}
}

func (r Command) Check(ctx context.Context, sys Sys) (Change, error) {
	if r.User != "" {
		if _, err := sys.LookupUser(r.User); errors.Is(err, fs.ErrNotExist) {
			return Change{}, fmt.Errorf("user %s doesn't exist yet: %w", r.User, ErrNotYetCheckable)
		} else if err != nil {
			return Change{}, err
		}
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
	_, err := runOK(ctx, sys, Cmd{Argv: r.ApplyArgv, User: r.User, Env: r.Env})
	return err
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

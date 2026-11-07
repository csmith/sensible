package host

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	tests := []struct {
		name      string
		show      string
		enabled   int
		resource  Service
		wantDiff  string
		wantApply []string
	}{
		{
			name:     "in sync",
			show:     "LoadState=loaded\nActiveState=active\n",
			resource: Service{Name: "sshd", Enabled: true, Running: true},
		},
		{
			name:      "stopped and disabled",
			show:      "LoadState=loaded\nActiveState=inactive\n",
			enabled:   1,
			resource:  Service{Name: "sshd", Enabled: true, Running: true},
			wantDiff:  "enable\nstart\n",
			wantApply: []string{"systemctl enable sshd", "systemctl start sshd"},
		},
		{
			name:      "unwanted",
			show:      "LoadState=loaded\nActiveState=active\n",
			resource:  Service{Name: "sshd"},
			wantDiff:  "disable\nstop\n",
			wantApply: []string{"systemctl disable sshd", "systemctl stop sshd"},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newTestSys(t)
				sys.on("systemctl show --property=LoadState,ActiveState sshd", tt.show, 0)
				sys.on("systemctl is-enabled --quiet sshd", "", tt.enabled)
				for _, cmd := range tt.wantApply {
					sys.on(cmd, "", 0)
				}

				change, err := tt.resource.Check(context.Background(), sys)
				require.NoError(t, err)
				assert.Equal(t, tt.wantDiff, change.Diff)
				assert.Equal(t, tt.wantDiff == "", change.InSync)
				if tt.wantApply != nil {
					sys.ran = nil
					require.NoError(t, tt.resource.Apply(context.Background(), sys))
					assert.Equal(t, tt.wantApply, sys.ran[len(sys.ran)-len(tt.wantApply):])
				}
			},
		)
	}
}

func TestService_MissingUnitIsNotYetCheckable(t *testing.T) {
	sys := newTestSys(t)
	sys.on("systemctl show --property=LoadState,ActiveState docker", "LoadState=not-found\nActiveState=inactive\n", 0)

	_, err := Service{Name: "docker", Enabled: true}.Check(context.Background(), sys)

	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestServiceAction_ReloadStartsStoppedUnit(t *testing.T) {
	tests := []struct {
		state, want string
	}{
		{state: "active", want: "systemctl reload ssh"},
		{state: "inactive", want: "systemctl start ssh"},
	}
	for _, tt := range tests {
		sys := newTestSys(t)
		sys.on("systemctl show --property=LoadState,ActiveState ssh", "LoadState=loaded\nActiveState="+tt.state+"\n", 0)
		sys.on(tt.want, "", 0)

		require.NoError(t, ServiceAction{Name: "ssh", Action: "reload"}.Apply(context.Background(), sys))

		assert.Equal(t, tt.want, sys.ran[len(sys.ran)-1])
	}
}

func TestUser_Create(t *testing.T) {
	sys := newTestSys(t)
	sys.on("useradd *", "", 0)
	sys.on("chpasswd --encrypted", "", 0)
	r := User{
		Name:     "aur",
		System:   true,
		Home:     "/var/lib/aur",
		Shell:    "/usr/bin/nologin",
		Groups:   []string{"wheel"},
		Password: "!",
	}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(
		t,
		"create user\nhome: /var/lib/aur\nshell: /usr/bin/nologin\ngroups: + wheel\nset password\n",
		change.Diff,
	)

	var stdin string
	sys.commands["chpasswd --encrypted"] = func(cmd Cmd) Result {
		stdin = cmd.Stdin
		return Result{}
	}
	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(
		t,
		[]string{
			"useradd --create-home --system --home-dir /var/lib/aur --shell /usr/bin/nologin --groups wheel aur",
			"chpasswd --encrypted",
		},
		sys.ran,
	)
	assert.Equal(t, "aur:!\n", stdin)
}

func TestUser_Modify(t *testing.T) {
	sys := newTestSys(t)
	sys.on("usermod *", "", 0)
	r := User{Name: "alice", Shell: "/usr/bin/zsh", Groups: []string{"users", "wheel"}}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "shell: /bin/bash → /usr/bin/zsh\ngroups: + wheel\n", change.Diff)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(t, []string{"usermod --shell /usr/bin/zsh --append --groups wheel alice"}, sys.ran)
}

func TestUser_InSync(t *testing.T) {
	sys := newTestSys(t)

	for _, r := range []User{
		{Name: "bob", Shell: "/bin/sh", Groups: []string{"wheel", "users"}, Password: "!"},
		{Name: "alice", Password: "$y$abc"},
		{Name: "carol", Absent: true},
	} {
		change, err := r.Check(context.Background(), sys)
		require.NoError(t, err)
		assert.True(t, change.InSync, "%s: %s", r.Name, change.Diff)
	}
}

func TestUser_CreatesManagedAccountMarked(t *testing.T) {
	sys := newTestSys(t)
	sys.on("useradd *", "", 0)

	r := User{Name: "carol", Managed: true}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "create user\n", change.Diff)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(t, []string{"useradd --create-home --comment ,,,,managed by sensible carol"}, sys.ran)
}

func TestUser_MarksExistingManagedAccount(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/passwd", "alice:x:1000:1000:Alice A,,,:/home/alice:/bin/bash\n")
	sys.on("usermod *", "", 0)
	r := User{Name: "alice", Managed: true}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "comment: \"Alice A,,,\" → \"Alice A,,,,managed by sensible\"\n", change.Diff)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(t, []string{"usermod --comment Alice A,,,,managed by sensible alice"}, sys.ran)
}

func TestUser_ManagedAccountAlreadyMarkedInSync(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/passwd", "alice:x:1000:1000:Alice A,,,,managed by sensible:/home/alice:/bin/bash\n")

	change, err := User{Name: "alice", Managed: true}.Check(context.Background(), sys)

	require.NoError(t, err)
	assert.True(t, change.InSync, change.Diff)
}

func TestUsers_WarnsAboutUndeclaredMarkedAccounts(t *testing.T) {
	sys := newTestSys(t)
	uid := os.Getuid()
	sys.write("/etc/login.defs", fmt.Sprintf("# comment\nUID_MIN\t\t%d\nUID_MAX\t%d\n", uid, uid+10))
	sys.write(
		"/etc/passwd",
		fmt.Sprintf(
			"alice:x:%[1]d:1:,,,,managed by sensible:/home/alice:/bin/sh\n"+
				"carol:x:%[1]d:1:Carol,,,,managed by sensible:/home/carol:/bin/sh\n"+
				"dave:x:%[2]d:1:,,,,managed by sensible:/home/dave:/bin/sh\n"+
				"erin:x:%[1]d:1:Erin,,,:/home/erin:/bin/sh\n"+
				"frank:x:%[3]d:1:,,,,managed by sensible:/home/frank:/bin/sh\n",
			uid,
			uid+1,
			uid+11,
		),
	)
	require.NoError(t, os.MkdirAll(sys.path("/home/carol"), 0o755))
	st := newRunState()
	st.declare(User{Name: "alice"})
	st.declare(User{Name: "dave", Absent: true})
	ctx := withRunState(context.Background(), st)

	change, err := Users{}.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)
	assert.Equal(
		t,
		"user carol and /home/carol\nuser dave\n"+
			"no role declares these; run `sensible prune` to remove them once they're not needed\n",
		change.Warning,
	)

	require.NoError(t, Users{}.Apply(ctx, sys))
	assert.Empty(t, sys.ran)
}

func TestUsers_NeverListsSystemAccounts(t *testing.T) {
	sys := newTestSys(t)
	sys.write(
		"/etc/passwd",
		"svc:x:999:999:,,,,managed by sensible:/var/lib/svc:/bin/sh\n"+
			"nobody:x:65534:65534:,,,,managed by sensible:/:/bin/sh\n"+
			"carol:x:1000:1000:,,,,managed by sensible:/home/carol:/bin/sh\n",
	)

	items, err := Users{}.Leftovers(context.Background(), sys)

	require.NoError(t, err)
	assert.Equal(t, []string{"user carol"}, items)
}

func TestUsers_PruneDeletesAccount(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/passwd", "carol:x:1000:1000:,,,,managed by sensible:/home/carol:/bin/sh\n")
	sys.on("userdel *", "", 0)
	e := &engine{sys: sys, log: io.Discard}

	require.NoError(t, e.remove(context.Background(), ResourceList{Users{}}, "users", "user carol"))

	assert.Equal(t, []string{"userdel carol"}, sys.ran)
}

func TestUsers_PruneDeletesOwnedHome(t *testing.T) {
	sys := newTestSys(t)
	uid := os.Getuid()
	sys.write("/etc/login.defs", fmt.Sprintf("UID_MIN %d\n", uid))
	sys.write("/etc/passwd", fmt.Sprintf("carol:x:%d:1:,,,,managed by sensible:/home/carol:/bin/sh\n", uid))
	require.NoError(t, os.MkdirAll(sys.path("/home/carol"), 0o755))
	sys.on("userdel *", "", 0)
	e := &engine{sys: sys, log: io.Discard}

	err := e.remove(context.Background(), ResourceList{Users{}}, "users", "user carol and /home/carol")

	require.NoError(t, err)
	assert.Equal(t, []string{"userdel --remove carol"}, sys.ran)
}

func TestUsers_PruneKeepsDeclaredAccounts(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/passwd", "carol:x:1000:1000:,,,,managed by sensible:/home/carol:/bin/sh\n")
	e := &engine{sys: sys, log: io.Discard}

	err := e.remove(context.Background(), ResourceList{User{Name: "carol"}, Users{}}, "users", "user carol")

	require.Error(t, err)
	assert.Empty(t, sys.ran)
}

func TestGroupMembers_RemovesUndeclared(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/group", "docker:x:970:alice,bob,carol\n")
	sys.on("gpasswd --delete *", "", 0)
	r := GroupMembers{Group: "docker", Members: []string{"bob"}}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "- alice\n- carol\n", change.Diff)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(t, []string{"gpasswd --delete alice docker", "gpasswd --delete carol docker"}, sys.ran)
}

func TestGroupMembers_InSync(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/group", "docker:x:970:bob\nempty:x:971:\n")

	for _, r := range []GroupMembers{
		{Group: "docker", Members: []string{"alice", "bob"}},
		{Group: "empty"},
		{Group: "missing"},
	} {
		change, err := r.Check(context.Background(), sys)
		require.NoError(t, err)
		assert.True(t, change.InSync, "%s: %s", r.Group, change.Diff)
	}
}

func TestUser_MissingGroupIsNotYetCheckable(t *testing.T) {
	sys := newTestSys(t)

	_, err := User{Name: "alice", Groups: []string{"docker"}}.Check(context.Background(), sys)

	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestUser_ChangesPassword(t *testing.T) {
	sys := newTestSys(t)
	sys.on("chpasswd --encrypted", "", 0)

	change := User{Name: "alice", Password: "$y$new"}
	c, err := change.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "change password\n", c.Diff)
	assert.NotContains(t, c.Diff, "$y$")
}

func TestGitCheckout_Clones(t *testing.T) {
	sys := newTestSys(t)
	sys.on("git *", "", 0)
	r := GitCheckout{Path: "/usr/share/oh-my-zsh", Repo: "https://example.com/omz.git", Commit: "abc123"}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "clone https://example.com/omz.git at abc123\n", change.Diff)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(
		t,
		[]string{
			"cd /usr/share/oh-my-zsh && git init --quiet",
			"cd /usr/share/oh-my-zsh && git remote add origin https://example.com/omz.git",
			"cd /usr/share/oh-my-zsh && git fetch --quiet --depth 1 origin abc123",
			"cd /usr/share/oh-my-zsh && git checkout --quiet --force --detach abc123",
		},
		sys.ran,
	)
}

func TestGitCheckout_MovesExisting(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/srv/repo/.git/HEAD", "")
	sys.on("git rev-parse --verify --quiet HEAD", "old\n", 0)
	sys.on("git config --get remote.origin.url", "https://example.com/old.git\n", 0)
	sys.on("git *", "", 0)
	r := GitCheckout{Path: "/srv/repo", Repo: "https://example.com/new.git", Commit: "new", Owner: "alice"}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "origin: https://example.com/old.git → https://example.com/new.git\ncommit: old → new\n", change.Diff)

	var users []string
	sys.commands["git *"] = func(cmd Cmd) Result {
		users = append(users, cmd.User)
		return Result{}
	}
	sys.ran = nil
	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Contains(t, sys.ran, "cd /srv/repo && git remote set-url origin https://example.com/new.git")
	assert.Contains(t, sys.ran, "cd /srv/repo && git checkout --quiet --force --detach new")
	assert.Equal(t, []string{"alice", "alice", "alice"}, users)
}

func TestGitCheckout_RecoversFailedFetch(t *testing.T) {
	const prefix = "cd /srv/repo && git remote "
	for _, tc := range []struct {
		name   string
		origin string
		remote []string
	}{
		{"origin right", "https://example.com/omz.git\n", nil},
		{"origin missing", "", []string{prefix + "add origin https://example.com/omz.git"}},
		{"origin differs", "https://example.com/old.git\n", []string{prefix + "set-url origin https://example.com/omz.git"}},
	} {
		t.Run(
			tc.name,
			func(t *testing.T) {
				sys := newTestSys(t)
				sys.write("/srv/repo/.git/HEAD", "")
				sys.on("git rev-parse --verify --quiet HEAD", "", 1)
				sys.on("git config --get remote.origin.url", tc.origin, 0)
				sys.on("git *", "", 0)
				r := GitCheckout{Path: "/srv/repo", Repo: "https://example.com/omz.git", Commit: "abc123"}

				change, err := r.Check(context.Background(), sys)
				require.NoError(t, err)
				assert.False(t, change.InSync)

				sys.ran = nil
				require.NoError(t, r.Apply(context.Background(), sys))
				want := []string{
					"cd /srv/repo && git rev-parse --verify --quiet HEAD",
					"cd /srv/repo && git config --get remote.origin.url",
				}
				want = append(want, tc.remote...)
				want = append(
					want,
					"cd /srv/repo && git fetch --quiet --depth 1 origin abc123",
					"cd /srv/repo && git checkout --quiet --force --detach abc123",
				)
				assert.Equal(t, want, sys.ran)
			},
		)
	}
}

func TestCommand(t *testing.T) {
	sys := newTestSys(t)
	r := Command{
		Name:      "paru",
		CheckArgv: []string{"paru", "--version"},
		ApplyArgv: []string{"sh", "-c", "build"},
		User:      "bob",
	}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.False(t, change.InSync, "a missing program means drift")

	sys.on("paru --version", "paru v2", 0)
	change, err = r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)

	sys.on("sh -c build", "", 3)
	require.ErrorContains(t, r.Apply(context.Background(), sys), "status 3")

	_, err = Command{Name: "x", CheckArgv: []string{"true"}, User: "aur"}.Check(context.Background(), sys)
	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestCommand_WatchRunsOnlyAfterAChange(t *testing.T) {
	sys := newTestSys(t)
	st := newRunState()
	ctx := withRunState(context.Background(), st)
	r := Command{Name: "start", Watch: []string{"package:docker"}, ApplyArgv: []string{"start"}}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)

	st.modified["package:docker"] = true
	change, err = r.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)
}

func TestTailscaleSet(t *testing.T) {
	sys := newTestSys(t)
	sys.on("tailscale status --json", `{"BackendState":"Running"}`, 0)
	prefs, err := os.ReadFile("testdata/tailscale-prefs.json")
	require.NoError(t, err)
	sys.on("tailscale debug prefs", string(prefs), 0)
	sys.on("tailscale set *", "", 0)

	r := TailscaleSet{Settings: map[string]string{
		"ssh":                 "true",
		"operator":            "chris",
		"advertise-exit-node": "true",
		"auto-update":         "false",
		"relay-server-port":   "40000",
	}}
	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.True(t, change.InSync, change.Diff)

	r = TailscaleSet{Settings: map[string]string{"accept-dns": "true", "advertise-exit-node": "false", "new-flag": "x"}}
	change, err = r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(
		t,
		"accept-dns: false → true\nadvertise-exit-node: true → false\nnew-flag: can't be checked; will set x\n",
		change.Diff,
	)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(t, "tailscale set --accept-dns=true --advertise-exit-node=false --new-flag=x", sys.ran[len(sys.ran)-1])
}

func TestTailscaleSet_Unavailable(t *testing.T) {
	sys := newTestSys(t)
	r := TailscaleSet{Settings: map[string]string{"ssh": "true"}}

	_, err := r.Check(context.Background(), sys)
	require.ErrorIs(t, err, ErrNotYetCheckable, "tailscale isn't installed")

	sys.on("tailscale status --json", `{"BackendState":"NeedsLogin"}`, 0)
	_, err = r.Check(context.Background(), sys)
	require.ErrorContains(t, err, "NeedsLogin")
	assert.NotErrorIs(t, err, ErrNotYetCheckable)
}

func TestSystemdReload_OnlyAfterWatchedChanges(t *testing.T) {
	sys := newTestSys(t)
	sys.on("systemctl daemon-reload", "", 0)
	st := newRunState()
	ctx := withRunState(context.Background(), st)
	r := SystemdReload{Watch: []string{"file:/etc/systemd/system/a.timer"}}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)

	st.modified["file:/etc/systemd/system/a.timer"] = true
	change, err = r.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)
	require.NoError(t, r.Apply(ctx, sys))
	assert.Equal(t, []string{"systemctl daemon-reload"}, sys.ran)
}

func TestServiceRestart_OnlyAfterWatchedChanges(t *testing.T) {
	sys := newTestSys(t)
	sys.on("systemctl restart docker", "", 0)
	st := newRunState()
	ctx := withRunState(context.Background(), st)
	r := ServiceRestart{Name: "docker", Watch: []string{"file:/etc/docker/daemon.json"}}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)

	st.modified["file:/etc/docker/daemon.json"] = true
	change, err = r.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)
	require.NoError(t, r.Apply(ctx, sys))
	assert.Equal(t, []string{"systemctl restart docker"}, sys.ran)
}

func TestSystemdUnits_RemovesUndeclaredUnits(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/systemd/system/sensible-keep.timer", "")
	sys.write("/etc/systemd/system/sensible-old.service", "")
	sys.write("/etc/systemd/system/sensible-old.timer", "")
	sys.write("/etc/systemd/system/other.service", "")
	sys.write("/etc/systemd/system/sensible-dir.wants/x", "")
	sys.on("systemctl disable --now *", "", 0)
	sys.on("systemctl daemon-reload", "", 0)
	st := newRunState()
	st.declare(File{Path: "/etc/systemd/system/sensible-keep.timer"})
	ctx := withRunState(context.Background(), st)
	r := SystemdUnits{Prefix: "sensible-"}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(
		t,
		"stop, disable and remove /etc/systemd/system/sensible-old.service\n"+
			"stop, disable and remove /etc/systemd/system/sensible-old.timer\n",
		change.Diff,
	)

	require.NoError(t, r.Apply(ctx, sys))
	assert.Equal(
		t,
		[]string{
			"systemctl disable --now sensible-old.service",
			"systemctl disable --now sensible-old.timer",
			"systemctl daemon-reload",
		},
		sys.ran,
	)
	assert.True(t, sys.exists("/etc/systemd/system/sensible-keep.timer"))
	assert.True(t, sys.exists("/etc/systemd/system/other.service"))
	assert.True(t, sys.exists("/etc/systemd/system/sensible-dir.wants/x"))
	assert.False(t, sys.exists("/etc/systemd/system/sensible-old.service"))
	assert.False(t, sys.exists("/etc/systemd/system/sensible-old.timer"))
}

func TestSystemdUnits_FailedDisableKeepsFiles(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/systemd/system/sensible-old.timer", "")
	sys.on("systemctl *", "", 1)

	err := SystemdUnits{Prefix: "sensible-"}.Apply(context.Background(), sys)

	require.Error(t, err)
	assert.True(t, sys.exists("/etc/systemd/system/sensible-old.timer"))
}

package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestFile_CreatesWithOwnerAndMode(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/app/.keep", "")
	change := checkApply(t, sys, File{Path: "/etc/app/conf", Content: "a\nb\n", Owner: "alice", Mode: 0o600})

	assert.Equal(t, "create file\n@@ -0,0 +1,2 @@\n+a\n+b\n", change.Diff)
	assert.Equal(t, "a\nb\n", sys.read("/etc/app/conf"))
	info, err := sys.Stat("/etc/app/conf")
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode.Perm())
	assert.Equal(t, os.Getuid(), info.UID)
}

func TestFile_ReportsContentAndModeChanges(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/conf", "one\ntwo\nthree\n")
	change := checkApply(t, sys, File{Path: "/etc/conf", Content: "one\n2\nthree\n", Mode: 0o640})

	assert.Equal(t, "mode: 0644 → 0640\n@@ -1,3 +1,3 @@\n one\n-two\n+2\n three\n", change.Diff)
}

func TestFile_MasksSecretsInDiff(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/conf", "user: a\npass: hunter2\n")

	change := checkApply(
		t,
		sys,
		File{Path: "/etc/conf", Content: "user: b\npass: hunter2\n", Secrets: []string{"hunter2"}},
	)
	assert.Equal(t, "@@ -1,2 +1,2 @@\n-user: a\n+user: b\n pass: (secret)\n", change.Diff)

	change = checkApply(t, sys, File{Path: "/etc/conf", Content: "user: b\npass: hunter3\n", Secrets: []string{"hunter3"}})
	assert.NotContains(t, change.Diff, "hunter3")

	change = checkApply(
		t,
		sys,
		File{Path: "/etc/conf", Content: "user: b\npass: hunter4\n", Secrets: []string{"hunter4", "hunter3"}},
	)
	assert.Equal(t, "change secret values\n", change.Diff)
}

func TestFile_HidesContent(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/app/.keep", "")

	change := checkApply(t, sys, File{Path: "/etc/app/env", Content: "TOKEN=a\n", Hidden: true})
	assert.Equal(t, "create file\ncontent hidden\n", change.Diff)

	change = checkApply(t, sys, File{Path: "/etc/app/env", Content: "TOKEN=b\n", Hidden: true})
	assert.Equal(t, "content hidden\n", change.Diff)
}

func TestFile_KeepsUnmanagedModeOnRewrite(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/conf", "old\n")
	require.NoError(t, sys.Chmod("/etc/conf", 0o600))

	checkApply(t, sys, File{Path: "/etc/conf", Content: "new\n"})

	info, err := sys.Stat("/etc/conf")
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode.Perm())
}

func TestFile_AcceptsNumericOwnerAndGroup(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/conf", "x\n")
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())

	change, err := File{Path: "/etc/conf", Content: "x\n", Owner: uid, Group: gid}.Check(context.Background(), sys)

	require.NoError(t, err)
	assert.True(t, change.InSync)
}

func TestFile_UnknownOwnerIsNotYetCheckable(t *testing.T) {
	sys := newTestSys(t)

	_, err := File{Path: "/etc/conf", Owner: "carol"}.Check(context.Background(), sys)

	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestFile_ValidatesTemporaryCopy(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/x", "old\n")
	var validated string
	sys.commands["visudo *"] = func(cmd Cmd) Result {
		data, err := os.ReadFile(cmd.Argv[2])
		require.NoError(t, err)
		validated = string(data)
		return Result{Code: 1, Stderr: "syntax error"}
	}

	err := File{Path: "/etc/sudoers.d/x", Content: "bad\n", Validate: []string{"visudo", "-cf", "%s"}}.
		Apply(context.Background(), sys)

	require.ErrorContains(t, err, "syntax error")
	assert.Equal(t, "bad\n", validated)
	assert.Equal(t, "old\n", sys.read("/etc/sudoers.d/x"))
	names, err := sys.ReadDir("/etc/sudoers.d")
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, names)
}

func TestFile_ValidatesTheCopyEvenIfItsDirIsSwapped(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.ssh/.keep", "")
	require.NoError(t, os.Chmod(sys.path("/home/alice"), 0o777))
	var validated string
	sys.commands["check *"] = func(cmd Cmd) Result {
		// Swap in another directory with a file of the same name.
		tmp, err := os.Readlink(cmd.Argv[1])
		require.NoError(t, err)
		require.NoError(t, os.Rename(sys.path("/home/alice/.ssh"), sys.path("/home/alice/.ssh-old")))
		sys.write("/home/alice/.ssh/"+filepath.Base(tmp), "good\n")

		data, err := os.ReadFile(cmd.Argv[1])
		require.NoError(t, err)
		validated = string(data)
		return Result{Code: 1}
	}

	err := File{Path: "/home/alice/.ssh/config", Content: "bad\n", Validate: []string{"check", "%s"}}.
		Apply(context.Background(), sys)

	require.Error(t, err)
	assert.Equal(t, "bad\n", validated)
}

func TestFile_ChangingAptSourceMarksIndexStale(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/apt/sources.list.d/.keep", "")
	st := newRunState()

	r := File{Path: "/etc/apt/sources.list.d/x.list", Content: "deb x\n"}
	err := r.Apply(withRunState(context.Background(), st), sys)

	require.NoError(t, err)
	assert.True(t, st.aptSourcesChanged)
}

func TestDir_CreatesAndFixesMode(t *testing.T) {
	sys := newTestSys(t)

	change := checkApply(t, sys, Dir{Path: "/srv/a/b", Owner: "alice", Mode: 0o700})

	assert.Equal(t, "create directory\n", change.Diff)
	info, err := sys.Stat("/srv/a/b")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, fs.FileMode(0o700), info.Mode.Perm())

	change = checkApply(t, sys, Dir{Path: "/srv/a/b", Mode: 0o755})
	assert.Equal(t, "mode: 0700 → 0755\n", change.Diff)
}

func TestDir_FailsOnFile(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/srv", "")

	_, err := Dir{Path: "/srv"}.Check(context.Background(), sys)

	assert.Error(t, err)
}

// userHome makes /home/alice a directory someone other than the agent can
// change, with .ssh swapped for a link to target.
func userHome(t *testing.T, sys *testSys, target string) {
	t.Helper()
	sys.write("/home/alice/.profile", "")
	require.NoError(t, os.Chmod(sys.path("/home/alice"), 0o777))
	require.NoError(t, os.Symlink(target, sys.path("/home/alice/.ssh")))
}

func TestDir_DoesNotChmodThroughSwappedLink(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/usr/bin/sh", "")
	userHome(t, sys, "../../usr")

	err := Dir{Path: "/home/alice/.ssh", Mode: 0o700}.Apply(context.Background(), sys)

	require.Error(t, err)
	info, err := sys.Stat("/usr")
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o755), info.Mode.Perm())
}

func TestFile_DoesNotWriteThroughSwappedLink(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/README", "")
	userHome(t, sys, "../../etc/sudoers.d")

	err := File{Path: "/home/alice/.ssh/authorized_keys", Content: "ALL ALL=(ALL) NOPASSWD: ALL\n"}.
		Apply(context.Background(), sys)

	require.Error(t, err)
	assert.False(t, sys.exists("/etc/sudoers.d/authorized_keys"))
}

func TestFile_DoesNotFollowLinksInUserDirs(t *testing.T) {
	sys := newTestSys(t)
	userHome(t, sys, "dotfiles/ssh")
	sys.write("/home/alice/dotfiles/ssh/.keep", "")

	err := File{Path: "/home/alice/.ssh/authorized_keys", Content: "key\n"}.Apply(context.Background(), sys)

	require.Error(t, err)
	assert.False(t, sys.exists("/home/alice/dotfiles/ssh/authorized_keys"))
}

func TestDir_DoesNotChmodThroughLinkInsideUserDir(t *testing.T) {
	sys := newTestSys(t)
	userHome(t, sys, "secret")
	sys.write("/home/alice/secret", "")
	require.NoError(t, os.Chmod(sys.path("/home/alice/secret"), 0o600))

	err := Dir{Path: "/home/alice/.ssh", Mode: 0o755}.Apply(context.Background(), sys)

	require.Error(t, err)
	info, err := os.Stat(sys.path("/home/alice/secret"))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
}

func TestFile_DoesNotFollowLinksIntoUserDirsWhereTheyChange(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/README", "")
	userHome(t, sys, "../../etc/sudoers.d")
	require.NoError(t, os.Symlink("../home/alice/.ssh", sys.path("/etc/ssh-keys")))

	err := File{Path: "/etc/ssh-keys/authorized_keys", Content: "ALL ALL=(ALL) NOPASSWD: ALL\n"}.
		Apply(context.Background(), sys)

	require.Error(t, err)
	assert.False(t, sys.exists("/etc/sudoers.d/authorized_keys"))
}

func TestSys_DoesNotChangeFilesHardLinkedIntoUserDirs(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.profile", "")
	require.NoError(t, os.Chmod(sys.path("/home/alice"), 0o777))
	require.NoError(t, os.Chmod(sys.path("/etc/shadow"), 0o600))
	require.NoError(t, os.Link(sys.path("/etc/shadow"), sys.path("/home/alice/.zshrc")))

	require.ErrorIs(t, sys.Chmod("/home/alice/.zshrc", 0o644), errHardLinked)
	require.ErrorIs(t, sys.Chown("/home/alice/.zshrc", os.Getuid(), os.Getgid()), errHardLinked)
	info, err := sys.Stat("/etc/shadow")
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode.Perm())
}

func TestSys_WritesInPlaceKeepingTheFile(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/hosts", "127.0.0.1 localhost old-name.example.com\n")
	before, err := os.Stat(sys.path("/etc/hosts"))
	require.NoError(t, err)

	err = confinedErr(
		sys.localSys,
		"/etc/hosts",
		lastAsIs,
		func(f fileOps) error {
			return f.writeInPlace(
				[]byte("127.0.0.1 localhost\n"),
				WriteOptions{UID: os.Getuid(), GID: os.Getgid(), Mode: 0o600},
			)
		},
	)

	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1 localhost\n", sys.read("/etc/hosts"))
	after, err := os.Stat(sys.path("/etc/hosts"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after))
	assert.Equal(t, fs.FileMode(0o600), after.Mode().Perm())
}

func TestSys_DoesNotWriteInPlaceToFilesHardLinkedIntoUserDirs(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.profile", "")
	require.NoError(t, os.Chmod(sys.path("/home/alice"), 0o777))
	require.NoError(t, os.Link(sys.path("/etc/shadow"), sys.path("/home/alice/.zshrc")))

	err := confinedErr(
		sys.localSys,
		"/home/alice/.zshrc",
		lastAsIs,
		func(f fileOps) error {
			return f.writeInPlace([]byte("x"), WriteOptions{UID: os.Getuid(), GID: os.Getgid(), Mode: 0o644})
		},
	)

	require.ErrorIs(t, err, errHardLinked)
	assert.NotEqual(t, "x", sys.read("/etc/shadow"))
}

func TestSys_DoesNotWaitOnFIFOs(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.profile", "")
	require.NoError(t, os.Chmod(sys.path("/home/alice"), 0o777))
	require.NoError(t, unix.Mkfifo(sys.path("/home/alice/.zshrc"), 0o644))

	_, err := sys.ReadFile("/home/alice/.zshrc")

	assert.ErrorIs(t, err, errNotRegular)
}

func TestSys_GlobDoesNotFollowLinksInUserDirs(t *testing.T) {
	sys := newTestSys(t)
	userHome(t, sys, "keys")
	sys.write("/home/alice/keys/authorized_keys", "")
	sys.write("/home/bob/.ssh/authorized_keys", "")
	require.NoError(t, os.Symlink("bob", sys.path("/home/carol")))

	matches, err := sys.Glob("/home/*/.ssh/authorized_keys")

	require.NoError(t, err)
	assert.Equal(t, []string{"/home/bob/.ssh/authorized_keys", "/home/carol/.ssh/authorized_keys"}, matches)
}

func TestSys_RunsCommandsInDirWithoutFollowingUserLinks(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/srv/app/.keep", "")
	userHome(t, sys, "../../srv/app")
	local := &localSys{root: sys.root}

	res, err := local.Run(context.Background(), Cmd{Argv: []string{"pwd", "-P"}, Dir: "/srv/app"})
	require.NoError(t, err)
	want, err := filepath.EvalSymlinks(sys.path("/srv/app"))
	require.NoError(t, err)
	assert.Equal(t, want+"\n", res.Stdout)

	_, err = local.Run(context.Background(), Cmd{Argv: []string{"pwd"}, Dir: "/home/alice/.ssh"})
	assert.ErrorIs(t, err, errUntrustedLink)
}

func TestSys_RunsUsersCommandsInTheirHomeUnlessItIsALink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("running a command as another user needs root")
	}
	sys := newTestSys(t)
	sys.write("/etc/passwd", "alice:x:65534:65534::/home/alice:/bin/sh\nbob:x:65534:65534::/home/bob:/bin/sh\n")
	sys.write("/etc/group", "nogroup:x:65534:\n")
	sys.write("/home/alice/.profile", "")
	require.NoError(t, os.Chmod(sys.path("/home"), 0o777))
	require.NoError(t, os.Symlink("alice", sys.path("/home/bob")))
	local := &localSys{root: sys.root}

	res, err := local.Run(context.Background(), Cmd{Argv: []string{"pwd", "-P"}, User: "alice"})
	require.NoError(t, err)
	want, err := filepath.EvalSymlinks(sys.path("/home/alice"))
	require.NoError(t, err)
	assert.Equal(t, want+"\n", res.Stdout)

	res, err = local.Run(context.Background(), Cmd{Argv: []string{"pwd", "-P"}, User: "bob"})
	require.NoError(t, err)
	assert.Equal(t, "/\n", res.Stdout)
}

func TestSys_FollowsLastLinkTheAgentControls(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/usr/lib/os-release", "ID=debian\n")
	require.NoError(t, os.Symlink("/usr/lib/os-release", sys.path("/etc/os-release")))

	data, err := sys.ReadFile("/etc/os-release")
	require.NoError(t, err)
	assert.Equal(t, "ID=debian\n", string(data))
	require.NoError(t, sys.Chmod("/etc/os-release", 0o600))
	info, err := sys.Lstat("/usr/lib/os-release")
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode.Perm())
	info, err = sys.Lstat("/etc/os-release")
	require.NoError(t, err)
	assert.True(t, info.IsSymlink())
}

func TestFile_FollowsLinksTheAgentControls(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/run/.keep", "")
	require.NoError(t, os.MkdirAll(sys.path("/var"), 0o755))
	require.NoError(t, os.Symlink("../run", sys.path("/var/run")))

	checkApply(t, sys, File{Path: "/var/run/app.conf", Content: "x\n"})

	assert.Equal(t, "x\n", sys.read("/run/app.conf"))
}

func TestAbsent_RemovesTree(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.oh-my-zsh/lib/x.zsh", "")

	change := checkApply(t, sys, Absent{Path: "/home/alice/.oh-my-zsh"})

	assert.Equal(t, "remove directory and its contents\n", change.Diff)
	assert.False(t, sys.exists("/home/alice/.oh-my-zsh"))
}

func TestAbsent_RemovesLinksNotWhatTheyPointAt(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/notes/x", "")
	sys.write("/home/alice/.oh-my-zsh/lib/x.zsh", "")
	require.NoError(t, os.Chmod(sys.path("/home/alice"), 0o777))
	require.NoError(t, os.Symlink("../../notes", sys.path("/home/alice/.oh-my-zsh/lib/notes")))

	checkApply(t, sys, Absent{Path: "/home/alice/.oh-my-zsh"})

	assert.False(t, sys.exists("/home/alice/.oh-my-zsh"))
	assert.True(t, sys.exists("/home/alice/notes/x"))
}

func TestDisowned_WarnsAboutUndeclaredWithoutRemoving(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.zshrc", "# Managed\nalice")
	sys.write("/home/bob/.zshrc", "# Managed\nbob")
	sys.write("/home/carol/.zshrc", "by hand")
	sys.write("/root/.zshrc", "# Managed\nroot")
	st := newRunState()
	st.declare(File{Path: "/home/bob/.zshrc"})
	ctx := withRunState(context.Background(), st)
	r := Disowned{
		Name:   "zsh",
		Paths:  []string{"/root/.zshrc", "/home/*/.zshrc", "/home/alice/.zshrc"},
		Header: "# Managed",
	}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)
	assert.Equal(
		t,
		"/root/.zshrc\n/home/alice/.zshrc\n"+
			"no longer managed; run `sensible prune` to remove them once they're not needed\n",
		change.Warning,
	)

	require.NoError(t, r.Apply(ctx, sys))
	assert.True(t, sys.exists("/home/alice/.zshrc"))
	assert.True(t, sys.exists("/root/.zshrc"))
}

func TestDisowned_TargetLimitsToSymlinks(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/usr/local/bin/view", "binary")
	require.NoError(t, sys.Symlink("/usr/bin/vim", "/usr/local/bin/vi"))
	require.NoError(t, sys.Symlink("/usr/bin/nvim", "/usr/local/bin/ex"))
	r := Disowned{Name: "vim", Paths: []string{"/usr/local/bin/*"}, Target: "/usr/bin/vim"}

	got, err := r.Leftovers(context.Background(), sys)

	require.NoError(t, err)
	assert.Equal(t, []string{"/usr/local/bin/vi"}, got)
}

func TestDisowned_RecordedLimitsToFilesAsWritten(t *testing.T) {
	sys := newTestSys(t)
	for _, f := range []File{
		{Path: "/etc/docker/daemon.json", Content: "{}\n"},
		{Path: "/root/.docker/config.json", Content: `{"auths": {}}`},
	} {
		record := WrittenRecord(f)
		sys.write(f.Path, f.Content)
		sys.write(record.Path, record.Content)
	}
	sys.write("/root/.docker/config.json", `{"auths": {"by": "hand"}}`)
	sys.write("/etc/docker/other.json", "{}\n")
	r := Disowned{
		Name:     "docker",
		Paths:    []string{"/etc/docker/*.json", "/root/.docker/config.json"},
		Recorded: true,
	}

	got, err := r.Leftovers(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/docker/daemon.json"}, got)

	require.NoError(t, r.Prune(context.Background(), sys, "/etc/docker/daemon.json"))
	assert.False(t, sys.exists("/etc/docker/daemon.json"))
	assert.False(t, sys.exists(recordPath(WrittenDir, "/etc/docker/daemon.json")))
	assert.True(t, sys.exists(recordPath(WrittenDir, "/root/.docker/config.json")))
}

func TestDisowned_RecordedForgetsFilesNoLongerAsWritten(t *testing.T) {
	sys := newTestSys(t)
	for _, f := range []File{
		{Path: "/etc/docker/daemon.json", Content: "{}\n"},
		{Path: "/etc/docker/gone.json", Content: "{}\n"},
		{Path: "/etc/docker/kept.json", Content: "{}\n"},
		{Path: "/etc/docker/declared.json", Content: "{}\n"},
		{Path: "/etc/other.json", Content: "{}\n"},
	} {
		record := WrittenRecord(f)
		sys.write(f.Path, f.Content)
		sys.write(record.Path, record.Content)
	}
	sys.write("/etc/docker/daemon.json", `{"by": "hand"}`)
	sys.write("/etc/docker/declared.json", `{"by": "hand"}`)
	sys.write("/etc/other.json", `{"by": "hand"}`)
	require.NoError(t, os.Remove(sys.path("/etc/docker/gone.json")))
	r := Disowned{Name: "docker", Paths: []string{"/etc/docker/*.json"}, Recorded: true}
	st := newRunState()
	st.declare(File{Path: "/etc/docker/declared.json"})
	ctx := withRunState(context.Background(), st)

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)
	assert.Equal(t, "forget record of /etc/docker/daemon.json\nforget record of /etc/docker/gone.json\n", change.Diff)
	assert.Contains(t, change.Warning, "/etc/docker/kept.json")

	require.NoError(t, r.Apply(ctx, sys))
	after, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, after.InSync)
	assert.Equal(t, change.Warning, after.Warning)
	assert.False(t, sys.exists(recordPath(WrittenDir, "/etc/docker/daemon.json")))
	assert.False(t, sys.exists(recordPath(WrittenDir, "/etc/docker/gone.json")))
	assert.True(t, sys.exists("/etc/docker/daemon.json"))
	for _, kept := range []string{"/etc/docker/kept.json", "/etc/docker/declared.json", "/etc/other.json"} {
		assert.True(t, sys.exists(recordPath(WrittenDir, kept)), kept)
	}
}

func TestDisowned_RecordsFindsFilesAtAnyPath(t *testing.T) {
	sys := newTestSys(t)
	const dir = WrittenDir + "/files"
	for _, f := range []File{
		{Path: "/etc/zram.conf", Content: "[zram0]\n"},
		{Path: "/usr/local/bin/tool", Content: "binary"},
		{Path: "/etc/edited.conf", Content: "as written\n"},
		{Path: "/etc/declared.conf", Content: "as written\n"},
		{Path: "/etc/gone.conf", Content: "as written\n"},
	} {
		record := WrittenRecordIn(dir, f)
		sys.write(f.Path, f.Content)
		sys.write(record.Path, record.Content)
	}
	sys.write("/etc/edited.conf", "by hand\n")
	require.NoError(t, os.Remove(sys.path("/etc/gone.conf")))
	// Another feature's record isn't this resource's.
	docker := WrittenRecord(File{Path: "/etc/docker/daemon.json", Content: "{}\n"})
	sys.write("/etc/docker/daemon.json", "{}\n")
	sys.write(docker.Path, docker.Content)
	r := Disowned{Name: "files", Records: dir}
	st := newRunState()
	st.declare(File{Path: "/etc/declared.conf"})
	ctx := withRunState(context.Background(), st)

	got, err := r.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"/etc/zram.conf", "/usr/local/bin/tool"}, got)

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "forget record of /etc/edited.conf\nforget record of /etc/gone.conf\n", change.Diff)
	require.NoError(t, r.Apply(ctx, sys))
	assert.True(t, sys.exists("/etc/edited.conf"))
	assert.False(t, sys.exists(recordPath(dir, "/etc/edited.conf")))
	assert.True(t, sys.exists(recordPath(dir, "/etc/declared.conf")))

	require.NoError(t, r.Prune(ctx, sys, "/usr/local/bin/tool"))
	assert.False(t, sys.exists("/usr/local/bin/tool"))
	assert.False(t, sys.exists(recordPath(dir, "/usr/local/bin/tool")))
	assert.True(t, sys.exists(docker.Path))
}

func TestFile_CarriesContentThatIsNotUTF8(t *testing.T) {
	for _, content := range []string{"text\n", "\x7fELF\x00\xff\xfe"} {
		data, err := json.Marshal(ResourceList{File{Path: "/usr/local/bin/tool", Content: content}})
		require.NoError(t, err)
		var got ResourceList
		require.NoError(t, json.Unmarshal(data, &got))
		assert.Equal(t, content, got[0].(File).Content)
	}
}

func TestFile_DoesNotDiffBinaryContent(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/usr/local/bin/tool", "\x7fELF\x01")

	change, err := File{Path: "/usr/local/bin/tool", Content: "\x7fELF\x02\xff"}.Check(context.Background(), sys)

	require.NoError(t, err)
	assert.Equal(t, "change binary content\n", change.Diff)
}

func TestDisowned_SkipsWhatOtherResourcesDeclare(t *testing.T) {
	sys := newTestSys(t)
	for _, path := range []string{"/usr/local/bin/vi", "/usr/share/oh-my-zsh/oh-my-zsh.sh", "/var/cache/pam-rssh.deb"} {
		sys.write(path, "")
	}
	st := newRunState()
	st.declare(Symlink{Path: "/usr/local/bin/vi"})
	st.declare(GitCheckout{Path: "/usr/share/oh-my-zsh"})
	st.declare(Download{Path: "/var/cache/pam-rssh.deb"})
	r := Disowned{Name: "all", Paths: []string{"/usr/local/bin/vi", "/usr/share/oh-my-zsh", "/var/cache/*.deb"}}

	got, err := r.Leftovers(withRunState(context.Background(), st), sys)

	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestDisowned_NothingWhenAbsent(t *testing.T) {
	r := Disowned{Name: "docker", Paths: []string{"/etc/docker/daemon.json"}}

	change, err := r.Check(context.Background(), newTestSys(t))

	require.NoError(t, err)
	assert.Equal(t, Change{InSync: true}, change)
}

func TestDisowned_PruneRemovesThenNotifies(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/ssh/sshd_config.d/10-sensible.conf", "# Managed\n")
	sys.on("systemctl show --property=LoadState,ActiveState ssh", "LoadState=loaded\nActiveState=active\n", 0)
	sys.on("systemctl reload ssh", "", 0)
	r := Disowned{
		Name:   "sshd",
		Paths:  []string{"/etc/ssh/sshd_config.d/10-sensible.conf"},
		Notify: ResourceList{ServiceAction{Name: "ssh", Action: "reload"}},
	}

	require.NoError(t, r.Prune(context.Background(), sys, "/etc/ssh/sshd_config.d/10-sensible.conf"))

	assert.False(t, sys.exists("/etc/ssh/sshd_config.d/10-sensible.conf"))
	assert.Equal(t, "systemctl reload ssh", sys.ran[len(sys.ran)-1])
}

func TestSymlink_CreatesAndRetargets(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/usr/local/bin/.keep", "")

	checkApply(t, sys, Symlink{Path: "/usr/local/bin/vi", Target: "/usr/bin/nano"})
	change := checkApply(t, sys, Symlink{Path: "/usr/local/bin/vi", Target: "/usr/bin/vim"})

	assert.Equal(t, "target: /usr/bin/nano → /usr/bin/vim\n", change.Diff)
	target, err := sys.Readlink("/usr/local/bin/vi")
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/vim", target)
}

func TestSymlink_RefusesToReplaceFile(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/usr/local/bin/vi", "binary")

	_, err := Symlink{Path: "/usr/local/bin/vi", Target: "/usr/bin/vim"}.Check(context.Background(), sys)

	assert.Error(t, err)
}

func TestLineInFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		resource LineInFile
		want     string
	}{
		{
			name:     "replaces the last match",
			content:  "auth a\n#x\nauth b\nother\n",
			resource: LineInFile{Regexp: `^auth`, Line: "auth new"},
			want:     "auth a\n#x\nauth new\nother\n",
		},
		{
			name:     "inserts before the first matching line",
			content:  "#%PAM-1.0\nauth include system\nauth other\n",
			resource: LineInFile{Regexp: `pam_rssh`, Line: "auth sufficient pam_rssh.so", InsertBefore: `^auth\s`},
			want:     "#%PAM-1.0\nauth sufficient pam_rssh.so\nauth include system\nauth other\n",
		},
		{
			name:     "appends without an insertion point",
			content:  "a\nb",
			resource: LineInFile{Regexp: `^c`, Line: "c", InsertBefore: `^z`},
			want:     "a\nb\nc\n",
		},
		{
			name:     "leaves an exact line that doesn't match the regexp",
			content:  "a\nc\n",
			resource: LineInFile{Regexp: `^x`, Line: "c"},
			want:     "a\nc\n",
		},
		{
			name:     "removes every match when absent",
			content:  "auth x\nauth sufficient pam_rssh.so\nauth y\n  auth optional pam_rssh.so\n",
			resource: LineInFile{Regexp: `^\s*auth\s+\S+\s+pam_rssh\.so`, Absent: true},
			want:     "auth x\nauth y\n",
		},
		{
			name:     "leaves a file without a match when absent",
			content:  "auth x\n",
			resource: LineInFile{Regexp: `pam_rssh`, Absent: true},
			want:     "auth x\n",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newTestSys(t)
				sys.write("/etc/f", tt.content)
				tt.resource.Path = "/etc/f"

				change, err := tt.resource.Check(context.Background(), sys)
				require.NoError(t, err)
				assert.Equal(t, tt.content == tt.want, change.InSync)
				require.NoError(t, tt.resource.Apply(context.Background(), sys))
				assert.Equal(t, tt.want, sys.read("/etc/f"))
			},
		)
	}
}

func TestLineInFile_MissingFileIsNotYetCheckable(t *testing.T) {
	sys := newTestSys(t)

	_, err := LineInFile{Path: "/etc/pam.d/sudo", Regexp: "x", Line: "x"}.Check(context.Background(), sys)

	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestLineInFile_AbsentFromMissingFileIsInSync(t *testing.T) {
	change, err := LineInFile{Path: "/etc/pam.d/sudo-i", Regexp: "x", Absent: true}.
		Check(context.Background(), newTestSys(t))

	require.NoError(t, err)
	assert.True(t, change.InSync)
}

func TestCommentOut_CommentsMatchingLinesAcrossFiles(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/pam.d/login", "auth x\nsession optional pam_motd.so\n# session optional pam_lastlog.so\n")
	sys.write("/etc/pam.d/sshd", "  session optional pam_lastlog2.so silent\n")
	sys.write("/etc/pam.d/su", "auth y\n")
	change := checkApply(t, sys, CommentOut{Glob: "/etc/pam.d/*", Regexp: `^\s*session\s+.*pam_(motd|lastlog2?)\.so`})

	assert.Contains(t, change.Diff, "--- /etc/pam.d/login\n")
	assert.NotContains(t, change.Diff, "/etc/pam.d/su")
	assert.Equal(
		t,
		"auth x\n# session optional pam_motd.so\n# session optional pam_lastlog.so\n",
		sys.read("/etc/pam.d/login"),
	)
	assert.Equal(t, "#   session optional pam_lastlog2.so silent\n", sys.read("/etc/pam.d/sshd"))
	assert.Equal(t, "auth y\n", sys.read("/etc/pam.d/su"))
}

func TestDownload_VerifiesChecksum(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/var/cache/.keep", "")
	sys.urls["https://example.com/x.deb"] = "package"
	sum := sha256.Sum256([]byte("package"))
	r := Download{URL: "https://example.com/x.deb", Path: "/var/cache/x.deb", SHA256: hex.EncodeToString(sum[:])}

	checkApply(t, sys, r)
	assert.Equal(t, "package", sys.read("/var/cache/x.deb"))

	sys.urls["https://example.com/x.deb"] = "tampered"
	sys.write("/var/cache/x.deb", "stale")
	err := r.Apply(context.Background(), sys)
	require.ErrorContains(t, err, "SHA-256")
	assert.Equal(t, "stale", sys.read("/var/cache/x.deb"))
}

func TestOwnedDir_RemovesUndeclaredEntries(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/keep", "")
	sys.write("/etc/sudoers.d/.hidden", "")
	sys.write("/etc/sudoers.d/old/nested", "")
	st := newRunState()
	st.declare(File{Path: "/etc/sudoers.d/keep"})
	ctx := withRunState(context.Background(), st)
	r := OwnedDir{Path: "/etc/sudoers.d"}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "remove /etc/sudoers.d/.hidden\nremove /etc/sudoers.d/old\n", change.Diff)

	require.NoError(t, r.Apply(ctx, sys))
	names, err := sys.ReadDir("/etc/sudoers.d")
	require.NoError(t, err)
	assert.Equal(t, []string{"keep"}, names)
}

func TestOwnedDir_RecursiveCleansDeclaredDirs(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/srv/app/keep", "")
	sys.write("/srv/app/conf/keep", "")
	sys.write("/srv/app/conf/stray", "")
	sys.write("/srv/app/old/nested", "")
	st := newRunState()
	st.declare(File{Path: "/srv/app/keep"})
	st.declare(Dir{Path: "/srv/app/conf"})
	st.declare(File{Path: "/srv/app/conf/keep"})
	ctx := withRunState(context.Background(), st)
	r := OwnedDir{Path: "/srv/app", Recursive: true}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "remove /srv/app/conf/stray\nremove /srv/app/old\n", change.Diff)

	require.NoError(t, r.Apply(ctx, sys))
	assert.True(t, sys.exists("/srv/app/conf/keep"))
	assert.False(t, sys.exists("/srv/app/conf/stray"))
	assert.False(t, sys.exists("/srv/app/old"))
}

func TestOwnedDir_HeaderLeavesOtherEntriesForPrune(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/keep", "# Managed\nkeep\n")
	sys.write("/etc/sudoers.d/old", "# Managed\nold\n")
	sys.write("/etc/sudoers.d/90-cloud-init-users", "ubuntu ALL=(ALL) NOPASSWD:ALL\n")
	sys.write("/etc/sudoers.d/dir/nested", "# Managed\n")
	st := newRunState()
	st.declare(File{Path: "/etc/sudoers.d/keep"})
	ctx := withRunState(context.Background(), st)
	r := OwnedDir{Path: "/etc/sudoers.d", Header: "# Managed"}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)
	assert.Equal(t, "remove /etc/sudoers.d/old\n", change.Diff)
	assert.Contains(t, change.Warning, "/etc/sudoers.d/90-cloud-init-users\n/etc/sudoers.d/dir\n")

	require.NoError(t, r.Apply(ctx, sys))
	names, err := sys.ReadDir("/etc/sudoers.d")
	require.NoError(t, err)
	assert.Equal(t, []string{"90-cloud-init-users", "dir", "keep"}, names)

	change, err = r.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)
	assert.NotEmpty(t, change.Warning)
	leftovers, err := r.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/sudoers.d/90-cloud-init-users", "/etc/sudoers.d/dir"}, leftovers)
}

func TestOwnedDir_WithoutHeaderLeavesNothingForPrune(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/stray", "")

	leftovers, err := OwnedDir{Path: "/etc/sudoers.d"}.Leftovers(
		withRunState(context.Background(), newRunState()),
		sys,
	)
	require.NoError(t, err)
	assert.Empty(t, leftovers)
}

func TestOwnedDir_PruneRemovesThenNotifies(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/systemd/timesyncd.conf.d/local.conf", "[Time]\n")
	sys.on(
		"systemctl show --property=LoadState,ActiveState systemd-timesyncd",
		"LoadState=loaded\nActiveState=active\n",
		0,
	)
	sys.on("systemctl restart systemd-timesyncd", "", 0)
	r := OwnedDir{
		Path:   "/etc/systemd/timesyncd.conf.d",
		Header: "# Managed",
		Notify: ResourceList{ServiceAction{Name: "systemd-timesyncd", Action: "restart"}},
	}

	require.NoError(t, r.Prune(context.Background(), sys, "/etc/systemd/timesyncd.conf.d/local.conf"))

	assert.False(t, sys.exists("/etc/systemd/timesyncd.conf.d/local.conf"))
	assert.Equal(t, "systemctl restart systemd-timesyncd", sys.ran[len(sys.ran)-1])
}

func TestUnifiedDiff(t *testing.T) {
	lines := func(n int, change map[int]string) string {
		var b strings.Builder
		for i := 1; i <= n; i++ {
			if s, ok := change[i]; ok {
				b.WriteString(s)
			} else {
				b.WriteString("l" + strconv.Itoa(i) + "\n")
			}
		}
		return b.String()
	}

	tests := []struct {
		name     string
		old, new string
		want     string
	}{
		{name: "equal", old: "a\n", new: "a\n", want: ""},
		{
			name: "separate hunks",
			old:  lines(20, nil),
			new:  lines(20, map[int]string{2: "X\n", 18: ""}),
			want: "@@ -1,5 +1,5 @@\n l1\n-l2\n+X\n l3\n l4\n l5\n" +
				"@@ -15,6 +15,5 @@\n l15\n l16\n l17\n-l18\n l19\n l20\n",
		},
		{
			name: "nearby changes share a hunk",
			old:  lines(10, nil),
			new:  lines(10, map[int]string{3: "X\n", 8: "Y\n"}),
			want: "@@ -1,10 +1,10 @@\n l1\n l2\n-l3\n+X\n l4\n l5\n l6\n l7\n-l8\n+Y\n l9\n l10\n",
		},
		{
			name: "missing final newline",
			old:  "a\nb",
			new:  "a\nb\n",
			want: "@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n",
		},
		{
			name: "insertion",
			old:  "a\nc\n",
			new:  "a\nb\nc\n",
			want: "@@ -1,2 +1,3 @@\n a\n+b\n c\n",
		},
		{
			name: "removing everything",
			old:  "a\n",
			new:  "",
			want: "@@ -1 +0,0 @@\n-a\n",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				assert.Equal(t, tt.want, unifiedDiff(tt.old, tt.new))
			},
		)
	}
}

package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		validated = sys.read(cmd.Argv[2])
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

func TestAbsent_RemovesTree(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.oh-my-zsh/lib/x.zsh", "")

	change := checkApply(t, sys, Absent{Path: "/home/alice/.oh-my-zsh"})

	assert.Equal(t, "remove directory and its contents\n", change.Diff)
	assert.False(t, sys.exists("/home/alice/.oh-my-zsh"))
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

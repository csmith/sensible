package host

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newArchSys(t *testing.T) *testSys {
	sys := newTestSys(t)
	sys.write("/etc/os-release", "NAME=\"Arch Linux\"\nID=arch\n")
	sys.write("/var/lib/pacman/local/ALPM_DB_VERSION", "9\n")
	sys.write("/var/lib/pacman/local/vim-9.1-1/desc", "%NAME%\nvim\n\n%VERSION%\n9.1-1\n\n%PROVIDES%\nxxd\nvi=9.1\n\n")
	sys.write("/var/lib/pacman/local/zsh-5.9-1/desc", "%NAME%\nzsh\n\n%VERSION%\n5.9-1\n\n")
	return sys
}

func TestPackage_Pacman(t *testing.T) {
	tests := []struct {
		name     string
		resource Package
		inSync   bool
		apply    string
	}{
		{name: "installed", resource: Package{Name: "zsh"}, inSync: true},
		{name: "provided", resource: Package{Name: "vi"}, inSync: true},
		{name: "missing", resource: Package{Name: "git"}, apply: "pacman -S --needed --noconfirm git"},
		{name: "absent", resource: Package{Name: "git", Absent: true}, inSync: true},
		{name: "only provided, so not removed", resource: Package{Name: "xxd", Absent: true}, inSync: true},
		{name: "installed and unwanted", resource: Package{Name: "zsh", Absent: true}, apply: "pacman -R --noconfirm zsh"},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newArchSys(t)
				sys.on(tt.apply, "", 0)
				ctx := withRunState(context.Background(), newRunState())

				change, err := tt.resource.Check(ctx, sys)
				require.NoError(t, err)
				assert.Equal(t, tt.inSync, change.InSync)
				if !tt.inSync {
					require.NoError(t, tt.resource.Apply(ctx, sys))
					assert.Equal(t, []string{tt.apply}, sys.ran)
				}
			},
		)
	}
}

func TestPackage_PacmanDatabaseIsCachedUntilAChange(t *testing.T) {
	sys := newArchSys(t)
	st := newRunState()
	ctx := withRunState(context.Background(), st)

	change, err := Package{Name: "git"}.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)

	sys.write("/var/lib/pacman/local/git-2.0-1/desc", "%NAME%\ngit\n")
	change, err = Package{Name: "git"}.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync, "the database should be read once")

	st.changed()
	change, err = Package{Name: "git"}.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)
}

func newDebianSys(t *testing.T) *testSys {
	sys := newTestSys(t)
	sys.write("/etc/os-release", "ID=debian\nVERSION_CODENAME=trixie\n")
	sys.write(
		"/var/lib/dpkg/status",
		"Package: zsh\nStatus: install ok installed\nVersion: 5.9-8\n"+
			"Description: shell\n multi-line: description\n\n"+
			"Package: old\nStatus: deinstall ok config-files\nVersion: 1\n\n"+
			"Package: pam-rssh\nStatus: install ok installed\nVersion: 1.2.1-1\n",
	)
	sys.write("/var/lib/apt/lists/lock", "")
	require.NoError(t, os.Chtimes(sys.path("/var/lib/apt/lists"), sys.now, sys.now.Add(-10*time.Minute)))
	return sys
}

func TestPackage_AptInstalledAndRemoved(t *testing.T) {
	sys := newDebianSys(t)
	ctx := withRunState(context.Background(), newRunState())

	change, err := Package{Name: "zsh"}.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)

	change, err = Package{Name: "old", Absent: true}.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)

	sys.on("apt-get -y -q remove zsh", "", 0)
	require.NoError(t, Package{Name: "zsh", Absent: true}.Apply(ctx, sys))
	assert.Equal(t, []string{"apt-get -y -q remove zsh"}, sys.ran)
}

const aptInstallGit = "apt-get -y -q install -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold git"

func TestPackage_AptAvailability(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		indexAge time.Duration
		// sourcesChanged marks an apt source as changed earlier in the run.
		sourcesChanged bool
		wantDiff       string
		notYet         bool
		wantApply      []string
	}{
		{
			name:      "available with a fresh index",
			policy:    "git:\n  Installed: (none)\n  Candidate: 1:2.47\n",
			indexAge:  10 * time.Minute,
			wantDiff:  "install package (1:2.47)\n",
			wantApply: []string{aptInstallGit},
		},
		{
			name:     "available with a stale index",
			policy:   "git:\n  Installed: (none)\n  Candidate: 1:2.47\n",
			indexAge: 2 * time.Hour,
			wantDiff: "install package (1:2.47)\n",
			wantApply: []string{
				"apt-get -y -q update",
				aptInstallGit,
			},
		},
		{
			name:     "unknown with a stale index",
			indexAge: 2 * time.Hour,
			wantDiff: "install package, after refreshing the package index\n",
		},
		{
			name:     "unknown with a fresh index",
			indexAge: 10 * time.Minute,
			notYet:   true,
		},
		{
			name:           "unknown with a fresh index after a source changed",
			indexAge:       10 * time.Minute,
			sourcesChanged: true,
			wantDiff:       "install package, after refreshing the package index\n",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newDebianSys(t)
				require.NoError(t, os.Chtimes(sys.path("/var/lib/apt/lists"), sys.now, sys.now.Add(-tt.indexAge)))
				sys.on("apt-cache policy git", tt.policy, 0)
				sys.on("apt-get *", "", 0)
				st := newRunState()
				st.aptSourcesChanged = tt.sourcesChanged
				ctx := withRunState(context.Background(), st)

				change, err := Package{Name: "git"}.Check(ctx, sys)
				if tt.notYet {
					require.ErrorIs(t, err, ErrNotYetCheckable)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.wantDiff, change.Diff)

				if tt.wantApply != nil {
					sys.ran = nil
					require.NoError(t, Package{Name: "git"}.Apply(ctx, sys))
					assert.Equal(t, tt.wantApply, sys.ran)
				}
			},
		)
	}
}

func TestPackage_AptUpdatesOnceAfterSourceChange(t *testing.T) {
	sys := newDebianSys(t)
	sys.on("apt-get *", "", 0)
	st := newRunState()
	ctx := withRunState(context.Background(), st)
	st.aptSourcesChanged = true

	require.NoError(t, Package{Name: "a"}.Apply(ctx, sys))
	require.NoError(t, Package{Name: "b"}.Apply(ctx, sys))

	assert.Equal(t, "apt-get -y -q update", sys.ran[0])
	assert.NotContains(t, sys.ran[1:], "apt-get -y -q update")
}

func TestPackage_Deb(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		wantDiff string
	}{
		{name: "same version", version: "1.2.1-1"},
		{name: "new version", version: "1.2.2-1", wantDiff: "install /var/cache/p.deb (1.2.1-1 → 1.2.2-1)\n"},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newDebianSys(t)
				sys.write("/var/cache/p.deb", "")
				sys.on("dpkg-deb --field /var/cache/p.deb Version", tt.version+"\n", 0)

				change, err := Package{Name: "pam-rssh", Deb: "/var/cache/p.deb"}.Check(context.Background(), sys)

				require.NoError(t, err)
				assert.Equal(t, tt.wantDiff == "", change.InSync)
				assert.Equal(t, tt.wantDiff, change.Diff)
			},
		)
	}
}

func TestPackage_DebNotDownloadedYet(t *testing.T) {
	sys := newDebianSys(t)

	_, err := Package{Name: "pam-rssh", Deb: "/var/cache/p.deb"}.Check(context.Background(), sys)

	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestAptRepo(t *testing.T) {
	sys := newDebianSys(t)
	sys.urls["https://pkgs.example.com/key.gpg"] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n"
	sys.write("/etc/apt/sources.list.d/.keep", "")
	r := AptRepo{
		Name:          "example",
		URIs:          []string{"https://pkgs.example.com/debian"},
		Suites:        []string{"trixie"},
		Components:    []string{"main"},
		SigningKeyURL: "https://pkgs.example.com/key.gpg",
	}
	st := newRunState()

	ctx := withRunState(context.Background(), st)
	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Contains(t, change.Diff, "add signing key /etc/apt/keyrings/example.asc\n")
	require.NoError(t, r.Apply(ctx, sys))

	assert.True(t, st.aptSourcesChanged)
	assert.Equal(
		t,
		"Types: deb\nURIs: https://pkgs.example.com/debian\nSuites: trixie\nComponents: main\n"+
			"Signed-By: /etc/apt/keyrings/example.asc\n",
		sys.read("/etc/apt/sources.list.d/example.sources"),
	)
	change, err = r.Check(ctx, sys)
	require.NoError(t, err)
	assert.True(t, change.InSync)

	sys.urls["https://pkgs.example.com/key.gpg"] = "\x99binary"
	change, err = r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Contains(t, change.Diff, "add signing key /etc/apt/keyrings/example.gpg\n")
}

func TestAURPackage(t *testing.T) {
	sys := newArchSys(t)
	sys.on("paru *", "", 0)
	ctx := withRunState(context.Background(), newRunState())

	_, err := AURPackage{Name: "pam_rssh", BuildUser: "aur"}.Check(ctx, sys)
	require.ErrorIs(t, err, ErrNotYetCheckable)

	r := AURPackage{Name: "pam_rssh", BuildUser: "bob"}
	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)

	var user string
	sys.commands["paru *"] = func(cmd Cmd) Result {
		user = cmd.User
		return Result{}
	}
	require.NoError(t, r.Apply(ctx, sys))
	assert.Equal(t, "bob", user)
}

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		data, family, release string
		wantErr               bool
	}{
		{data: "ID=arch\n", family: "archlinux"},
		{data: "ID=debian\nVERSION_CODENAME=bookworm\n", family: "debian", release: "bookworm"},
		{data: "ID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=\"noble\"\n", family: "debian", release: "noble"},
		{data: "ID=endeavouros\nID_LIKE=\"arch\"\n", family: "archlinux"},
		{data: "ID=fedora\n", wantErr: true},
	}
	for _, tt := range tests {
		family, release, err := parseOSRelease(tt.data)
		if tt.wantErr {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, tt.family, family)
		assert.Equal(t, tt.release, release)
	}
}

func TestPackage_AptSourceNewerThanIndex(t *testing.T) {
	sys := newDebianSys(t)
	sys.write("/etc/apt/sources.list.d/docker.sources", "Types: deb\n")
	path := sys.path("/etc/apt/sources.list.d/docker.sources")
	require.NoError(t, os.Chtimes(path, sys.now, sys.now.Add(-5*time.Minute)))
	sys.on("apt-cache policy docker-ce", "", 0)
	sys.on("apt-get *", "", 0)
	ctx := withRunState(context.Background(), newRunState())

	change, err := Package{Name: "docker-ce"}.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "install package, after refreshing the package index\n", change.Diff)

	require.NoError(t, Package{Name: "docker-ce"}.Apply(ctx, sys))
	assert.Equal(t, "apt-get -y -q update", sys.ran[1])
}

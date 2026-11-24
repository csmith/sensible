package host

import (
	"context"
	"os"
	"strings"
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
	sys.on("pacman -Sp *", "", 0)
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
		{
			name:     "installed and unwanted",
			resource: Package{Name: "zsh", Absent: true},
			apply:    "pacman -R --noconfirm zsh",
		},
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
					sys.ran = nil
					require.NoError(t, tt.resource.Apply(ctx, sys))
					assert.Equal(t, []string{tt.apply}, sys.ran)
				}
			},
		)
	}
}

func TestPackage_PacmanNotInSyncDatabase(t *testing.T) {
	sys := newArchSys(t)
	sys.commands["pacman -Sp --noconfirm --print-format %n git"] = func(Cmd) Result {
		return Result{Stderr: "error: target not found: git\n", Code: 1}
	}
	_, err := Package{Name: "git"}.Check(withRunState(context.Background(), newRunState()), sys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pacman -Syu")
	assert.NotErrorIs(t, err, ErrNotYetCheckable)
}

func TestPackage_PacmanInstallFailures(t *testing.T) {
	tests := []struct {
		name    string
		stderr  string
		wantSyu bool
	}{
		{
			name: "stale sync database",
			stderr: "error: failed retrieving file 'git-2.0-1-x86_64.pkg.tar.zst' from mirror : " +
				"The requested URL returned error: 404\nerror: failed to commit transaction (failed to retrieve some files)\n",
			wantSyu: true,
		},
		{
			name:   "something else",
			stderr: "error: failed to commit transaction (conflicting files)\n",
		},
	}
	installs := []struct {
		name     string
		argv     string
		resource Resource
	}{
		{"package", "pacman -S --needed --noconfirm git", Package{Name: "git"}},
		{"aur package", "paru *", AURPackage{Name: "pam_rssh", BuildUser: "bob"}},
		{
			"command",
			"sh -c pacman -S docker",
			Command{Name: "docker", ApplyArgv: []string{"sh", "-c", "pacman -S docker"}},
		},
	}
	for _, tt := range tests {
		for _, install := range installs {
			t.Run(
				tt.name+"/"+install.name,
				func(t *testing.T) {
					sys := newArchSys(t)
					sys.commands[install.argv] = func(Cmd) Result {
						return Result{Stderr: tt.stderr, Code: 1}
					}
					err := install.resource.Apply(withRunState(context.Background(), newRunState()), sys)
					require.Error(t, err)
					assert.Contains(t, err.Error(), "failed to commit transaction")
					if tt.wantSyu {
						assert.Contains(t, err.Error(), "pacman -Syu")
					} else {
						assert.NotContains(t, err.Error(), "pacman -Syu")
					}
				},
			)
		}
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

const aptRelease = "/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease"

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
	sys.write(aptRelease, "")
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

	sys.on("apt-get -y -q -o DPkg::Lock::Timeout=300 remove zsh", "", 0)
	require.NoError(t, Package{Name: "zsh", Absent: true}.Apply(ctx, sys))
	assert.Equal(t, []string{"apt-get -y -q -o DPkg::Lock::Timeout=300 remove zsh"}, sys.ran)
}

const aptInstallGit = "apt-get -y -q -o DPkg::Lock::Timeout=300 install " +
	"-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold git"

func TestPackage_AptAvailability(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		indexAge time.Duration
		// emptyLists leaves the index with nothing fetched.
		emptyLists bool
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
				"apt-get -y -q -o DPkg::Lock::Timeout=300 update",
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
			name:       "unknown with a recent but empty index",
			indexAge:   10 * time.Minute,
			emptyLists: true,
			wantDiff:   "install package, after refreshing the package index\n",
			wantApply: []string{
				"apt-get -y -q -o DPkg::Lock::Timeout=300 update",
				aptInstallGit,
			},
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
				if tt.emptyLists {
					require.NoError(t, os.Remove(sys.path(aptRelease)))
				}
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

	assert.Equal(t, "apt-get -y -q -o DPkg::Lock::Timeout=300 update", sys.ran[0])
	assert.NotContains(t, sys.ran[1:], "apt-get -y -q -o DPkg::Lock::Timeout=300 update")
}

func TestPackage_AptUpdateWaitsForListsLock(t *testing.T) {
	sys := newDebianSys(t)
	sys.on(aptInstallGit, "", 0)
	updates := 0
	sys.commands["apt-get -y -q -o DPkg::Lock::Timeout=300 update"] = func(Cmd) Result {
		updates++
		if updates < 3 {
			return Result{
				Stderr: "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 10 (apt-get)\n",
				Code:   100,
			}
		}
		return Result{}
	}
	st := newRunState()
	st.aptSourcesChanged = true
	ctx := withRunState(context.Background(), st)

	require.NoError(t, Package{Name: "git"}.Apply(ctx, sys))
	assert.Equal(t, 3, updates)
}

func TestPackage_PacmanWaitsForLock(t *testing.T) {
	tests := []struct {
		name string
		lock bool
		// pacmanFor is how long another pacman runs; -1 runs it throughout.
		pacmanFor time.Duration
		wantErr   string
	}{
		{name: "unlocked"},
		{name: "locked by no running pacman", lock: true},
		{name: "locked by a pacman that finishes", lock: true, pacmanFor: time.Minute},
		{
			name:      "locked throughout",
			lock:      true,
			pacmanFor: -1,
			wantErr:   "another pacman still holds /var/lib/pacman/db.lck",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newArchSys(t)
				sys.on("pacman -S *", "", 0)
				sys.write("/proc/1/comm", "systemd\n")
				if tt.lock {
					sys.write(pacmanLock, "")
				}
				if tt.pacmanFor != 0 {
					sys.write("/proc/42/comm", "pacman\n")
				}
				start := sys.now
				sys.sleeper = func(d time.Duration) {
					sys.now = sys.now.Add(d)
					if tt.pacmanFor > 0 && sys.now.Sub(start) >= tt.pacmanFor {
						require.NoError(t, os.Remove(sys.path("/proc/42/comm")))
						require.NoError(t, os.Remove(sys.path(pacmanLock)))
					}
				}

				err := Package{Name: "git"}.Apply(withRunState(context.Background(), newRunState()), sys)
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
					assert.Empty(t, sys.ran)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, []string{"pacman -S --needed --noconfirm git"}, sys.ran)
			},
		)
	}
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

func TestAptRepo_LocalKeyring(t *testing.T) {
	sys := newDebianSys(t)
	change := checkApply(
		t,
		sys,
		AptRepo{
			Name:       "debian",
			URIs:       []string{"https://deb.debian.org/debian"},
			Suites:     []string{"trixie", "trixie-updates"},
			Components: []string{"main"},
			SigningKey: "/usr/share/keyrings/debian-archive-keyring.gpg",
		},
	)

	assert.NotContains(t, change.Diff, "signing key")
	assert.Equal(
		t,
		"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main\n"+
			"Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n",
		sys.read("/etc/apt/sources.list.d/debian.sources"),
	)
	assert.False(t, sys.exists(AptKeyringsDir))
}

func TestDisownedAptSources_SourcesList(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		sourcesList bool
		want        []string
	}{
		{
			name:        "active",
			content:     "# comment\ndeb http://deb.debian.org/debian bookworm main\n",
			sourcesList: true,
			want:        []string{AptSourcesList, AptSourcesDir + "/stray.list"},
		},
		{
			name:        "source only",
			content:     "  deb-src [arch=amd64] http://deb.debian.org/debian bookworm main\n",
			sourcesList: true,
			want:        []string{AptSourcesList, AptSourcesDir + "/stray.list"},
		},
		{
			name:        "empty",
			sourcesList: true,
			want:        []string{AptSourcesDir + "/stray.list"},
		},
		{
			name:        "comments only",
			content:     "# deb http://deb.debian.org/debian bookworm main\n\n#deb-src http://x bookworm main\n",
			sourcesList: true,
			want:        []string{AptSourcesDir + "/stray.list"},
		},
		{
			name:    "not owned",
			content: "deb http://deb.debian.org/debian bookworm main\n",
			want:    []string{AptSourcesDir + "/stray.list"},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newDebianSys(t)
				sys.write(AptSourcesList, tt.content)
				sys.write(AptSourcesDir+"/stray.list", "deb http://example.com stable main\n")
				ctx := withRunState(context.Background(), newRunState())
				r := DisownedAptSources{SourcesList: tt.sourcesList}

				leftovers, err := r.Leftovers(ctx, sys)
				require.NoError(t, err)
				assert.Equal(t, tt.want, leftovers)
				change, err := r.Check(ctx, sys)
				require.NoError(t, err)
				assert.True(t, change.InSync)
				assert.Equal(t, strings.Join(tt.want, "\n"), strings.SplitN(change.Warning, "\nno apt repo", 2)[0])

				require.NoError(t, r.Apply(ctx, sys))
				assert.True(t, sys.exists(AptSourcesList))
			},
		)
	}
}

func TestDisownedAptSources_PrunesSourcesList(t *testing.T) {
	sys := newDebianSys(t)
	sys.write(AptSourcesList, "deb http://deb.debian.org/debian bookworm main\n")
	ctx := withRunState(context.Background(), newRunState())
	r := DisownedAptSources{SourcesList: true}

	require.NoError(t, r.Prune(ctx, sys, AptSourcesList))

	assert.False(t, sys.exists(AptSourcesList))
	leftovers, err := r.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.Empty(t, leftovers)
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
		data    string
		want    Facts
		wantErr bool
	}{
		{data: "ID=arch\n", want: Facts{OSFamily: "arch", Distro: "arch"}},
		{
			data: "ID=debian\nVERSION_CODENAME=bookworm\n",
			want: Facts{OSFamily: "debian", Distro: "debian", Release: "bookworm"},
		},
		{
			data: "ID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=\"noble\"\n",
			want: Facts{OSFamily: "debian", Distro: "ubuntu", Release: "noble"},
		},
		{data: "ID=endeavouros\nID_LIKE=\"arch\"\n", want: Facts{OSFamily: "arch", Distro: "endeavouros"}},
		{data: "ID=fedora\n", wantErr: true},
	}
	for _, tt := range tests {
		facts, err := parseOSRelease(tt.data)
		if tt.wantErr {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, tt.want, facts)
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
	assert.Equal(t, "apt-get -y -q -o DPkg::Lock::Timeout=300 update", sys.ran[1])
}

func TestPackage_RecordsOnlyWhatItInstalls(t *testing.T) {
	sys := newArchSys(t)
	sys.on("pacman -S *", "", 0)
	sys.on("pacman -R *", "", 0)
	sys.on("paru *", "", 0)
	ctx := withRunState(context.Background(), newRunState())

	require.NoError(t, Package{Name: "git", Record: true}.Apply(ctx, sys))
	require.NoError(t, Package{Name: "curl"}.Apply(ctx, sys))
	require.NoError(t, Package{Name: "vim", Record: true}.Apply(ctx, sys))
	require.NoError(t, AURPackage{Name: "pam_rssh", BuildUser: "bob", Record: true}.Apply(ctx, sys))
	assert.True(t, sys.exists(packageRecordPath("git")))
	assert.False(t, sys.exists(packageRecordPath("curl")))
	assert.False(t, sys.exists(packageRecordPath("vim")), "vim was installed by hand")
	assert.True(t, sys.exists(packageRecordPath("pam_rssh")))

	require.NoError(t, Package{Name: "git", Absent: true}.Apply(ctx, sys))
	assert.False(t, sys.exists(packageRecordPath("git")))
}

func TestDisownedPackages(t *testing.T) {
	sys := newArchSys(t)
	for _, name := range []string{"vim", "zsh", "gone"} {
		sys.write(packageRecordPath(name), "")
	}
	var removed []string
	sys.commands["pacman -R *"] = func(cmd Cmd) Result {
		removed = append(removed, cmd.Argv[len(cmd.Argv)-1])
		return Result{}
	}
	st := newRunState()
	st.declare(Package{Name: "zsh"})
	ctx := withRunState(context.Background(), st)
	r := DisownedPackages{}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.False(t, change.InSync)
	assert.Equal(t, "forget record of package gone\n", change.Diff)
	assert.Contains(t, change.Warning, "package vim\nnothing declares these")

	require.NoError(t, r.Apply(ctx, sys))
	assert.False(t, sys.exists(packageRecordPath("gone")))
	assert.True(t, sys.exists(packageRecordPath("vim")))
	assert.Empty(t, removed)

	require.NoError(t, r.Prune(ctx, sys, "package vim"))
	assert.Equal(t, []string{"vim"}, removed)
	assert.False(t, sys.exists(packageRecordPath("vim")))
	assert.True(t, sys.exists(packageRecordPath("zsh")))
}

func TestDisownedPackages_NothingLeftOver(t *testing.T) {
	sys := newArchSys(t)
	st := newRunState()
	st.declare(Package{Name: "vim"})
	st.declare(Package{Name: "zsh"})
	change, err := DisownedPackages{}.Check(withRunState(context.Background(), st), sys)
	require.NoError(t, err)
	assert.Equal(t, Change{InSync: true}, change)
}

func TestDisownedPackages_ListsPackagesInstalledByHandOnPacman(t *testing.T) {
	sys := newArchSys(t)
	sys.write("/var/lib/pacman/local/htop-3.4-1/desc", "%NAME%\nhtop\n\n")
	sys.write("/var/lib/pacman/local/ncurses-6.5-1/desc", "%NAME%\nncurses\n\n%REASON%\n1\n\n")
	sys.write("/var/lib/pacman/local/cronie-1.7-1/desc", "%NAME%\ncronie\n\n%PROVIDES%\ncron\n\n")
	sys.write("/var/lib/pacman/local/tmux-3.5-1/desc", "%NAME%\ntmux\n\n")
	sys.write("/var/lib/pacman/local/paru-2.0-1/desc", "%NAME%\nparu\n\n")
	st := newRunState()
	st.declare(Package{Name: "zsh"})
	st.declare(Package{Name: "cron"})
	st.declare(AURPackage{Name: "tmux"})
	st.declare(Command{Name: "install paru", Packages: []string{"paru"}})
	st.ignored = map[string][]string{"disowned-packages": {"package vim"}}
	ctx := withRunState(context.Background(), st)
	r := DisownedPackages{}

	got, err := r.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"package htop", "package vim"}, got)

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Contains(t, change.Warning, "package htop\nnothing declares these")
}

func TestDisownedPackages_Apt(t *testing.T) {
	sys := newDebianSys(t)
	sys.write(packageRecordPath("pam-rssh"), "")
	sys.on("apt-get -y -q -o DPkg::Lock::Timeout=300 remove pam-rssh", "", 0)
	ctx := withRunState(context.Background(), newRunState())
	r := DisownedPackages{}

	got, err := r.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"package pam-rssh", "package zsh"}, got)

	require.NoError(t, r.Prune(ctx, sys, "package pam-rssh"))
	assert.False(t, sys.exists(packageRecordPath("pam-rssh")))
}

func TestDisownedPackages_ListsPackagesInstalledByHandOnApt(t *testing.T) {
	sys := newDebianSys(t)
	sys.write(
		"/var/lib/dpkg/status",
		"Package: zsh\nStatus: install ok installed\nVersion: 5.9-8\n\n"+
			"Package: htop\nStatus: install ok installed\nVersion: 3.4\n\n"+
			"Package: git\nStatus: install ok installed\nVersion: 2.47\n\n"+
			"Package: libpcre2\nStatus: install ok installed\nVersion: 10.45\n\n"+
			"Package: old\nStatus: deinstall ok config-files\nVersion: 1\n",
	)
	sys.write(
		"/var/lib/apt/extended_states",
		"Package: libpcre2\nArchitecture: amd64\nAuto-Installed: 1\n\n"+
			"Package: git\nArchitecture: amd64\nAuto-Installed: 0\n",
	)
	st := newRunState()
	st.declare(Package{Name: "zsh"})
	st.ignored = map[string][]string{"disowned-packages": {"package git"}}
	ctx := withRunState(context.Background(), st)

	got, err := DisownedPackages{}.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"package git", "package htop"}, got)

	change, err := DisownedPackages{}.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(
		t,
		"package htop\nnothing declares these; run `sensible prune` to remove them once they're not needed\n",
		change.Warning,
	)
}

func TestDisownedPackages_LeavesOutDebianBaseSystem(t *testing.T) {
	sys := newDebianSys(t)
	sys.write(
		"/var/lib/dpkg/status",
		"Package: zsh\nStatus: install ok installed\nVersion: 5.9-8\n\n"+
			"Package: bash\nStatus: install ok installed\nEssential: yes\nVersion: 5.2\n\n"+
			"Package: libc6\nStatus: install ok installed\nPriority: required\nVersion: 2.41\n\n"+
			"Package: apt\nStatus: install ok installed\nPriority: important\nVersion: 3.0\n\n"+
			"Package: less\nStatus: install ok installed\nPriority: standard\nVersion: 668\n\n"+
			"Package: htop\nStatus: install ok installed\nPriority: optional\nVersion: 3.4\n",
	)
	st := newRunState()
	st.declare(Package{Name: "zsh"})

	got, err := DisownedPackages{}.Leftovers(withRunState(context.Background(), st), sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"package htop", "package less"}, got)
}

// withKernels scripts the running kernel and installs modules for each of
// installed.
func withKernels(sys *testSys, running string, installed ...string) {
	sys.on("uname -r", running+"\n", 0)
	for _, k := range installed {
		sys.write("/lib/modules/"+k+"/kernel/.keep", "")
	}
}

// applyAll applies list in one run, returning its results and whether any
// failed.
func applyAll(t *testing.T, sys Sys, list ResourceList) ([]Applied, bool) {
	t.Helper()
	e := newTestEngine(t)
	e.sys = sys
	var applied []Applied
	failed, err := e.apply(
		context.Background(),
		list,
		-1,
		func(msg any) error {
			if a, ok := msg.(Applied); ok {
				applied = append(applied, a)
			}
			return nil
		},
	)
	require.NoError(t, err)
	return applied, failed
}

func TestPackageUpdate_ArchUpgradesBeforeOtherResources(t *testing.T) {
	sys := newArchSys(t)
	withKernels(sys, "6.17.7-arch1-1", "6.17.7-arch1-1")
	sys.on("pacman -Syu --noconfirm", "", 0)
	sys.on("pacman -S --needed --noconfirm git", "", 0)

	_, failed := applyAll(t, sys, ResourceList{PackageUpdate{}, Package{Name: "git"}})

	assert.False(t, failed)
	assert.Equal(
		t,
		[]string{
			"pacman -Syu --noconfirm",
			"uname -r",
			"pacman -Sp --noconfirm --print-format %n git",
			"pacman -S --needed --noconfirm git",
		},
		sys.ran,
	)
}

func TestPackageUpdate_DebianUpgradesBeforeOtherResources(t *testing.T) {
	sys := newDebianSys(t)
	// An index this old would otherwise be refreshed before installing.
	require.NoError(t, os.Chtimes(sys.path("/var/lib/apt/lists"), sys.now, sys.now.Add(-2*time.Hour)))
	withKernels(sys, "6.12.48+deb13-amd64", "6.12.48+deb13-amd64")
	sys.on("apt-get -y -q -o DPkg::Lock::Timeout=300 update", "", 0)
	sys.on("apt-get -y -q -o DPkg::Lock::Timeout=300 full-upgrade *", "", 0)
	sys.on("apt-cache policy git", "  Candidate: 1:2.47-1\n", 0)
	sys.on("apt-get -y -q -o DPkg::Lock::Timeout=300 install *", "", 0)

	_, failed := applyAll(t, sys, ResourceList{PackageUpdate{}, Package{Name: "git"}})

	assert.False(t, failed)
	assert.Equal(
		t,
		[]string{
			"apt-get -y -q -o DPkg::Lock::Timeout=300 update",
			"apt-get -y -q -o DPkg::Lock::Timeout=300 full-upgrade " +
				"-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold",
			"uname -r",
			"apt-cache policy git",
			aptInstallGit,
		},
		sys.ran,
	)
}

func TestPackageUpdate_DefersPackagesMissingFromTheSyncDatabase(t *testing.T) {
	sys := newArchSys(t)
	sys.commands["pacman -Sp --noconfirm --print-format %n strace"] = func(Cmd) Result {
		return Result{Stderr: "error: target not found: strace\n", Code: 1}
	}

	e := newTestEngine(t)
	e.sys = sys
	var checked []Status
	failedAt, err := e.check(
		context.Background(),
		ResourceList{PackageUpdate{}, Package{Name: "strace"}},
		func(c Checked) error {
			checked = append(checked, c.Status)
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, -1, failedAt)
	assert.Equal(t, []Status{StatusDrifted, StatusDeferred}, checked)
}

func TestPackageUpdate_WarnsWhenTheHostNeedsAReboot(t *testing.T) {
	tests := []struct {
		name      string
		running   string
		installed []string
		want      string
	}{
		{
			name:      "running the newest",
			running:   "6.1.0-20-amd64",
			installed: []string{"6.1.0-18-amd64", "6.1.0-20-amd64"},
		},
		{
			name:      "newer kernel installed",
			running:   "6.1.0-9-amd64",
			installed: []string{"6.1.0-9-amd64", "6.1.0-20-amd64"},
			want:      "6.1.0-20-amd64, instead of 6.1.0-9-amd64",
		},
		{
			name:      "newer kernel only of another flavour",
			running:   "6.12.47+rpt-rpi-v8",
			installed: []string{"6.12.47+rpt-rpi-v8", "6.12.62+rpt-rpi-2712"},
		},
		{
			name:      "running kernel removed",
			running:   "6.17.7-arch1-1",
			installed: []string{"6.12.57-1-lts"},
			want:      "6.17.7-arch1-1, is no longer installed",
		},
		{
			name:    "no kernels, as in a container",
			running: "6.17.7-arch1-1",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newArchSys(t)
				withKernels(sys, tt.running, tt.installed...)
				sys.on("pacman -Syu --noconfirm", "", 0)

				applied, failed := applyAll(t, sys, ResourceList{PackageUpdate{}})

				require.False(t, failed)
				require.Len(t, applied, 1)
				if tt.want == "" {
					assert.Empty(t, applied[0].Warning)
				} else {
					assert.Contains(t, applied[0].Warning, tt.want)
				}
			},
		)
	}
}

func TestPackageUpdate_FailedUpgradeDoesNotCheckTheKernel(t *testing.T) {
	sys := newArchSys(t)
	sys.on("pacman -Syu --noconfirm", "", 1)

	applied, failed := applyAll(t, sys, ResourceList{PackageUpdate{}})

	assert.True(t, failed)
	assert.Empty(t, applied[0].Warning)
	assert.NotContains(t, sys.ran, "uname -r")
}

func TestDisownedPackages_LeavesOutWhatPacmanPackagesDependOn(t *testing.T) {
	sys := newArchSys(t)
	sys.write("/var/lib/pacman/local/htop-3.4-1/desc", "%NAME%\nhtop\n\n%DEPENDS%\nncurses>=6\nlibnl\n\n")
	sys.write("/var/lib/pacman/local/ncurses-6.5-1/desc", "%NAME%\nncurses\n\n")
	sys.write("/var/lib/pacman/local/libnl-ng-3.11-1/desc", "%NAME%\nlibnl-ng\n\n%PROVIDES%\nlibnl=3.11\n\n")
	sys.write(
		"/var/lib/pacman/local/lsof-4.99-1/desc",
		"%NAME%\nlsof\n\n%OPTDEPENDS%\nperl: for sample scripts\n\n%REASON%\n1\n\n",
	)
	sys.write("/var/lib/pacman/local/perl-5.40-1/desc", "%NAME%\nperl\n\n")
	st := newRunState()
	st.declare(Package{Name: "vim"})
	st.declare(Package{Name: "zsh"})

	got, err := DisownedPackages{}.Leftovers(withRunState(context.Background(), st), sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"package htop", "package perl"}, got)
}

func TestDisownedPackages_LeavesOutWhatAptPackagesDependOn(t *testing.T) {
	sys := newDebianSys(t)
	sys.write(
		"/var/lib/dpkg/status",
		"Package: htop\nStatus: install ok installed\nVersion: 3.4\n"+
			"Depends: libc6 (>= 2.34), libncursesw6:any (>= 6), python3 | perl\n\n"+
			"Package: libncursesw6\nStatus: install ok installed\nVersion: 6.5\n\n"+
			"Package: perl\nStatus: install ok installed\nVersion: 5.40\n\n"+
			"Package: mawk\nStatus: install ok installed\nVersion: 1.3\nProvides: awk\n\n"+
			"Package: dash\nStatus: install ok installed\nVersion: 0.5\nPre-Depends: awk\n\n"+
			"Package: zlib1g\nStatus: install ok installed\nVersion: 1.3\n\n"+
			"Package: old\nStatus: deinstall ok config-files\nVersion: 1\nDepends: zlib1g\n",
	)
	st := newRunState()
	st.declare(Package{Name: "dash"})

	got, err := DisownedPackages{}.Leftovers(withRunState(context.Background(), st), sys)
	require.NoError(t, err)
	assert.Equal(t, []string{"package htop", "package zlib1g"}, got)
}

// pacmanRepoSys is an Arch host whose pacman-key and gpg keep a keyring of
// key IDs, and whose pacman -Sy fetches the sync database of the repo on
// stdin.
func pacmanRepoSys(t *testing.T) (*testSys, map[string]bool) {
	t.Helper()
	sys := newArchSys(t)
	sys.write(PacmanConf, "[options]\nArchitecture = auto\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n")
	sys.urls["https://git.example.com/repository.key"] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n"
	trusted := map[string]bool{}
	sys.on("pacman-key --init", "", 0)
	sys.on("pacman-key --add *", "", 0)
	sys.commands["pacman-key --lsign-key chris@noreply.git.example.com"] = func(Cmd) Result {
		trusted["chris@noreply.git.example.com"] = true
		return Result{}
	}
	sys.commands["gpg --homedir /etc/pacman.d/gnupg --no-permission-warning --batch --with-colons --list-keys *"] =
		func(c Cmd) Result {
			if trusted[c.Argv[len(c.Argv)-1]] {
				return Result{Stdout: "tru::1:1:0:3:1:5\npub:f:255:22:ABCD:1:::-:::scSC::::::23::0:\n"}
			}
			return Result{Code: 2}
		}
	sys.commands["pacman --config /dev/stdin --arch auto -Sy --noconfirm"] = func(c Cmd) Result {
		sys.write(pacmanSyncDir+"/"+strings.Trim(strings.SplitN(c.Stdin, "\n", 2)[0], "[]")+".db", "db")
		return Result{}
	}
	return sys, trusted
}

func TestPacmanRepo(t *testing.T) {
	sys, trusted := pacmanRepoSys(t)
	r := PacmanRepo{
		Name:          "chris.forgejo.git.example.com",
		Servers:       []string{"https://git.example.com/api/packages/chris/arch/forgejo/$arch"},
		SigLevel:      "Required",
		SigningKeyURL: "https://git.example.com/repository.key",
		SigningKeyID:  "chris@noreply.git.example.com",
	}

	change := checkApply(t, sys, r)

	assert.Contains(t, change.Diff, "add signing key "+PacmanReposDir+"/chris.forgejo.git.example.com.key\n")
	assert.Contains(t, change.Diff, "refresh chris.forgejo.git.example.com's sync database\n")
	assert.True(t, trusted["chris@noreply.git.example.com"])
	assert.Equal(
		t,
		"[chris.forgejo.git.example.com]\nSigLevel = Required\n"+
			"Server = https://git.example.com/api/packages/chris/arch/forgejo/$arch\n",
		sys.read(PacmanReposDir+"/chris.forgejo.git.example.com.conf"),
	)
	assert.True(
		t,
		strings.HasSuffix(
			sys.read(PacmanConf),
			"[core]\nInclude = /etc/pacman.d/mirrorlist\nInclude = "+PacmanReposDir+"/chris.forgejo.git.example.com.conf\n",
		),
	)

	// An unchanged key isn't imported again, but one pacman stopped
	// trusting is.
	sys.ran = nil
	change = checkApply(t, sys, PacmanRepo{Name: "other", Servers: r.Servers, SigLevel: "Never"})
	assert.NotContains(t, strings.Join(sys.ran, "\n"), "pacman-key")
	assert.NotContains(t, change.Diff, "signing key")
	delete(trusted, "chris@noreply.git.example.com")
	change = checkApply(t, sys, r)
	assert.Equal(t, "trust signing key chris@noreply.git.example.com\n", change.Diff)
}

func TestPacmanRepo_RefreshFails(t *testing.T) {
	sys, _ := pacmanRepoSys(t)
	sys.on("pacman --config /dev/stdin --arch auto -Sy --noconfirm", "", 1)
	r := PacmanRepo{Name: "example", Servers: []string{"https://example.com/$arch"}, SigLevel: "Never"}
	ctx := withRunState(context.Background(), newRunState())

	require.Error(t, r.Apply(ctx, sys))

	// pacman isn't pointed at a repo whose database it hasn't got.
	assert.False(t, sys.exists(PacmanReposDir+"/example.conf"))
	assert.NotContains(t, sys.read(PacmanConf), "example")
}

func TestPackage_PacmanAfterNewRepo(t *testing.T) {
	sys := newArchSys(t)
	sys.commands["pacman -Sp *"] = func(Cmd) Result {
		return Result{Stderr: "error: target not found: widget", Code: 1}
	}
	st := newRunState()
	st.modified[PacmanRepo{Name: "example"}.ID()] = true

	_, err := Package{Name: "widget"}.Check(withRunState(context.Background(), st), sys)

	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestDisownedPacmanRepos(t *testing.T) {
	sys, _ := pacmanRepoSys(t)
	declared := PacmanRepo{
		Name:          "kept",
		Servers:       []string{"https://git.example.com/kept/$arch"},
		SigLevel:      "Required",
		SigningKeyURL: "https://git.example.com/repository.key",
		SigningKeyID:  "chris@noreply.git.example.com",
	}
	removed := declared
	removed.Name = "removed"
	for _, r := range []PacmanRepo{declared, removed} {
		checkApply(t, sys, r)
	}
	sys.write(PacmanReposDir+"/lone.key", "other key")
	// Kept and removed share a key, which lone doesn't.
	sys.commands["gpg --homedir /etc/pacman.d/gnupg --no-permission-warning --batch --with-colons --show-keys *"] =
		func(c Cmd) Result {
			fpr := "SHARED"
			if strings.HasSuffix(c.Argv[len(c.Argv)-1], "/lone.key") {
				fpr = "LONE"
			}
			return Result{
				Stdout: "pub:-:255:22:X:1:::-:::scSC:::\nfpr:::::::::" + fpr + ":\n" +
					"sub:-:255:18:Y:1::::::e:::\nfpr:::::::::SUB:\n",
			}
		}
	sys.on(
		"gpg --homedir /etc/pacman.d/gnupg --no-permission-warning --batch --with-colons --list-keys LONE",
		"pub:f:\n",
		0,
	)
	sys.on("pacman-key --delete *", "", 0)

	st := newRunState()
	st.declare(declared)
	ctx := withRunState(context.Background(), st)
	r := DisownedPacmanRepos{}
	leftovers, err := r.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{PacmanReposDir + "/lone.key", PacmanReposDir + "/removed.conf", PacmanReposDir + "/removed.key"},
		leftovers,
	)

	sys.ran = nil
	for _, item := range leftovers {
		require.NoError(t, r.Prune(ctx, sys, item))
	}

	assert.Contains(t, sys.ran, "pacman-key --delete LONE")
	assert.NotContains(t, strings.Join(sys.ran, "\n"), "pacman-key --delete SHARED")
	assert.False(t, sys.exists(pacmanSyncDir+"/removed.db"))
	assert.True(t, sys.exists(pacmanSyncDir+"/kept.db"))
	assert.NotContains(t, sys.read(PacmanConf), "removed.conf")
	assert.Contains(t, sys.read(PacmanConf), "kept.conf")
	leftovers, err = r.Leftovers(ctx, sys)
	require.NoError(t, err)
	assert.Empty(t, leftovers)
}

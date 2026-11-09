package features

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

func testHost(osFamily string) Host {
	return Host{
		Name: "testhost",
		Config: config.Config{
			Packages: &config.PackagesConfig{Install: []string{"htop"}, Remove: []string{"nano"}},
			AUR:      &config.AURConfig{Packages: []string{"widget-bin"}},
			Users:    map[string]config.UserConfig{"alice": {Groups: []string{"wheel"}}, "bob": {}},
			Sudoers:  map[string]config.Set{"000-alice": {"alice ALL=(ALL:ALL) ALL"}},
			PamRSSH:  &config.PamRSSHConfig{Keys: []string{"ssh-ed25519 AAAA sudo"}},
			SSHD: &config.SSHDConfig{
				Settings: map[string]string{"MaxAuthTries": "3"},
				AuthorizedKeys: map[string]config.Set{
					"alice": {"ssh-ed25519 AAAA alice"},
					"bob":   {"ssh-ed25519 AAAA bob"},
				},
			},
			Tailscale: &config.TailscaleConfig{Settings: map[string]string{"advertise-exit-node": "true"}},
			Zsh: &config.ZshConfig{
				Users:         []string{"alice"},
				Plugins:       []string{"git"},
				PromptColours: map[string]string{"alice": "blue"},
			},
			Docker: &config.DockerConfig{
				Users:    []string{"alice"},
				Networks: map[string]config.DockerNetworkConfig{"web": {}},
			},
			Vim:        &config.VimConfig{},
			QuietLogin: &config.QuietLoginConfig{},
			Hostname:   &config.HostnameConfig{},
			Timezone:   &config.TimezoneConfig{Zone: "Europe/London"},
			Locale:     &config.LocaleConfig{Lang: "en_GB.UTF-8", Generate: []string{"en_US.UTF-8"}},
			NTP:        &config.NTPConfig{Servers: []string{"ntp.example.com"}},
			Stacks:     []config.Stack{{Name: "web", Files: []config.StackFile{{Path: "docker-compose.yml"}}}},
			Jobs:       map[string]config.JobConfig{"prune": {Command: []string{"docker", "image", "prune"}, Schedule: "daily"}},
		},
		Facts: host.Facts{
			OSFamily: osFamily,
			Distro:   osFamily,
			Release:  "trixie",
			Arch:     "x86_64",
		},
		SensibleKey: "ssh-ed25519 AAAA sensible@testhost",
	}
}

func ids(rs host.ResourceList) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID()
	}
	return out
}

func find[T host.Resource](rs host.ResourceList, id string) (T, bool) {
	for _, r := range rs {
		if t, ok := r.(T); ok && r.ID() == id {
			return t, true
		}
	}
	var zero T
	return zero, false
}

func TestResources_order(t *testing.T) {
	tests := []struct {
		osFamily string
		want     []string
	}{
		{
			osFamily: archLinux,
			want: []string{
				"package:nano",
				"package:htop",
				"aur:widget-bin",
				"file:/etc/hostname",
				"symlink:/etc/localtime",
				"file:/etc/locale.gen",
				"command:generate locales",
				"file:/etc/locale.conf",
				"file:" + timesyncdConfDir + "/sensible.conf",
				"owned-dir:" + timesyncdConfDir,
				"service:systemd-timesyncd",
				"symlink:/usr/local/bin/vi",
				"user:alice",
				"package:zsh",
				"user:alice",
				"file:/home/alice/.zshrc",
				"file:/etc/sudoers.d/000-alice",
				"aur:pam_rssh",
				"file:/etc/sudoers.keys",
				"comment-out:/etc/pam.d/*:" + `^\s*session\s+.*pam_(motd|lastlog2?)\.so`,
				"file:/etc/ssh/sshd_config.d/10-sensible.conf",
				"file:/home/alice/.ssh/authorized_keys",
				"user:" + SensibleUser,
				"file:/etc/sudoers.d/" + SensibleUser,
				"service:tailscaled",
				"file:/etc/sysctl.d/99-tailscale.conf",
				"tailscale-set",
				"package:docker",
				"docker-network:web",
				"compose:/srv/compose/web",
				"compose-projects:/srv/compose",
				"docker-networks",
				"file:/etc/systemd/system/sensible-prune.service",
				"file:/etc/systemd/system/sensible-prune.timer",
				"systemd-reload",
				"service:sensible-prune.timer",
				"systemd-units:sensible-",
				"users",
				"owned-dir:/etc/sudoers.d",
				"disowned:sshd",
				"disowned:vim",
			},
		},
		{
			osFamily: debian,
			want: []string{
				"apt-repo:raspi",
				"package:nano",
				"package:htop",
				"line:/etc/hosts:" + `^127\.0\.1\.1\s`,
				"file:/etc/timezone",
				"package:locales",
				"file:/etc/default/locale",
				"package:systemd-timesyncd",
				"service:systemd-timesyncd",
				"package:vim",
				"user:alice",
				"file:/home/alice/.zshrc",
				"file:/etc/sudoers.d/000-alice",
				"package:pam-rssh",
				"file:/etc/ssh/sshd_config.d/10-sensible.conf",
				"file:/etc/sudoers.d/" + SensibleUser,
				"apt-repo:tailscale",
				"tailscale-set",
				"apt-repo:docker",
				"package:docker-ce",
				"docker-network:web",
				"compose:/srv/compose/web",
				"compose-projects:/srv/compose",
				"docker-networks",
				"file:/etc/systemd/system/sensible-prune.service",
				"file:/etc/systemd/system/sensible-prune.timer",
				"systemd-reload",
				"service:sensible-prune.timer",
				"systemd-units:sensible-",
				"users",
				"owned-dir:/etc/sudoers.d",
				"disowned:sshd",
				"disowned:pam_rssh package",
				"disowned-apt-sources",
			},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.osFamily,
			func(t *testing.T) {
				h := testHost(tt.osFamily)
				if tt.osFamily == debian {
					h.Config.AUR.Packages = nil
					h.Config.AptRepos = map[string]config.AptRepoConfig{"raspi": testAptRepo}
				}
				rs, err := Resources(h)
				require.NoError(t, err)
				got := ids(rs)
				last := -1
				for _, id := range tt.want {
					i := indexAfter(got, id, last)
					require.Greater(t, i, last, "%s should follow the previous resource", id)
					last = i
				}
				assert.Equal(t, tt.want[len(tt.want)-1], got[len(got)-1])
			},
		)
	}
}

var testAptRepo = config.AptRepoConfig{
	URIs:          []string{"http://archive.raspberrypi.com/debian/"},
	Suites:        []string{"trixie"},
	Components:    []string{"main"},
	SigningKeyURL: "https://archive.raspberrypi.com/debian/raspberrypi.gpg.key",
}

func indexAfter(ids []string, id string, after int) int {
	for i := after + 1; i < len(ids); i++ {
		if ids[i] == id {
			return i
		}
	}
	return -1
}

func TestAptRepos_placeholders(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR.Packages = nil
	h.Config.PamRSSH = nil
	h.Facts.Distro = "ubuntu"
	h.Facts.Release = "noble"
	h.Config.AptRepos = map[string]config.AptRepoConfig{
		"example": {
			URIs:          []string{"https://pkgs.example.com/{distro}"},
			Suites:        []string{"{release}", "{release}-updates"},
			Components:    []string{"main"},
			SigningKeyURL: "https://pkgs.example.com/{distro}/{release}.gpg",
		},
	}

	rs, err := Resources(h)
	require.NoError(t, err)
	repo, ok := find[host.AptRepo](rs, "apt-repo:example")
	require.True(t, ok)
	assert.Equal(t, []string{"https://pkgs.example.com/ubuntu"}, repo.URIs)
	assert.Equal(t, []string{"noble", "noble-updates"}, repo.Suites)
	assert.Equal(t, "https://pkgs.example.com/ubuntu/noble.gpg", repo.SigningKeyURL)
}

func TestVendorRepos_ubuntu(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR.Packages = nil
	h.Config.PamRSSH = nil
	h.Facts.Distro = "ubuntu"
	h.Facts.Release = "noble"

	rs, err := Resources(h)
	require.NoError(t, err)
	docker, ok := find[host.AptRepo](rs, "apt-repo:docker")
	require.True(t, ok)
	assert.Equal(t, []string{"https://download.docker.com/linux/ubuntu"}, docker.URIs)
	assert.Equal(t, "https://download.docker.com/linux/ubuntu/gpg", docker.SigningKeyURL)
	tailscale, ok := find[host.AptRepo](rs, "apt-repo:tailscale")
	require.True(t, ok)
	assert.Equal(t, []string{"https://pkgs.tailscale.com/stable/ubuntu"}, tailscale.URIs)
	assert.Equal(t, "https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg", tailscale.SigningKeyURL)
}

func TestResources_errors(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Host)
	}{
		{"unsupported OS", func(h *Host) { h.Facts.OSFamily = "redhat" }},
		{"Debian without release", func(h *Host) { h.Facts.Release = "" }},
		{"Docker on a Debian derivative", func(h *Host) {
			h.Config.AUR.Packages = nil
			h.Config.Tailscale = nil
			h.Facts.Distro = "linuxmint"
		}},
		{"Tailscale on a Debian derivative", func(h *Host) {
			h.Config.AUR.Packages = nil
			h.Config.Docker = nil
			h.Config.Stacks = nil
			h.Facts.Distro = "linuxmint"
		}},
		{"AUR on Debian", func(h *Host) {}},
		{"invalid hostname", func(h *Host) { h.Config.Hostname.Name = "bad_name" }},
		{"unknown timezone", func(h *Host) { h.Config.Timezone.Zone = "Europe/Nowhere" }},
		{"local timezone", func(h *Host) { h.Config.Timezone.Zone = "Local" }},
		{"locale without lang", func(h *Host) { h.Config.Locale.Lang = "" }},
		{"locale without charset", func(h *Host) { h.Config.Locale.Generate = []string{"en_US"} }},
		{"invalid job name", func(h *Host) { h.Config.Jobs["Prune"] = h.Config.Jobs["prune"] }},
		{"job without a command", func(h *Host) { h.Config.Jobs["prune"] = config.JobConfig{Schedule: "daily"} }},
		{"job without a schedule", func(h *Host) { h.Config.Jobs["prune"] = config.JobConfig{Command: []string{"true"}} }},
		{"apt repos on Arch", func(h *Host) {
			h.Facts.OSFamily = archLinux
			h.Config.AptRepos = map[string]config.AptRepoConfig{"raspi": testAptRepo}
		}},
		{"invalid apt repo name", func(h *Host) {
			h.Config.AUR.Packages = nil
			h.Config.AptRepos = map[string]config.AptRepoConfig{"../raspi": testAptRepo}
		}},
		{"apt repo without a signing key", func(h *Host) {
			h.Config.AUR.Packages = nil
			repo := testAptRepo
			repo.SigningKeyURL = ""
			h.Config.AptRepos = map[string]config.AptRepoConfig{"raspi": repo}
		}},
		{"apt repo clashing with docker's", func(h *Host) {
			h.Config.AUR.Packages = nil
			h.Config.AptRepos = map[string]config.AptRepoConfig{"docker": testAptRepo}
		}},
		{"pam_rssh without a release", func(h *Host) {
			h.Config.AUR.Packages = nil
			h.Facts.Release = "buster"
		}},
		{"pam_rssh on a Debian derivative", func(h *Host) {
			h.Config.AUR.Packages, h.Config.Docker, h.Config.Tailscale = nil, nil, nil
			h.Facts.Distro = "linuxmint"
		}},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				h := testHost(debian)
				tt.modify(&h)
				_, err := Resources(h)
				assert.Error(t, err)
			},
		)
	}
}

func TestResources_featuresTurnOff(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Host)
		absent  []string
		present []string
	}{
		{
			name:    "no AUR packages",
			modify:  func(h *Host) { h.Config.AUR.Packages = nil },
			absent:  []string{"aur:widget-bin"},
			present: []string{"aur:pam_rssh", "user:" + aurUser},
		},
		{
			name:   "no AUR packages or pam_rssh keys",
			modify: func(h *Host) { h.Config.AUR.Packages, h.Config.PamRSSH.Keys = nil, nil },
			absent: []string{"user:" + aurUser, "file:/etc/sudoers.d/" + aurUser, "file:/etc/sudoers.keys"},
		},
		{
			name:    "no sshd",
			modify:  func(h *Host) { h.Config.SSHD = nil },
			absent:  []string{"file:/home/alice/.ssh/authorized_keys", "file:/etc/ssh/sshd_config.d/10-sensible.conf"},
			present: []string{"user:alice", "file:/etc/ssh/sshd_config.d/05-sensible.conf"},
		},
		{
			name:    "no docker",
			modify:  func(h *Host) { h.Config.Docker = nil },
			absent:  []string{"package:docker", "command:start docker", "docker-network:web"},
			present: []string{"docker-networks"},
		},
		{
			name:    "no stacks",
			modify:  func(h *Host) { h.Config.Stacks = nil },
			absent:  []string{"dir:/srv/compose", "dir:/srv/volumes"},
			present: []string{"compose-projects:/srv/compose", "volumes:/srv/volumes"},
		},
		{
			name:   "no tailscale",
			modify: func(h *Host) { h.Config.Tailscale = nil },
			absent: []string{"package:tailscale", "tailscale-set"},
		},
		{
			name:   "no zsh",
			modify: func(h *Host) { h.Config.Zsh = nil },
			absent: []string{"git:" + ohMyZshPath, "package:zsh"},
		},
		{
			name:   "no vim",
			modify: func(h *Host) { h.Config.Vim = nil },
			absent: []string{"package:vim", "symlink:/usr/local/bin/vi"},
		},
		{
			name: "no system settings",
			modify: func(h *Host) {
				h.Config.Hostname, h.Config.Timezone, h.Config.Locale, h.Config.NTP = nil, nil, nil, nil
			},
			absent: []string{
				"file:/etc/hostname",
				"symlink:/etc/localtime",
				"file:/etc/locale.gen",
				"service:systemd-timesyncd",
				"owned-dir:" + timesyncdConfDir,
			},
		},
		{
			name:    "no NTP servers",
			modify:  func(h *Host) { h.Config.NTP.Servers = nil },
			absent:  []string{"file:" + timesyncdConfDir + "/sensible.conf", "dir:" + timesyncdConfDir},
			present: []string{"owned-dir:" + timesyncdConfDir, "service:systemd-timesyncd"},
		},
		{
			name:   "no packages, AUR or pam_rssh",
			modify: func(h *Host) { h.Config.Packages, h.Config.AUR, h.Config.PamRSSH = nil, nil, nil },
			absent: []string{"package:htop", "package:nano", "user:" + aurUser},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				h := testHost(archLinux)
				tt.modify(&h)
				rs, err := Resources(h)
				require.NoError(t, err)
				got := ids(rs)
				for _, id := range tt.absent {
					assert.NotContains(t, got, id)
				}
				for _, id := range tt.present {
					assert.Contains(t, got, id)
				}
			},
		)
	}
}

func TestResources_stack(t *testing.T) {
	h := testHost(archLinux)
	perms := config.Perms{Owner: "root", Group: "docker", Mode: 0o640}
	h.Config.Stacks = []config.Stack{
		{
			Name: "twowords-centralpark",
			Files: []config.StackFile{
				{Path: "docker-compose.yml", Content: "services: {}\n", Perms: perms, Secrets: []string{"pw"}},
				{Path: ".env", Content: "A=b\n", Perms: perms, Hidden: true},
				{Path: "conf/sub/site.conf", Content: "s\n", Perms: config.Perms{Owner: "1000", Mode: 0o644}},
				{Path: "conf/other.conf", Content: "o\n", Perms: perms},
			},
			Dirs: map[string]config.Perms{"conf/sub": {Owner: "1000", Mode: 0o755}},
		},
	}
	h.Config.Volumes = []config.Volume{
		{Path: "/srv/volumes/twowords/blobs", Owner: "33"},
		{Path: "/srv/volumes/twowords-centralpark/database", Owner: "postgres", Group: "postgres", Mode: 0o700},
		{Path: "/srv/volumes/twowords-centralpark/uploads", Owner: "33", Mode: 0o750},
	}
	rs, err := Resources(h)
	require.NoError(t, err)

	dir := "/srv/compose/twowords-centralpark"
	compose, ok := find[host.ComposeStack](rs, "compose:"+dir)
	require.True(t, ok)
	assert.Equal(
		t,
		host.ComposeStack{
			Dir: dir,
			Watch: []string{
				"file:" + dir + "/docker-compose.yml",
				"file:" + dir + "/.env",
				"file:" + dir + "/conf/sub/site.conf",
				"file:" + dir + "/conf/other.conf",
				"owned-dir:" + dir,
			},
		},
		compose,
	)

	got := ids(rs)
	stack := []host.Resource(rs[slices.Index(got, "dir:/srv/volumes") : slices.Index(got, "docker-networks")+1])
	assert.Equal(
		t,
		[]host.Resource{
			host.Dir{Path: "/srv/volumes", Owner: "root", Group: "root", Mode: 0o700},
			host.Dir{Path: "/srv/volumes/twowords", Owner: "root", Group: "root", Mode: 0o755},
			host.Dir{Path: "/srv/volumes/twowords/blobs", Owner: "33"},
			host.Dir{Path: "/srv/volumes/twowords-centralpark", Owner: "root", Group: "root", Mode: 0o755},
			host.Dir{Path: "/srv/volumes/twowords-centralpark/database", Owner: "postgres", Group: "postgres", Mode: 0o700},
			host.Dir{Path: "/srv/volumes/twowords-centralpark/uploads", Owner: "33", Mode: 0o750},
			host.Dir{Path: "/srv/compose", Owner: "root", Group: "docker", Mode: 0o750},
			host.Dir{Path: dir, Owner: "root", Group: "docker", Mode: 0o750},
			host.File{
				Path:    dir + "/docker-compose.yml",
				Content: "services: {}\n",
				Owner:   "root",
				Group:   "docker",
				Mode:    0o640,
				Secrets: []string{"pw"},
			},
			host.File{Path: dir + "/.env", Content: "A=b\n", Owner: "root", Group: "docker", Mode: 0o640, Hidden: true},
			host.Dir{Path: dir + "/conf", Owner: "root", Group: "docker", Mode: 0o750},
			host.Dir{Path: dir + "/conf/sub", Owner: "1000", Mode: 0o755},
			host.File{Path: dir + "/conf/sub/site.conf", Content: "s\n", Owner: "1000", Mode: 0o644},
			host.File{Path: dir + "/conf/other.conf", Content: "o\n", Owner: "root", Group: "docker", Mode: 0o640},
			host.OwnedDir{Path: dir, Recursive: true},
			compose,
			host.ComposeProjects{Path: "/srv/compose"},
			host.DockerNetworks{},
		},
		stack,
	)
}

func TestResources_stackMigrations(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Stacks = []config.Stack{
		{
			Name:  "web",
			Files: []config.StackFile{{Path: "docker-compose.yml", Content: "services: {}\n"}},
			Migrations: []config.Migration{
				{Name: "a", On: "x", Before: config.Command{"dump"}},
				{Name: "b", On: "pw", Secret: true, After: config.Command{"alter"}},
			},
		},
	}
	rs, err := Resources(h)
	require.NoError(t, err)

	got := ids(rs)
	assert.Equal(
		t,
		[]string{
			"migration-before:web/a",
			"migration-before:web/b",
			"dir:/srv/compose/web",
			"file:/srv/compose/web/docker-compose.yml",
			"owned-dir:/srv/compose/web",
			"compose:/srv/compose/web",
			"migration-after:web/a",
			"migration-after:web/b",
		},
		got[slices.Index(got, "migration-before:web/a"):slices.Index(got, "migration-after:web/b")+1],
	)
	assert.Equal(t, "migrations", got[slices.Index(got, "docker-networks")+1], "records are cleaned up after the stacks")
	b, ok := find[host.Migration](rs, "migration-after:web/b")
	require.True(t, ok)
	assert.Equal(
		t,
		host.Migration{
			Stack:  "/srv/compose/web",
			Name:   "b",
			Phase:  "after",
			On:     "pw",
			Secret: true,
			After:  []string{"alter"},
		},
		b,
	)
}

func TestResources_dockerNetworks(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Docker.Networks = map[string]config.DockerNetworkConfig{
		"web": {},
		"six": {Subnets: []string{"fd00:dead:beef::/48", "10.1.0.0/16"}, IPv6: true},
	}
	rs, err := Resources(h)
	require.NoError(t, err)

	six, ok := find[host.DockerNetwork](rs, "docker-network:six")
	require.True(t, ok)
	assert.Equal(
		t,
		host.DockerNetwork{Name: "six", Subnets: []string{"fd00:dead:beef::/48", "10.1.0.0/16"}, IPv6: true},
		six,
	)
	got := ids(rs)
	assert.Less(t, indexAfter(got, "docker-network:six", -1), indexAfter(got, "docker-network:web", -1))

	for subnets, want := range map[string]string{"fd00::/8": "needs ipv6: true", "10.1.0.0": "10.1.0.0"} {
		h.Config.Docker.Networks = map[string]config.DockerNetworkConfig{"bad": {Subnets: []string{subnets}}}
		_, err := Resources(h)
		assert.ErrorContains(t, err, want)
	}
}

func TestResources_dockerGroupMembers(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Docker.Users = []string{"alice", "carol"}
	h.Config.Users["bob"] = config.UserConfig{Groups: []string{"docker"}}
	rs, err := Resources(h)
	require.NoError(t, err)

	members, ok := find[host.GroupMembers](rs, "group-members:docker")
	require.True(t, ok)
	assert.Equal(t, []string{"alice", "bob", "carol"}, members.Members)
	got := ids(rs)
	assert.Less(t, indexAfter(got, "user:carol", -1), indexAfter(got, "group-members:docker", -1))
}

func TestResources_sharedDependenciesOnce(t *testing.T) {
	rs, err := Resources(testHost(archLinux))
	require.NoError(t, err)
	got := ids(rs)
	for _, id := range []string{"user:" + aurUser, "package:git", "command:install paru"} {
		count := 0
		for _, g := range got {
			if g == id {
				count++
			}
		}
		assert.Equal(t, 1, count, id)
	}
}

func TestResources_ipForwarding(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]string
		want     bool
	}{
		{"exit node", map[string]string{"advertise-exit-node": "true"}, true},
		{"routes", map[string]string{"advertise-routes": "10.0.0.0/8"}, true},
		{"neither", map[string]string{"advertise-exit-node": "false", "ssh": "true"}, false},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				h := testHost(archLinux)
				h.Config.Tailscale.Settings = tt.settings
				rs, err := Resources(h)
				require.NoError(t, err)
				f, ok := find[host.File](rs, "file:/etc/sysctl.d/99-tailscale.conf")
				assert.Equal(t, tt.want, ok)
				if ok {
					assert.Equal(t, host.ResourceList{host.ServiceAction{Name: "systemd-sysctl", Action: "restart"}}, f.Notify)
				}
			},
		)
	}
}

func TestResources_sshdReloadUnit(t *testing.T) {
	tests := []struct {
		osFamily string
		unit     string
	}{
		{archLinux, "sshd"},
		{debian, "ssh"},
	}
	for _, tt := range tests {
		t.Run(
			tt.osFamily,
			func(t *testing.T) {
				h := testHost(tt.osFamily)
				h.Config.AUR.Packages = nil
				rs, err := Resources(h)
				require.NoError(t, err)
				want := host.ResourceList{host.ServiceAction{Name: tt.unit, Action: "reload"}}
				for _, path := range []string{
					"/etc/ssh/sshd_config.d/05-sensible.conf",
					"/etc/ssh/sshd_config.d/10-sensible.conf",
				} {
					f, ok := find[host.File](rs, "file:"+path)
					require.True(t, ok, path)
					assert.Equal(t, want, f.Notify, path)
				}
				_, ok := find[host.Service](rs, "service:"+tt.unit)
				assert.True(t, ok)
			},
		)
	}
}

func TestResources_pamRSSHDebianArch(t *testing.T) {
	tests := []struct {
		distro, release string
		deb             string
	}{
		{"debian", "trixie", "debian-trixie-arm64-pam-rssh_1.2.2-1_arm64.deb"},
		{"ubuntu", "noble", "ubuntu-24.04-arm-pam-rssh_1.2.2-1_arm64.deb"},
	}
	for _, tt := range tests {
		t.Run(
			tt.distro,
			func(t *testing.T) {
				h := testHost(debian)
				h.Config.AUR.Packages = nil
				h.Facts.Distro, h.Facts.Release, h.Facts.Arch = tt.distro, tt.release, "aarch64"
				rs, err := Resources(h)
				require.NoError(t, err)
				d, ok := find[host.Download](rs, "download:/var/cache/"+tt.deb)
				require.True(t, ok)
				assert.NotEmpty(t, d.SHA256)
				for _, service := range []string{"sudo", "sudo-i"} {
					l, ok := find[host.LineInFile](rs, "line:/etc/pam.d/"+service+":"+`^\s*auth\s+\S+\s+\S*pam_rssh\.so`)
					require.True(t, ok, service)
					assert.Contains(t, l.Line, "/lib/aarch64-linux-gnu/security/libpam_rssh.so")
				}
			},
		)
	}
}

func TestResources_pamRSSHArchHasNoLoginService(t *testing.T) {
	rs, err := Resources(testHost(archLinux))
	require.NoError(t, err)
	_, ok := find[host.LineInFile](rs, "line:/etc/pam.d/sudo-i:"+`^\s*auth\s+\S+\s+\S*pam_rssh\.so`)
	assert.False(t, ok)
}

func TestResources_remove(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Users["carol"] = config.UserConfig{Home: "/srv/carol"}
	h.Config.Remove = &config.RemoveConfig{
		Paths: config.Set{"/etc/ssh/sshd_config.d/10-other.conf", "~alice/.cache/old", "~carol/.old", "~root/.old"},
	}

	rs, err := Resources(h)
	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{
			"absent:/etc/ssh/sshd_config.d/10-other.conf",
			"absent:/home/alice/.cache/old",
			"absent:/srv/carol/.old",
			"absent:/root/.old",
		},
		ids(rs)[:4],
	)
}

func TestResources_removeRejectsPaths(t *testing.T) {
	for _, p := range []string{"etc/x", "/", "/etc/../x", "/etc/x/", "~", "~alice", "~alice/", "~/x", "~alice/../bob"} {
		t.Run(
			p,
			func(t *testing.T) {
				h := testHost(archLinux)
				h.Config.Remove = &config.RemoveConfig{Paths: config.Set{p}}
				_, err := Resources(h)
				assert.ErrorContains(t, err, "remove.paths")
			},
		)
	}
}

func TestResources_leftoversComeFirst(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Leftovers = &config.LeftoversConfig{
		Ignore:   config.KeptConfig{Paths: config.Set{"/etc/sudoers.d/README"}},
		External: config.KeptConfig{Packages: config.Set{"tool-*"}},
	}

	rs, err := Resources(h)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rs), 2)
	assert.Equal(
		t,
		[]host.Resource{
			host.KeptLeftovers{Paths: []string{"/etc/sudoers.d/README"}},
			host.KeptLeftovers{Packages: []string{"tool-*"}, External: true},
		},
		[]host.Resource(rs[:2]),
	)
}

func TestResources_leftoversRejectPatterns(t *testing.T) {
	for _, tt := range []struct {
		config config.LeftoversConfig
		err    string
	}{
		{config.LeftoversConfig{Ignore: config.KeptConfig{Paths: config.Set{"etc/x"}}}, "leftovers.ignore.paths"},
		{config.LeftoversConfig{External: config.KeptConfig{Paths: config.Set{"/"}}}, "leftovers.external.paths"},
		{config.LeftoversConfig{Ignore: config.KeptConfig{Paths: config.Set{"/etc/[x"}}}, "leftovers.ignore.paths"},
		{config.LeftoversConfig{Ignore: config.KeptConfig{Packages: config.Set{"package x"}}}, "leftovers.ignore.packages"},
		{config.LeftoversConfig{External: config.KeptConfig{Packages: config.Set{""}}}, "leftovers.external.packages"},
	} {
		t.Run(
			tt.err,
			func(t *testing.T) {
				h := testHost(archLinux)
				h.Config.Leftovers = &tt.config
				_, err := Resources(h)
				assert.ErrorContains(t, err, tt.err)
			},
		)
	}
}

func TestResources_pamRSSHOffRemovesOnlyItsLine(t *testing.T) {
	for _, tt := range []struct {
		osFamily string
		services []string
	}{
		{archLinux, []string{"sudo"}},
		{debian, []string{"sudo", "sudo-i"}},
	} {
		t.Run(
			tt.osFamily,
			func(t *testing.T) {
				h := testHost(tt.osFamily)
				h.Config.AUR = nil
				on, err := Resources(h)
				require.NoError(t, err)
				h.Config.PamRSSH = nil
				off, err := Resources(h)
				require.NoError(t, err)

				var removed []string
				for _, r := range off {
					l, ok := r.(host.LineInFile)
					if !ok || !l.Absent {
						continue
					}
					removed = append(removed, strings.TrimPrefix(l.Path, "/etc/pam.d/"))
					added, ok := find[host.LineInFile](on, "line:"+l.Path+":"+`^\s*auth\s+\S+\s+\S*pam_rssh\.so`)
					require.True(t, ok, l.Path)
					assert.Regexp(t, l.Regexp, added.Line)
					assert.NotRegexp(t, l.Regexp, "auth sufficient pam_rssh.so auth_key_file=/etc/other.keys")
				}
				assert.Equal(t, tt.services, removed)
			},
		)
	}
}

func TestResources_zshrc(t *testing.T) {
	tests := []struct {
		name     string
		osFamily string
		colour   string
		want     []string
	}{
		{
			name:     "arch",
			osFamily: archLinux,
			colour:   "208",
			want:     []string{"plugins=(git archlinux)\n", "  prompt_segment 208 black %m\n"},
		},
		{
			name:     "debian with a colour needing quotes",
			osFamily: debian,
			colour:   "it's red",
			want:     []string{"plugins=(git)\n", `  prompt_segment 'it'"'"'s red' black %m` + "\n"},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				h := testHost(tt.osFamily)
				h.Config.AUR.Packages = nil
				h.Config.Zsh.PromptColours["alice"] = tt.colour
				rs, err := Resources(h)
				require.NoError(t, err)
				f, ok := find[host.File](rs, "file:/home/alice/.zshrc")
				require.True(t, ok)
				assert.Equal(t, "alice", f.Owner)
				for _, w := range tt.want {
					assert.Contains(t, f.Content, w)
				}
				assert.Contains(t, f.Content, "ZSH_THEME=agnoster\n")
				assert.Contains(t, f.Content, "export EDITOR=vim\n")
			},
		)
	}
}

func TestResources_zshrcOtherTheme(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Zsh.Theme = "robbyrussell"
	h.Config.Zsh.Editor = "code --wait"
	h.Config.Zsh.PromptColours = nil
	rs, err := Resources(h)
	require.NoError(t, err)
	f, ok := find[host.File](rs, "file:/home/alice/.zshrc")
	require.True(t, ok)
	assert.Contains(t, f.Content, "ZSH_THEME=robbyrussell\n")
	assert.Contains(t, f.Content, "export EDITOR='code --wait'\n")
	assert.NotContains(t, f.Content, "prompt_")
}

func TestResources_zshPromptColoursNeedAgnoster(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Zsh.Theme = "robbyrussell"
	_, err := Resources(h)
	assert.ErrorContains(t, err, "zsh.prompt_colours needs the agnoster theme, not robbyrussell")
}

func TestAccessFiles(t *testing.T) {
	files := AccessFiles("ssh-ed25519 AAAA key")
	require.Len(t, files, 3)
	assert.Contains(t, files[0].Content, "sensible ALL=(root) "+host.AgentPath+" agent\n")
	assert.Contains(
		t,
		files[1].Content,
		"Match User sensible\n    AuthenticationMethods publickey\n    PubkeyAuthentication yes\n",
	)
	assert.Contains(
		t,
		files[2].Content,
		`restrict,command="/usr/bin/sudo -k -S -p '' `+host.AgentPath+` agent" ssh-ed25519 AAAA key`+"\n",
	)
	for _, f := range files {
		assert.Equal(t, "root", f.Owner, f.Path)
		assert.Empty(t, f.Notify, f.Path)
	}
}

func TestResources_declaresAccessPackages(t *testing.T) {
	for osFamily, sshd := range map[string]string{debian: "openssh-server", archLinux: "openssh"} {
		t.Run(
			osFamily,
			func(t *testing.T) {
				h := testHost(osFamily)
				h.Config.AUR = nil
				h.Config.Sudoers = nil
				h.Config.SSHD = nil
				rs, err := Resources(h)
				require.NoError(t, err)
				assert.Contains(t, ids(rs), "package:sudo")
				assert.Contains(t, ids(rs), "package:"+sshd)
			},
		)
	}
}

func TestResources_zshSetsShells(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Zsh.Users = []string{"alice", "carol"}
	rs, err := Resources(h)
	require.NoError(t, err)

	var shells []string
	for _, r := range rs {
		if u, ok := r.(host.User); ok && u.Shell == "/usr/bin/zsh" {
			shells = append(shells, u.Name+" "+u.Shell)
		}
	}
	assert.Equal(t, []string{"alice /usr/bin/zsh", "carol /usr/bin/zsh"}, shells)
}

func TestResources_loginMessagesOnlyHiddenWhenQuiet(t *testing.T) {
	for _, quiet := range []bool{true, false} {
		h := testHost(debian)
		h.Config.AUR = nil
		if !quiet {
			h.Config.QuietLogin = nil
		}
		rs, err := Resources(h)
		require.NoError(t, err)

		hidden := slices.ContainsFunc(
			rs,
			func(r host.Resource) bool {
				_, ok := r.(host.CommentOut)
				return ok
			},
		)
		assert.Equal(t, quiet, hidden)
	}
}

func TestResources_onlyConfiguredUsersAreManaged(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Zsh.Users = []string{"alice", "carol"}
	h.Config.Docker.Users = []string{"dave"}
	rs, err := Resources(h)
	require.NoError(t, err)

	var managed, unmanaged []string
	for _, r := range rs {
		if u, ok := r.(host.User); ok {
			if u.Managed {
				managed = append(managed, u.Name)
			} else if !slices.Contains(unmanaged, u.Name) {
				unmanaged = append(unmanaged, u.Name)
			}
		}
	}
	assert.Equal(t, []string{"alice", "bob"}, managed)
	assert.ElementsMatch(t, []string{"alice", "carol", "dave", SensibleUser, aurUser}, unmanaged)
}

func TestResources_accountFilesInHome(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Users["git"] = config.UserConfig{Home: "/var/lib/git"}
	h.Config.Zsh.Users = []string{"carol", "git", "root"}
	h.Config.SSHD.AuthorizedKeys = map[string]config.Set{
		"carol": {"ssh-ed25519 AAAA carol"},
		"git":   {"ssh-ed25519 AAAA git"},
		"root":  {"ssh-ed25519 AAAA root"},
	}
	rs, err := Resources(h)
	require.NoError(t, err)

	for name, home := range map[string]string{"carol": "/home/carol", "git": "/var/lib/git", "root": "/root"} {
		for _, id := range []string{"file:" + home + "/.zshrc", "file:" + home + "/.ssh/authorized_keys"} {
			f, ok := find[host.File](rs, id)
			require.True(t, ok, id)
			assert.Equal(t, name, f.Owner, id)
			assert.Empty(t, f.Group, id)
		}
		d, ok := find[host.Dir](rs, "dir:"+home+"/.ssh")
		require.True(t, ok, home)
		assert.Equal(t, name, d.Owner)
		assert.Empty(t, d.Group)
	}
}

func TestResources_userHomeAndShell(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Users["git"] = config.UserConfig{Home: "/var/lib/git", Shell: "/usr/bin/git-shell"}
	rs, err := Resources(h)
	require.NoError(t, err)

	u, ok := find[host.User](rs, "user:git")
	require.True(t, ok)
	assert.Equal(t, "/var/lib/git", u.Home)
	assert.Equal(t, "/usr/bin/git-shell", u.Shell)
}

func TestResources_userErrors(t *testing.T) {
	tests := []struct {
		name string
		user config.UserConfig
		want string
	}{
		{
			"relative home",
			config.UserConfig{Home: "var/lib/git"},
			`users.alice.home must be an absolute path, not "var/lib/git"`,
		},
		{"unclean shell", config.UserConfig{Shell: "/bin/../bin/sh"}, "users.alice.shell must be an absolute path"},
		{
			"shell zsh would change",
			config.UserConfig{Shell: "/bin/bash"},
			"users.alice.shell is /bin/bash, but zsh.users sets it to /usr/bin/zsh",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				h := testHost(debian)
				h.Config.AUR = nil
				h.Config.Users["alice"] = tt.user
				_, err := Resources(h)
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestResources_zshUserMayAlsoSetZsh(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Users["alice"] = config.UserConfig{Shell: "/usr/bin/zsh"}
	_, err := Resources(h)
	assert.NoError(t, err)
}

func TestResources_hostname(t *testing.T) {
	tests := []struct {
		name       string
		osFamily   string
		configured string
		want       string
		hostsLine  string
	}{
		{"defaults to inventory name", archLinux, "", "testhost", ""},
		{
			"Debian maps the short name too",
			debian,
			"testhost.example.com",
			"testhost.example.com",
			"127.0.1.1\ttesthost.example.com testhost",
		},
		{"Debian short name", debian, "", "testhost", "127.0.1.1\ttesthost"},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				h := testHost(tt.osFamily)
				h.Config.AUR = nil
				h.Config.Hostname.Name = tt.configured
				rs, err := Resources(h)
				require.NoError(t, err)

				f, ok := find[host.File](rs, "file:/etc/hostname")
				require.True(t, ok)
				assert.Equal(t, tt.want+"\n", f.Content)
				c, ok := find[host.Command](rs, "command:set hostname")
				require.True(t, ok)
				assert.Equal(t, tt.want, c.ApplyArgv[len(c.ApplyArgv)-1])

				l, ok := find[host.LineInFile](rs, "line:/etc/hosts:"+`^127\.0\.1\.1\s`)
				assert.Equal(t, tt.hostsLine != "", ok)
				assert.Equal(t, tt.hostsLine, l.Line)
			},
		)
	}
}

func TestResources_locale(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Locale.Generate = []string{"en_GB.UTF-8", "de_DE.ISO-8859-15@euro"}
	rs, err := Resources(h)
	require.NoError(t, err)

	f, ok := find[host.File](rs, "file:/etc/locale.gen")
	require.True(t, ok)
	assert.Equal(t, managedLines([]string{"en_GB.UTF-8 UTF-8", "de_DE.ISO-8859-15@euro ISO-8859-15"}), f.Content)

	c, ok := find[host.Command](rs, "command:generate locales")
	require.True(t, ok)
	assert.Equal(t, []string{"en_GB.utf8", "de_DE.iso885915@euro"}, c.CheckArgv[4:])
}

func TestResources_ntpRestartsOnChange(t *testing.T) {
	rs, err := Resources(testHost(archLinux))
	require.NoError(t, err)
	restart := host.ResourceList{host.ServiceAction{Name: "systemd-timesyncd", Action: "restart"}}

	f, ok := find[host.File](rs, "file:"+timesyncdConfDir+"/sensible.conf")
	require.True(t, ok)
	assert.Contains(t, f.Content, "NTP=ntp.example.com\n")
	assert.Equal(t, restart, f.Notify)
	d, ok := find[host.OwnedDir](rs, "owned-dir:"+timesyncdConfDir)
	require.True(t, ok)
	assert.Equal(t, restart, d.Notify)
	require.NotEmpty(t, d.Header)
	assert.True(t, strings.HasPrefix(f.Content, d.Header), "the drop-in would be left for prune")
}

func TestResources_sudoersCleanUpRemovesOnlyItsOwnFiles(t *testing.T) {
	rs, err := Resources(testHost(archLinux))
	require.NoError(t, err)

	d, ok := find[host.OwnedDir](rs, "owned-dir:"+sudoersDir)
	require.True(t, ok)
	require.NotEmpty(t, d.Header)
	var files int
	for _, r := range rs {
		if f, ok := r.(host.File); ok && strings.HasPrefix(f.Path, sudoersDir+"/") {
			files++
			assert.True(t, strings.HasPrefix(f.Content, d.Header), "%s would be left for prune", f.Path)
		}
	}
	assert.NotZero(t, files)
}

func TestResources_jobs(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Jobs = map[string]config.JobConfig{
		"report": {Command: []string{"/usr/bin/report", `50% of "$HOME"`, `a\b`}, Schedule: "*-*-* 04:00", User: "alice"},
	}
	rs, err := Resources(h)
	require.NoError(t, err)

	service, ok := find[host.File](rs, "file:/etc/systemd/system/sensible-report.service")
	require.True(t, ok)
	assert.Contains(t, service.Content, "\nExecStart=\"/usr/bin/report\" \"50%% of \\\"$$HOME\\\"\" \"a\\\\b\"\n")
	assert.Contains(t, service.Content, "\nUser=alice\n")
	timer, ok := find[host.File](rs, "file:/etc/systemd/system/sensible-report.timer")
	require.True(t, ok)
	assert.Contains(t, timer.Content, "\nOnCalendar=*-*-* 04:00\n")
	assert.Equal(t, []string{"systemd-analyze", "calendar", "*-*-* 04:00"}, timer.Validate)
	reload, ok := find[host.SystemdReload](rs, "systemd-reload")
	require.True(t, ok)
	assert.Equal(t, []string{service.ID(), timer.ID()}, reload.Watch)
}

func TestResources_noJobsStillCleansUp(t *testing.T) {
	h := testHost(archLinux)
	h.Config.Jobs = nil
	rs, err := Resources(h)
	require.NoError(t, err)

	assert.NotContains(t, ids(rs), "systemd-reload")
	assert.Contains(t, ids(rs), "systemd-units:sensible-")
}

func TestResources_dockerDaemon(t *testing.T) {
	for _, osFamily := range []string{archLinux, debian} {
		t.Run(
			osFamily,
			func(t *testing.T) {
				h := testHost(osFamily)
				h.Config.AUR = nil
				h.Config.Docker.Daemon = map[string]any{
					"log-driver": "local",
					"log-opts":   map[string]any{"max-size": "10m"},
					"dns":        []any{"192.0.2.1"},
					"ipv6":       true,
				}
				rs, err := Resources(h)
				require.NoError(t, err)

				file, ok := find[host.File](rs, "file:/etc/docker/daemon.json")
				require.True(t, ok)
				assert.JSONEq(
					t,
					`{"log-driver": "local", "log-opts": {"max-size": "10m"}, "dns": ["192.0.2.1"], "ipv6": true}`,
					file.Content,
				)
				restart, ok := find[host.ServiceRestart](rs, "service-restart:docker")
				require.True(t, ok)
				assert.Equal(t, []string{file.ID()}, restart.Watch)

				got := ids(rs)
				install := map[string]string{archLinux: "package:docker", debian: "package:docker-ce"}[osFamily]
				assert.Less(t, slices.Index(got, install), slices.Index(got, file.ID()), "dockerd validates the file")
				assert.Less(t, slices.Index(got, file.ID()), slices.Index(got, restart.ID()))
				assert.Less(t, slices.Index(got, restart.ID()), slices.Index(got, "docker-network:web"))
				assert.Less(t, slices.Index(got, restart.ID()), slices.Index(got, "compose:/srv/compose/web"))
			},
		)
	}
}

func TestResources_dockerDaemonUnset(t *testing.T) {
	rs, err := Resources(testHost(archLinux))
	require.NoError(t, err)
	assert.NotContains(t, ids(rs), "file:/etc/docker/daemon.json")
	assert.NotContains(t, ids(rs), "service-restart:docker")
}

func TestResources_dockerRegistries(t *testing.T) {
	h := testHost(archLinux)
	rs, err := Resources(h)
	require.NoError(t, err)
	_, ok := find[host.File](rs, "file:/root/.docker/config.json")
	assert.False(t, ok, "root's client config is left alone without registries")

	h.Config.Docker.Auths = map[string]string{"b.example.com": "Yjpi", "a.example.com": "YTph"}
	rs, err = Resources(h)
	require.NoError(t, err)
	got := ids(rs)
	f, ok := find[host.File](rs, "file:/root/.docker/config.json")
	require.True(t, ok)
	assert.Equal(
		t,
		host.File{
			Path: "/root/.docker/config.json",
			Content: "{\n\t\"auths\": {\n" +
				"\t\t\"a.example.com\": {\n\t\t\t\"auth\": \"YTph\"\n\t\t},\n" +
				"\t\t\"b.example.com\": {\n\t\t\t\"auth\": \"Yjpi\"\n\t\t}\n" +
				"\t}\n}\n",
			Owner:  "root",
			Group:  "root",
			Mode:   0o600,
			Hidden: true,
		},
		f,
	)
	assert.Less(t, indexAfter(got, "dir:/root/.docker", -1), indexAfter(got, "file:/root/.docker/config.json", -1))
	assert.Less(t, indexAfter(got, "file:/root/.docker/config.json", -1), indexAfter(got, "compose:/srv/compose/web", -1))
}

func TestResources_certs(t *testing.T) {
	h := testHost(archLinux)
	dir := "/opt/app/certs"
	h.Config.IssuedCerts = []config.Cert{
		{Name: "app", Dir: dir, Owner: "alice", Group: "users", CACert: "ca\n", Cert: "cert\n", Key: "key\n"},
	}
	h.Config.Stacks = []config.Stack{{Name: "web", CertPaths: []string{dir + "/tls.key"}}}
	rs, err := Resources(h)
	require.NoError(t, err)

	index := func(id string) int {
		return slices.IndexFunc(rs, func(r host.Resource) bool { return r.ID() == id })
	}
	key, ok := find[host.File](rs, "file:"+dir+"/tls.key")
	require.True(t, ok)
	assert.Equal(t, "key\n", key.Content)
	assert.Equal(t, 0o600, int(key.Mode))
	assert.Equal(t, "alice", key.Owner)
	assert.True(t, key.Hidden)

	// The record comes first so a failed run can't leave an untracked key,
	// and clean-up comes after the stacks that may have been mounting it.
	record := index("cert-record:app")
	assert.Less(t, record, index("file:"+dir+"/tls.key"))
	assert.Less(t, index("file:"+dir+"/tls.key"), index("compose:/srv/compose/web"))
	assert.Less(t, index("compose:/srv/compose/web"), index("cert-records"))

	stack, ok := find[host.ComposeStack](rs, "compose:/srv/compose/web")
	require.True(t, ok)
	assert.Contains(t, stack.Watch, "file:"+dir+"/tls.key")
}

func TestResources_certsCleanUpWithoutCerts(t *testing.T) {
	rs, err := Resources(Host{Name: "testhost", Facts: host.Facts{OSFamily: archLinux}})
	require.NoError(t, err)
	assert.True(t, slices.ContainsFunc(rs, func(r host.Resource) bool { return r.ID() == "cert-records" }))
}

func TestResources_disownedMatchWhatFeaturesWrite(t *testing.T) {
	for _, osFamily := range []string{archLinux, debian} {
		t.Run(
			osFamily,
			func(t *testing.T) {
				h := testHost(osFamily)
				if osFamily == debian {
					h.Config.AUR.Packages = nil
				}
				h.Config.Docker.Daemon = map[string]any{"log-driver": "local"}
				h.Config.Docker.Auths = map[string]string{"registry.example.com": "YTph"}
				h.Config.Zsh.Users = append(h.Config.Zsh.Users, "root")
				h.Config.SSHD.AuthorizedKeys["root"] = config.Set{"ssh-ed25519 AAAA root"}
				h.Config.Users["git"] = config.UserConfig{Home: "/var/lib/git"}
				h.Config.Zsh.Users = append(h.Config.Zsh.Users, "git")
				h.Config.SSHD.AuthorizedKeys["git"] = config.Set{"ssh-ed25519 AAAA git"}
				rs, err := Resources(h)
				require.NoError(t, err)

				disowned := trailingDisowned(t, rs)
				require.NotEmpty(t, disowned)
				zsh, ok := find[host.Disowned](rs, "disowned:zsh")
				require.True(t, ok)
				assert.Contains(t, zsh.Paths, "/var/lib/git/.zshrc")
				for _, d := range disowned {
					for _, pattern := range d.Paths {
						assertWritten(t, rs, d, pattern)
					}
				}
				_, ok = find[host.DisownedPackages](rs, "disowned-packages")
				assert.True(t, ok)
			},
		)
	}
}

func TestResources_recordsOnlyPackagesSafeToPrune(t *testing.T) {
	for osFamily, docker := range map[string]string{archLinux: "docker", debian: "docker-ce"} {
		t.Run(
			osFamily,
			func(t *testing.T) {
				h := testHost(osFamily)
				if osFamily == debian {
					h.Config.AUR.Packages = nil
				}
				rs, err := Resources(h)
				require.NoError(t, err)

				recorded := map[string]bool{}
				for _, r := range rs {
					switch r := r.(type) {
					case host.Package:
						if r.Record {
							recorded[r.Name] = true
						}
					case host.AURPackage:
						if r.Record {
							recorded[r.Name] = true
						}
					default:
					}
				}
				wanted := append([]string{docker, pamRSSHPackage(h)}, h.Config.Packages.Install...)
				wanted = append(wanted, h.Config.AUR.Packages...)
				for _, name := range wanted {
					assert.True(t, recorded[name], "%s isn't recorded", name)
				}
				for _, name := range []string{"git", "base-devel", "sudo", "zsh", "tailscale"} {
					assert.False(t, recorded[name], "%s is recorded, but other things may rely on it", name)
				}
			},
		)
	}
}

// trailingDisowned returns the Disowned resources, requiring them,
// DisownedPackages and DisownedAptSources to come after every other resource.
func trailingDisowned(t *testing.T, rs host.ResourceList) []host.Disowned {
	t.Helper()
	var disowned []host.Disowned
	trailing := false
	for _, r := range rs {
		switch d := r.(type) {
		case host.Disowned:
			disowned = append(disowned, d)
			trailing = true
		case host.DisownedPackages, host.DisownedAptSources:
			trailing = true
		default:
			require.False(t, trailing, "%s comes after a disowned resource", r.ID())
		}
	}
	return disowned
}

// assertWritten checks that a feature writes something matching pattern,
// and that what it writes passes d's filters, or it would go unreported once
// the feature's turned off.
func assertWritten(t *testing.T, rs host.ResourceList, d host.Disowned, pattern string) {
	t.Helper()
	written := 0
	for _, r := range rs {
		p, ok := writtenPath(r)
		if match, _ := filepath.Match(pattern, p); !ok || !match {
			continue
		}
		written++
		if f, ok := r.(host.File); ok && d.Header != "" {
			assert.True(t, strings.HasPrefix(f.Content, d.Header), "%s doesn't start with %q", p, d.Header)
		}
		if f, ok := r.(host.File); ok && d.Recorded {
			assert.Contains(t, rs, host.WrittenRecord(f), "%s isn't recorded", p)
		}
		if l, ok := r.(host.Symlink); ok && d.Target != "" {
			assert.Equal(t, d.Target, l.Target)
		}
	}
	assert.NotZero(t, written, "nothing writes %s", pattern)
}

func writtenPath(r host.Resource) (string, bool) {
	switch r := r.(type) {
	case host.File:
		return r.Path, true
	case host.Symlink:
		return r.Path, true
	case host.GitCheckout:
		return r.Path, true
	case host.Download:
		return r.Path, true
	default:
		return "", false
	}
}

func TestResources_disownedReloadsSSHD(t *testing.T) {
	for osFamily, unit := range map[string]string{archLinux: "sshd", debian: "ssh"} {
		h := testHost(osFamily)
		h.Config.AUR.Packages = nil
		rs, err := Resources(h)
		require.NoError(t, err)

		d, ok := find[host.Disowned](rs, "disowned:sshd")
		require.True(t, ok)
		assert.Equal(
			t,
			host.ResourceList{host.ServiceAction{Name: unit, Action: "reload"}, sshdSocketRestart(h)},
			d.Notify,
		)
	}
}

func TestResources_sshdListenSettingsRestartSocket(t *testing.T) {
	for osFamily, unit := range map[string]string{archLinux: "sshd", debian: "ssh"} {
		t.Run(
			osFamily,
			func(t *testing.T) {
				h := testHost(osFamily)
				h.Config.AUR.Packages = nil
				h.Config.SSHD.Settings = map[string]string{
					"MaxAuthTries":  "3",
					"Port":          "2222",
					"listenaddress": "192.0.2.1",
				}
				rs, err := Resources(h)
				require.NoError(t, err)

				settings, ok := find[host.File](rs, "file:"+sshdDropIn)
				require.True(t, ok)
				assert.Equal(t, managedLines([]string{"MaxAuthTries 3"}), settings.Content)
				assert.Equal(t, host.ResourceList{host.ServiceAction{Name: unit, Action: "reload"}}, settings.Notify)

				listen, ok := find[host.File](rs, "file:"+sshdListenDropIn)
				require.True(t, ok)
				assert.Equal(t, managedLines([]string{"Port 2222", "listenaddress 192.0.2.1"}), listen.Content)
				require.Len(t, listen.Notify, 2)
				assert.Equal(t, host.ServiceAction{Name: unit, Action: "reload"}, listen.Notify[0])
				restart, ok := listen.Notify[1].(host.Command)
				require.True(t, ok)
				assert.Contains(t, restart.ApplyArgv[len(restart.ApplyArgv)-1], "systemctl restart "+unit+".socket")
			},
		)
	}
}

func TestResources_sshdAccessListsAdmitSensible(t *testing.T) {
	tests := []struct {
		key, value string
		err        string
	}{
		{key: "AllowUsers", value: "chris", err: "sshd.settings.AllowUsers must admit sensible"},
		{key: "allowusers", value: "chris sensible"},
		{key: "AllowUsers", value: "chris sensible@192.0.2.1"},
		{key: "AllowUsers", value: "*"},
		{key: "AllowUsers", value: "sens?ble"},
		{key: "AllowUsers", value: "sens*x", err: "must admit sensible"},
		{key: "AllowGroups", value: "wheel", err: "sshd.settings.AllowGroups must admit sensible"},
		{key: "AllowGroups", value: "wheel sensible"},
		{key: "DenyUsers", value: "root"},
		{key: "DenyUsers", value: "root sensible@*", err: "sshd.settings.DenyUsers must not match sensible"},
		{key: "denyusers", value: "s*", err: "must not match sensible"},
		{key: "DenyGroups", value: "sensible", err: "sshd.settings.DenyGroups must not match sensible"},
		{key: "DenyGroups", value: "sensiblex"},
	}
	for _, tt := range tests {
		t.Run(
			tt.key+" "+tt.value,
			func(t *testing.T) {
				h := testHost(debian)
				h.Config.AUR = nil
				h.Config.SSHD.Settings = map[string]string{tt.key: tt.value}
				_, err := Resources(h)
				if tt.err == "" {
					assert.NoError(t, err)
				} else {
					assert.ErrorContains(t, err, tt.err)
				}
			},
		)
	}
}

func TestParuInstallScript_disablesDebugPackage(t *testing.T) {
	bin, tmp := t.TempDir(), t.TempDir()
	out := filepath.Join(t.TempDir(), "debug")
	fakes := map[string]string{
		"runuser": "#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
		"git":     "#!/bin/sh\nfor a; do dir=$a; done\nmkdir -p \"$dir\"\n",
		// Reads its user config after a system config that enables debug
		// packages, and records the last word on them.
		"makepkg": "#!/bin/bash\nOPTIONS=(strip debug lto)\n" +
			"source \"${XDG_CONFIG_HOME:-$HOME/.config}/pacman/makepkg.conf\"\n" +
			"for o in \"${OPTIONS[@]}\"; do case $o in debug|'!debug') last=$o;; esac; done\n" +
			"echo \"$last\" >\"$OUT\"\n",
	}
	for name, script := range fakes {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755))
	}

	cmd := exec.CommandContext(t.Context(), "sh", "-c", paruInstallScript)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp, "OUT="+out)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "!debug\n", string(got))
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestResources_files(t *testing.T) {
	for _, osFamily := range []string{archLinux, debian} {
		t.Run(
			osFamily,
			func(t *testing.T) {
				h := testHost(osFamily)
				h.Config.AUR = nil
				h.Config.Files = []config.FileConfig{
					{
						Path:  "/etc/systemd/zram-generator.conf",
						Owner: "root", Group: "root", Mode: 0o644,
						Data:   "[zram0]\n",
						Hidden: true,
					},
				}
				rs, err := Resources(h)
				require.NoError(t, err)

				f, ok := find[host.File](rs, "file:/etc/systemd/zram-generator.conf")
				require.True(t, ok)
				assert.Equal(
					t,
					host.File{
						Path:    "/etc/systemd/zram-generator.conf",
						Content: "[zram0]\n",
						Owner:   "root",
						Group:   "root",
						Mode:    0o644,
						Hidden:  true,
					},
					f,
				)
				d, ok := find[host.Disowned](rs, "disowned:files")
				require.True(t, ok)
				record := host.WrittenRecordIn(d.Records, f)
				assert.Contains(t, rs, record)
				_, ok = find[host.Dir](rs, "dir:"+filepath.Dir(record.Path))
				assert.True(t, ok, "the records' directory isn't created")
			},
		)
	}
}

func TestResources_fileAlsoWrittenByAFeature(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Files = []config.FileConfig{{Path: "/etc/hostname", Data: "other\n"}}

	_, err := Resources(h)

	assert.ErrorContains(t, err, "/etc/hostname is written twice")
}

func TestResources_filesCreateTheirDirectories(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Files = []config.FileConfig{
		{Path: "/etc/foo.d/a.conf", Data: "a\n"},
		{Path: "/etc/foo.d/b.conf", Data: "b\n"},
	}
	rs, err := Resources(h)
	require.NoError(t, err)

	all := ids(rs)
	dir := slices.Index(all, "dir:/etc/foo.d")
	require.GreaterOrEqual(t, dir, 0)
	assert.Len(
		t,
		slices.DeleteFunc(slices.Clone(all), func(id string) bool { return id != "dir:/etc/foo.d" }),
		1,
		"the directory is declared more than once",
	)
	assert.Greater(t, slices.Index(all, "file:/etc/foo.d/a.conf"), dir)
	d, _ := find[host.Dir](rs, "dir:/etc/foo.d")
	assert.Equal(t, host.Dir{Path: "/etc/foo.d"}, d)
}

func TestResources_services(t *testing.T) {
	for _, osFamily := range []string{archLinux, debian} {
		t.Run(
			osFamily,
			func(t *testing.T) {
				h := testHost(osFamily)
				h.Config.AUR = nil
				h.Config.Services = map[string]config.ServiceState{
					"bluetooth.service":   config.ServiceEnabled,
					"fwupd-refresh.timer": config.ServiceDisabled,
					"smartd.service":      config.ServiceMasked,
				}
				rs, err := Resources(h)
				require.NoError(t, err)

				for _, want := range []host.Service{
					{Name: "bluetooth.service", Enabled: true, Running: true},
					{Name: "fwupd-refresh.timer"},
					{Name: "smartd.service", Masked: true},
				} {
					got, ok := find[host.Service](rs, want.ID())
					require.True(t, ok, want.Name)
					assert.Equal(t, want, got)
				}
			},
		)
	}
}

func TestResources_serviceAlsoRunByAFeature(t *testing.T) {
	h := testHost(debian)
	h.Config.AUR = nil
	h.Config.Services = map[string]config.ServiceState{"systemd-timesyncd": config.ServiceMasked}

	_, err := Resources(h)

	assert.ErrorContains(t, err, "service systemd-timesyncd is given two different states")
}

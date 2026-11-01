package features

import (
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
			Sudoers:  map[string][]string{"000-alice": {"alice ALL=(ALL:ALL) ALL"}},
			PamRSSH:  &config.PamRSSHConfig{Keys: []string{"ssh-ed25519 AAAA sudo"}},
			SSHD: &config.SSHDConfig{
				Settings: map[string]string{"MaxAuthTries": "3"},
				AuthorizedKeys: map[string][]string{
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
			Docker:   &config.DockerConfig{Users: []string{"alice"}},
			Vim:      &config.VimConfig{},
			Hostname: &config.HostnameConfig{},
			Timezone: &config.TimezoneConfig{Zone: "Europe/London"},
			Locale:   &config.LocaleConfig{Lang: "en_GB.UTF-8", Generate: []string{"en_US.UTF-8"}},
			NTP:      &config.NTPConfig{Servers: []string{"ntp.example.com"}},
		},
		Facts: host.Facts{
			OSFamily: osFamily,
			Release:  "trixie",
			Arch:     "x86_64",
			Users: map[string]host.PasswdUser{
				"alice": {UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/usr/bin/zsh"},
				"bob":   {UID: 1001, GID: 1001, Home: "/home/bob", Shell: "/bin/bash"},
			},
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
				"owned-dir:/etc/sudoers.d",
			},
		},
		{
			osFamily: debian,
			want: []string{
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
				"owned-dir:/etc/sudoers.d",
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
				assert.Equal(t, "owned-dir:/etc/sudoers.d", got[len(got)-1])
			},
		)
	}
}

func indexAfter(ids []string, id string, after int) int {
	for i := after + 1; i < len(ids); i++ {
		if ids[i] == id {
			return i
		}
	}
	return -1
}

func TestResources_errors(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Host)
	}{
		{"unsupported OS", func(h *Host) { h.Facts.OSFamily = "redhat" }},
		{"Debian without release", func(h *Host) { h.Facts.Release = "" }},
		{"AUR on Debian", func(h *Host) {}},
		{"invalid hostname", func(h *Host) { h.Config.Hostname.Name = "bad_name" }},
		{"unknown timezone", func(h *Host) { h.Config.Timezone.Zone = "Europe/Nowhere" }},
		{"local timezone", func(h *Host) { h.Config.Timezone.Zone = "Local" }},
		{"locale without lang", func(h *Host) { h.Config.Locale.Lang = "" }},
		{"locale without charset", func(h *Host) { h.Config.Locale.Generate = []string{"en_US"} }},
		{"pam_rssh without a release", func(h *Host) {
			h.Config.AUR.Packages = nil
			h.Facts.Release = "buster"
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
			name:    "local host",
			modify:  func(h *Host) { h.Local = true },
			absent:  []string{"user:" + SensibleUser, "file:/etc/sudoers.d/" + SensibleUser},
			present: []string{"owned-dir:/etc/sudoers.d"},
		},
		{
			name:   "no docker",
			modify: func(h *Host) { h.Config.Docker = nil },
			absent: []string{"package:docker", "command:install and start docker"},
		},
		{
			name:   "no tailscale",
			modify: func(h *Host) { h.Config.Tailscale = nil },
			absent: []string{"package:tailscale", "tailscale-set"},
		},
		{
			name:    "account not created yet",
			modify:  func(h *Host) { delete(h.Facts.Users, "alice") },
			absent:  []string{"file:/home/alice/.zshrc", "dir:/home/alice/.ssh", "absent:/home/alice/.oh-my-zsh"},
			present: []string{"user:alice", "file:/home/bob/.ssh/authorized_keys"},
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
	h := testHost(debian)
	h.Config.AUR.Packages = nil
	h.Facts.Arch = "aarch64"
	rs, err := Resources(h)
	require.NoError(t, err)
	d, ok := find[host.Download](rs, "download:/var/cache/debian-trixie-arm64-pam-rssh_1.2.2-1_arm64.deb")
	require.True(t, ok)
	assert.NotEmpty(t, d.SHA256)
	l, ok := find[host.LineInFile](rs, "line:/etc/pam.d/sudo:"+`^\s*auth\s+\S+\s+\S*pam_rssh\.so`)
	require.True(t, ok)
	assert.Contains(t, l.Line, "/lib/aarch64-linux-gnu/security/libpam_rssh.so")
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
				assert.Equal(t, "1000", f.Group)
				for _, w := range tt.want {
					assert.Contains(t, f.Content, w)
				}
				assert.Contains(t, f.Content, "ZSH_THEME=agnoster\n")
			},
		)
	}
}

func TestAccessFiles(t *testing.T) {
	files := AccessFiles("ssh-ed25519 AAAA key")
	require.Len(t, files, 3)
	assert.Contains(t, files[0].Content, "sensible ALL=(root) "+host.AgentPath+" agent\n")
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
	_, ok := find[host.File](rs, "file:/home/carol/.zshrc")
	assert.False(t, ok)
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
}

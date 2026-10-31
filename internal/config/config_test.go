package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type testRepo struct {
	dir      string
	identity *age.X25519Identity
	fetches  int
}

func newTestRepo(t *testing.T, files map[string]string) *testRepo {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	tr := &testRepo{dir: t.TempDir(), identity: id}

	if _, ok := files["hosts.yml"]; !ok {
		files["hosts.yml"] = "hosts:\n  alpha:\n    address: alpha.example.com\n  beta: {}\n"
	}
	if _, ok := files["secrets.yml"]; !ok {
		files["secrets.yml"] = "recipients: [" + id.Recipient().String() + "]\n"
	}
	for name, content := range files {
		p := filepath.Join(tr.dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	return tr
}

func (tr *testRepo) open(t *testing.T) *Repo {
	t.Helper()
	r, err := tr.tryOpen()
	require.NoError(t, err)
	return r
}

func (tr *testRepo) tryOpen() (*Repo, error) {
	return Open(tr.dir, tr.source)
}

func (tr *testRepo) source() (age.Identity, error) {
	tr.fetches++
	return tr.identity, nil
}

func TestHostConfig_mergesLayersInOrder(t *testing.T) {
	r := newTestRepo(
		t,
		map[string]string{
			"all.yml": `
packages:
  install: [zsh, vim]
users:
  chris:
    shell: /usr/bin/zsh
    groups: [wheel]
    prompt_colour: white
tailscale:
  settings:
    ssh: true
    advertise-exit-node: true
    operator: chris
`,
			"os/archlinux.yml": `
packages:
  install: [paru, zsh]
  remove: [vi]
`,
			"hosts/alpha.yml": `
packages:
  install: [docker, vim]
users:
  chris: {prompt_colour: green, groups: [docker]}
  root: {shell: /bin/sh}
tailscale:
  settings:
    advertise-exit-node: false
    relay-server-port: 40000
sshd:
  enabled: false
`,
		},
	).open(t)

	c, err := r.HostConfig("alpha", "archlinux")
	require.NoError(t, err)

	assert.Equal(t, []string{"zsh", "vim", "paru", "docker"}, c.Packages.Install)
	assert.Equal(t, []string{"vi"}, c.Packages.Remove)
	assert.Equal(
		t,
		map[string]UserConfig{
			"chris": {Shell: "/usr/bin/zsh", Groups: []string{"wheel", "docker"}, PromptColour: "green"},
			"root":  {Shell: "/bin/sh"},
		},
		c.Users,
	)
	assert.Equal(
		t,
		map[string]string{
			"ssh":                 "true",
			"advertise-exit-node": "false",
			"operator":            "chris",
			"relay-server-port":   "40000",
		},
		c.Tailscale.Settings,
	)
	assert.False(t, c.SSHD.Enabled)
	assert.True(t, c.Docker.Enabled)

	c, err = r.HostConfig("beta", "debian")
	require.NoError(t, err)
	assert.Equal(t, []string{"zsh", "vim"}, c.Packages.Install)
	assert.Equal(t, "white", c.Users["chris"].PromptColour)
	assert.True(t, c.SSHD.Enabled)
}

func TestHostConfig_replaceTag(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"all.yml": `
packages:
  install: [zsh, vim]
users:
  chris: {shell: /usr/bin/zsh, groups: [wheel]}
  root: {shell: /usr/bin/zsh}
sshd:
  settings:
    PermitRootLogin: "no"
    MaxAuthTries: 4
`,
			"hosts/alpha.yml": `
packages:
  install: !replace [nano]
users: !replace
  chris: {groups: [docker]}
sshd:
  settings: !replace {}
`,
		},
	).open(t).HostConfig("alpha", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"nano"}, c.Packages.Install)
	assert.Equal(t, map[string]UserConfig{"chris": {Groups: []string{"docker"}}}, c.Users)
	assert.Empty(t, c.SSHD.Settings)
}

func TestHostConfig_nullDoesNotOverride(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"all.yml":         "pam_rssh:\n  keys: [k1]\n",
			"hosts/alpha.yml": "pam_rssh:\n",
		},
	).open(t).HostConfig("alpha", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"k1"}, c.PamRSSH.Keys)
}

func TestHostConfig_errors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name:  "unknown key",
			files: map[string]string{"os/debian.yml": "packages:\n  install: [a]\n  instal: [b]\n"},
			want:  []string{"os/debian.yml", "[3:3]", "instal"},
		},
		{
			name:  "unknown top-level key under replace",
			files: map[string]string{"hosts/alpha.yml": "sshd: !replace\n  enable: true\n"},
			want:  []string{"hosts/alpha.yml", "enable"},
		},
		{
			name:  "plain secret",
			files: map[string]string{"all.yml": "dns:\n  auth_key: hunter2\n"},
			want:  []string{"all.yml", "[2:13]", "encrypt"},
		},
		{
			name:  "malformed secret",
			files: map[string]string{"all.yml": "dns:\n  auth_key: !age not armored\n"},
			want:  []string{"all.yml", "armored"},
		},
		{
			name:  "wrong type",
			files: map[string]string{"all.yml": "sshd:\n  enabled: [yes]\n"},
			want:  []string{"all.yml"},
		},
		{
			name:  "syntax error",
			files: map[string]string{"hosts/alpha.yml": "users: [\n"},
			want:  []string{"hosts/alpha.yml"},
		},
		{
			name:  "not a mapping",
			files: map[string]string{"all.yml": "- a\n- b\n"},
			want:  []string{"all.yml", "mapping"},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				_, err := newTestRepo(t, tt.files).open(t).HostConfig("alpha", "debian")
				require.Error(t, err)
				for _, w := range tt.want {
					assert.Contains(t, err.Error(), w)
				}
			},
		)
	}
}

func TestHostConfig_unknownHost(t *testing.T) {
	_, err := newTestRepo(t, map[string]string{}).open(t).HostConfig("gamma", "debian")
	assert.ErrorContains(t, err, "gamma")
}

func TestOpen(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"host file for unknown host", map[string]string{"hosts/gamma.yml": ""}, "gamma"},
		{"credentials for unknown host", map[string]string{"credentials/gamma.yml": ""}, "gamma"},
		{"wrong extension", map[string]string{"hosts/alpha.yaml": ""}, "alpha.yaml"},
		{"unknown inventory key", map[string]string{"hosts.yml": "hosts:\n  a: {addr: x}\n"}, "addr"},
		{"invalid host key", map[string]string{"hosts.yml": "hosts:\n  a: {host_keys: [ssh-ed25519 nope]}\n"}, "host key"},
		{"bad recipient", map[string]string{"secrets.yml": "recipients: [nope]\n"}, "recipients"},
		{"unknown secrets key", map[string]string{"secrets.yml": "identity: op://x\n"}, "identity"},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				_, err := newTestRepo(t, tt.files).tryOpen()
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}

	t.Run(
		"valid",
		func(t *testing.T) {
			tr := newTestRepo(t, map[string]string{"hosts/alpha.yml": "", "os/arch.yml": "", "hosts/.alpha.yml.swp": ""})
			r := tr.open(t)
			assert.Equal(t, "alpha.example.com", r.Inventory().Hosts["alpha"].Address)
		},
	)

	t.Run(
		"missing hosts.yml",
		func(t *testing.T) {
			_, err := Open(t.TempDir(), nil)
			assert.Error(t, err)
		},
	)
}

func TestOpen_hostKeys(t *testing.T) {
	key := testHostKey(t)
	keys := newTestRepo(
		t,
		map[string]string{"hosts.yml": "hosts:\n  alpha:\n    host_keys: [" + key.String() + " root@alpha]\n"},
	).open(t).Inventory().Hosts["alpha"].HostKeys
	require.Len(t, keys, 1)
	assert.Equal(t, key.Marshal(), keys[0].Marshal())
}

func TestAddHostKey(t *testing.T) {
	tests := []struct {
		name  string
		hosts string
		host  string
		want  string
	}{
		{
			name:  "block mapping keeps comments and layout",
			hosts: "# Hosts\nhosts:\n  # first\n  alpha:\n      address: a # inline\n\n  # second\n  beta:\n      address: b\n",
			host:  "alpha",
			want: "# Hosts\nhosts:\n  # first\n  alpha:\n      address: a # inline\n      host_keys:\n        - KEY\n" +
				"\n  # second\n  beta:\n      address: b\n",
		},
		{
			name:  "block scalar value",
			hosts: "hosts:\n  alpha:\n    address: |\n      a\n  beta:\n",
			host:  "alpha",
			want:  "hosts:\n  alpha:\n    address: |\n      a\n    host_keys:\n      - KEY\n  beta:\n",
		},
		{
			name:  "empty entry without trailing newline",
			hosts: "hosts:\n  alpha:\n    address: a\n  beta:",
			host:  "beta",
			want:  "hosts:\n  alpha:\n    address: a\n  beta:\n    host_keys:\n      - KEY\n",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				key := testHostKey(t)
				tr := newTestRepo(t, map[string]string{"hosts.yml": tt.hosts})
				r := tr.open(t)

				require.NoError(t, r.AddHostKey(tt.host, key.PublicKey))

				content, err := os.ReadFile(filepath.Join(tr.dir, "hosts.yml"))
				require.NoError(t, err)
				assert.Equal(t, strings.ReplaceAll(tt.want, "KEY", key.String()), string(content))
				keys := tr.open(t).Inventory().Hosts[tt.host].HostKeys
				require.Len(t, keys, 1)
				assert.Equal(t, key.Marshal(), keys[0].Marshal())
				assert.Equal(t, keys, r.Inventory().Hosts[tt.host].HostKeys)
			},
		)
	}
}

func TestAddHostKey_unsupportedLayoutIsLeftAlone(t *testing.T) {
	for _, hosts := range []string{
		"hosts:\n  alpha: {address: a}\n",
		"hosts:\n  alpha: ~\n",
		"hosts:\n  alpha:\n    host_keys: []\n",
	} {
		t.Run(
			hosts,
			func(t *testing.T) {
				key := testHostKey(t)
				tr := newTestRepo(t, map[string]string{"hosts.yml": hosts})

				err := tr.open(t).AddHostKey("alpha", key.PublicKey)

				require.ErrorContains(t, err, key.String())
				content, err := os.ReadFile(filepath.Join(tr.dir, "hosts.yml"))
				require.NoError(t, err)
				assert.Equal(t, hosts, string(content))
			},
		)
	}
}

func testHostKey(t *testing.T) HostKey {
	t.Helper()
	return HostKey{testPublicKey(t)}
}

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return key
}

func TestSecrets_encryptAndReveal(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	r := tr.open(t)

	user, err := r.Encrypt("alice")
	require.NoError(t, err)
	key, err := r.Encrypt("hunter2\nwith newline\n")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(user, "!age |\n  -----BEGIN AGE ENCRYPTED FILE-----\n"))

	writeFile(t, tr.dir, "all.yml", "dns:\n  auth_user: "+nest(user)+"\n")
	writeFile(t, tr.dir, "hosts/alpha.yml", "dns:\n  hostname: alpha.example.com\n  auth_key: "+nest(key)+"\n")

	c, err := r.HostConfig("alpha", "")
	require.NoError(t, err)
	assert.Equal(t, 0, tr.fetches)

	got, err := c.DNS.AuthUser.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "alice", got)
	got, err = c.DNS.AuthKey.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "hunter2\nwith newline\n", got)

	c, err = r.HostConfig("beta", "")
	require.NoError(t, err)
	assert.True(t, c.DNS.AuthKey.IsZero())
	_, err = c.DNS.AuthUser.Reveal()
	require.NoError(t, err)

	assert.Equal(t, 1, tr.fetches)
}

func TestSecrets_identityErrorIsCached(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	calls := 0
	r, err := Open(
		tr.dir,
		func() (age.Identity, error) {
			calls++
			return nil, errors.New("locked")
		},
	)
	require.NoError(t, err)
	enc, err := r.Encrypt("x")
	require.NoError(t, err)
	writeFile(t, tr.dir, "all.yml", "dns:\n  auth_key: "+nest(enc)+"\n  auth_user: "+nest(enc)+"\n")

	c, err := r.HostConfig("alpha", "")
	require.NoError(t, err)
	_, err = c.DNS.AuthKey.Reveal()
	require.ErrorContains(t, err, "locked")
	_, err = c.DNS.AuthUser.Reveal()
	require.ErrorContains(t, err, "locked")
	assert.Equal(t, 1, calls)
}

func TestSecrets_wrongIdentity(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	enc, err := tr.open(t).Encrypt("x")
	require.NoError(t, err)
	writeFile(t, tr.dir, "all.yml", "dns:\n  auth_key: "+nest(enc)+"\n")

	tr.identity, err = age.GenerateX25519Identity()
	require.NoError(t, err)
	c, err := tr.open(t).HostConfig("alpha", "")
	require.NoError(t, err)
	_, err = c.DNS.AuthKey.Reveal()
	assert.Error(t, err)
}

func TestSecret_zeroReveal(t *testing.T) {
	_, err := Secret{}.Reveal()
	assert.Error(t, err)
}

func TestEncrypt_noRecipients(t *testing.T) {
	_, err := newTestRepo(t, map[string]string{"secrets.yml": ""}).open(t).Encrypt("x")
	assert.Error(t, err)
}

func TestCredentials(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	r := tr.open(t)

	creds, err := r.Credentials("alpha")
	require.NoError(t, err)
	assert.Nil(t, creds)

	rotated := time.Date(2026, 10, 31, 12, 30, 0, 0, time.UTC)
	require.NoError(t, r.WriteCredentials("alpha", "old key", "old password", rotated.Add(-time.Hour)))
	require.NoError(t, r.WriteCredentials("alpha", "-----BEGIN KEY-----\nabc\n", "p@ss: word", rotated))

	path := filepath.Join(tr.dir, "credentials", "alpha.yml")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(content), "# Generated by `sensible bootstrap`"))

	// The written file must also pass Open's layout checks.
	r = tr.open(t)
	creds, err = r.Credentials("alpha")
	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.True(t, rotated.Equal(creds.Rotated))
	key, err := creds.SSHKey.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "-----BEGIN KEY-----\nabc\n", key)
	password, err := creds.SudoPassword.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "p@ss: word", password)

	require.Error(t, r.WriteCredentials("gamma", "k", "p", rotated))
	_, err = r.Credentials("../hosts")
	assert.Error(t, err)
}

func TestCredentials_plainValueRejected(t *testing.T) {
	_, err := newTestRepo(t, map[string]string{"credentials/alpha.yml": "ssh_key: secret\n"}).open(t).Credentials("alpha")
	assert.ErrorContains(t, err, "credentials/alpha.yml")
}

func TestCommandIdentity(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	got, err := newTestRepo(
		t,
		map[string]string{"secrets.yml": "identity_command: [echo, \"" + id.String() + "\"]\n"},
	).open(t).CommandIdentity()()
	require.NoError(t, err)
	assert.Equal(t, id.String(), got.(*age.X25519Identity).String())

	_, err = newTestRepo(t, map[string]string{"secrets.yml": ""}).open(t).CommandIdentity()()
	require.ErrorContains(t, err, "identity_command")

	got, err = commandIdentity("echo", "# comment\n"+id.String())()
	require.NoError(t, err)
	assert.Equal(t, id.String(), got.(*age.X25519Identity).String())

	_, err = commandIdentity("false")()
	require.Error(t, err)
	_, err = commandIdentity("echo", "not an identity")()
	assert.Error(t, err)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func nest(yaml string) string {
	return strings.ReplaceAll(yaml, "\n", "\n  ")
}

func TestHostConfig_listsReplaceBuiltInDefaults(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"all.yml":         "zsh:\n  plugins: [git, autojump]\nsshd:\n  settings:\n    MaxAuthTries: 6\n",
			"hosts/alpha.yml": "zsh:\n  plugins: [docker]\n",
		},
	).open(t).HostConfig("alpha", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"git", "autojump", "docker"}, c.Zsh.Plugins)
	assert.Equal(t, "6", c.SSHD.Settings["MaxAuthTries"])
	assert.Equal(t, "no", c.SSHD.Settings["PermitRootLogin"])
}

func TestHostConfig_unsetListsKeepBuiltInDefaults(t *testing.T) {
	c, err := newTestRepo(t, map[string]string{"all.yml": "docker:\n  users: [chris]\n"}).open(t).HostConfig("alpha", "")
	require.NoError(t, err)
	assert.Contains(t, c.Zsh.Plugins, "git")
}

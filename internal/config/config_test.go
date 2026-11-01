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
	if _, ok := files["sensible.yml"]; !ok {
		files["sensible.yml"] = "secrets:\n  recipients: [" + id.Recipient().String() + "]\n"
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

func TestHostConfig_mergesRoles(t *testing.T) {
	r := newTestRepo(
		t,
		map[string]string{
			"hosts.yml": `
hosts:
  alpha:
    roles:
      base:
      zsh: {users: [chris], prompt_colours: {chris: green}}
      tailscale: {relay_port: 40000}
  beta:
    roles:
      zsh:
      tailscale:
`,
			"roles/base/role.yml": `
packages:
  install: [vim, kitty-terminfo]
users:
  chris: {groups: [wheel]}
`,
			"roles/zsh/role.yml": `
params:
  users: [chris, root]
  prompt_colours: {chris: white, root: red}
zsh:
  users: !param users
  prompt_colours: !param prompt_colours
`,
			"roles/zsh/role.arch.yml": `
packages:
  install: [vim]
  remove: [autojump-rs]
aur:
  packages: [autojump-rs-bin]
`,
			"roles/zsh/role.debian.yml": "packages:\n  install: [autojump]\n",
			"roles/tailscale/role.yml": `
params:
  relay_port: ~
tailscale:
  settings:
    ssh: true
    relay-server-port: !param relay_port
`,
		},
	).open(t)

	c, err := r.HostConfig("alpha", "arch")
	require.NoError(t, err)
	assert.Equal(t, []string{"vim", "kitty-terminfo"}, c.Packages.Install)
	assert.Equal(t, []string{"autojump-rs"}, c.Packages.Remove)
	assert.Equal(t, []string{"autojump-rs-bin"}, c.AUR.Packages)
	assert.Equal(t, map[string]UserConfig{"chris": {Groups: []string{"wheel"}}}, c.Users)
	assert.Equal(t, []string{"chris"}, c.Zsh.Users)
	assert.Equal(t, map[string]string{"chris": "green", "root": "red"}, c.Zsh.PromptColours)
	assert.Equal(t, map[string]string{"ssh": "true", "relay-server-port": "40000"}, c.Tailscale.Settings)
	assert.Nil(t, c.SSHD)
	assert.Nil(t, c.Docker)

	c, err = r.HostConfig("beta", "debian")
	require.NoError(t, err)
	assert.Equal(t, []string{"autojump"}, c.Packages.Install)
	assert.Nil(t, c.AUR)
	assert.Equal(t, []string{"chris", "root"}, c.Zsh.Users)
	assert.Equal(t, map[string]string{"ssh": "true"}, c.Tailscale.Settings)
}

func TestHostConfig_bareModuleIsOn(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.yml":             "hosts:\n  alpha:\n    roles:\n      base:\n      docker:\n",
			"roles/base/role.yml":   "users:\n  chris:\nvim:\ndocker:\n",
			"roles/docker/role.yml": "docker:\n  users: [chris]\n",
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, map[string]UserConfig{"chris": {}}, c.Users)
	assert.Equal(t, &VimConfig{}, c.Vim)
	assert.Equal(t, []string{"chris"}, c.Docker.Users)
	assert.Nil(t, c.SSHD)
}

func TestHostConfig_noRoles(t *testing.T) {
	c, err := newTestRepo(t, map[string]string{}).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, Config{}, c)
}

func TestHostConfig_replaceTag(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.yml": "hosts:\n  alpha:\n    roles:\n      base: {colours: !replace {chris: green}}\n",
			"roles/base/role.yml": `
params:
  colours: {chris: white, root: red}
packages:
  install: [zsh, vim]
users:
  chris: {groups: [wheel]}
  root: {}
zsh:
  prompt_colours: !param colours
`,
			"roles/base/role.debian.yml": `
packages:
  install: !replace [nano]
users: !replace
  chris: {groups: [docker]}
`,
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, []string{"nano"}, c.Packages.Install)
	assert.Equal(t, map[string]UserConfig{"chris": {Groups: []string{"docker"}}}, c.Users)
	assert.Equal(t, map[string]string{"chris": "green"}, c.Zsh.PromptColours)
}

func TestHostConfig_conflictingRoles(t *testing.T) {
	files := func(second string) map[string]string {
		return map[string]string{
			"hosts.yml":          "hosts:\n  alpha:\n    roles: {one: , two: }\n",
			"roles/one/role.yml": "sshd:\n  settings: {MaxAuthTries: 4}\n  authorized_keys: {chris: [k1]}\n",
			"roles/two/role.yml": second,
		}
	}

	c, err := newTestRepo(
		t,
		files("sshd:\n  settings: {MaxAuthTries: \"4\", LogLevel: VERBOSE}\n  authorized_keys: {chris: [k2]}\n"),
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"MaxAuthTries": "4", "LogLevel": "VERBOSE"}, c.SSHD.Settings)
	assert.Equal(t, []string{"k1", "k2"}, c.SSHD.AuthorizedKeys["chris"])

	_, err = newTestRepo(t, files("sshd:\n  settings: {MaxAuthTries: 6}\n")).open(t).HostConfig("alpha", "debian")
	assert.ErrorContains(t, err, "roles one and two set sshd.settings.MaxAuthTries differently")
}

func TestHostConfig_errors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name:  "unknown key",
			files: map[string]string{"roles/base/role.debian.yml": "packages:\n  install: [a]\n  instal: [b]\n"},
			want:  []string{"roles/base/role.debian.yml", "[3:3]", "instal"},
		},
		{
			name:  "unknown key under replace",
			files: map[string]string{"roles/base/role.debian.yml": "sshd: !replace\n  setting: {}\n"},
			want:  []string{"roles/base/role.debian.yml", "setting"},
		},
		{
			name:  "unknown module",
			files: map[string]string{"roles/base/role.yml": "sshd:\n  settings: {}\nfoo: bar\n"},
			want:  []string{"roles/base/role.yml", "foo"},
		},
		{
			name:  "unknown parameter",
			files: map[string]string{"hosts.yml": "hosts:\n  alpha:\n    roles:\n      base: {colour: red}\n"},
			want:  []string{"hosts.yml", "[4:14]", `unknown parameter "colour"`},
		},
		{
			name:  "undeclared parameter",
			files: map[string]string{"roles/base/role.yml": "zsh:\n  plugins: !param plugins\n"},
			want:  []string{"roles/base/role.yml", "[2:12]", `unknown parameter "plugins"`},
		},
		{
			name:  "params not a mapping",
			files: map[string]string{"roles/base/role.yml": "params: [a]\n"},
			want:  []string{"roles/base/role.yml", "params must be a mapping"},
		},
		{
			name:  "syntax error",
			files: map[string]string{"roles/base/role.yml": "users: [\n"},
			want:  []string{"roles/base/role.yml"},
		},
		{
			name:  "not a mapping",
			files: map[string]string{"roles/base/role.yml": "- a\n- b\n"},
			want:  []string{"roles/base/role.yml", "mapping"},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				if _, ok := tt.files["hosts.yml"]; !ok {
					tt.files["hosts.yml"] = "hosts:\n  alpha:\n    roles: {base: }\n"
				}
				if _, ok := tt.files["roles/base/role.yml"]; !ok {
					tt.files["roles/base/role.yml"] = ""
				}
				_, err := newTestRepo(t, tt.files).open(t).HostConfig("alpha", "debian")
				require.Error(t, err)
				for _, w := range tt.want {
					assert.Contains(t, err.Error(), w)
				}
				assert.Contains(t, err.Error(), "role base")
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
		{"credentials for unknown host", map[string]string{"credentials/gamma.yml": ""}, "gamma"},
		{"wrong extension", map[string]string{"credentials/alpha.yaml": ""}, "alpha.yaml"},
		{"unknown inventory key", map[string]string{"hosts.yml": "hosts:\n  a: {addr: x}\n"}, "addr"},
		{"invalid host key", map[string]string{"hosts.yml": "hosts:\n  a: {host_keys: [ssh-ed25519 nope]}\n"}, "host key"},
		{"role parameters not a mapping", map[string]string{"hosts.yml": "hosts:\n  a: {roles: {base: [x]}}\n"}, "mapping"},
		{"unknown role", map[string]string{"hosts.yml": "hosts:\n  a: {roles: {base: }}\n"}, `role "base"`},
		{"file in roles", map[string]string{"roles/base.yml": ""}, "base.yml"},
		{"missing role.yml", map[string]string{"roles/base/role.arch.yml": ""}, "missing role.yml"},
		{"unknown OS", map[string]string{"roles/base/role.yml": "", "roles/base/role.archlinux.yml": ""}, `"archlinux"`},
		{"unexpected role file", map[string]string{"roles/base/role.yml": "", "roles/base/notes.txt": ""}, "notes.txt"},
		{"bad recipient", map[string]string{"sensible.yml": "secrets:\n  recipients: [nope]\n"}, "recipients"},
		{"unknown settings key", map[string]string{"sensible.yml": "identity: op://x\n"}, "identity"},
		{"plain DNS secret", map[string]string{"sensible.yml": "dns:\n  auth_key: hunter2\n"}, "encrypt"},
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
			assert.Equal(
				t,
				"alpha.example.com",
				newTestRepo(
					t,
					map[string]string{
						"roles/base/role.yml":        "",
						"roles/base/role.arch.yml":   "",
						"roles/base/.role.yml.swp":   "",
						"credentials/.alpha.yml.swp": "",
					},
				).open(t).Inventory().Hosts["alpha"].Address,
			)
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
			name:  "roles block",
			hosts: "hosts:\n  alpha:\n    address: a\n    roles:\n      base:\n      zsh: {users: [chris]}\n  beta:\n",
			host:  "alpha",
			want: "hosts:\n  alpha:\n    address: a\n    roles:\n      base:\n      zsh: {users: [chris]}\n" +
				"    host_keys:\n      - KEY\n  beta:\n",
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
				tr := newTestRepo(
					t,
					map[string]string{"hosts.yml": tt.hosts, "roles/base/role.yml": "", "roles/zsh/role.yml": ""},
				)
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

	settings, err := os.ReadFile(filepath.Join(tr.dir, "sensible.yml"))
	require.NoError(t, err)
	writeFile(t, tr.dir, "sensible.yml", string(settings)+"dns:\n  auth_user: "+nest(user)+"\n  auth_key: "+nest(key)+"\n")
	r = tr.open(t)
	assert.Equal(t, 0, tr.fetches)

	got, err := r.DNS().AuthUser.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "alice", got)
	got, err = r.DNS().AuthKey.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "hunter2\nwith newline\n", got)
	assert.Equal(t, 1, tr.fetches)
}

func TestSecrets_identityErrorIsCached(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	enc, err := tr.open(t).Encrypt("x")
	require.NoError(t, err)
	writeFile(t, tr.dir, "sensible.yml", "dns:\n  auth_key: "+nest(enc)+"\n  auth_user: "+nest(enc)+"\n")

	calls := 0
	r, err := Open(
		tr.dir,
		func() (age.Identity, error) {
			calls++
			return nil, errors.New("locked")
		},
	)
	require.NoError(t, err)
	_, err = r.DNS().AuthKey.Reveal()
	require.ErrorContains(t, err, "locked")
	_, err = r.DNS().AuthUser.Reveal()
	require.ErrorContains(t, err, "locked")
	assert.Equal(t, 1, calls)
}

func TestSecrets_wrongIdentity(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	enc, err := tr.open(t).Encrypt("x")
	require.NoError(t, err)
	writeFile(t, tr.dir, "sensible.yml", "dns:\n  auth_key: "+nest(enc)+"\n")

	tr.identity, err = age.GenerateX25519Identity()
	require.NoError(t, err)
	_, err = tr.open(t).DNS().AuthKey.Reveal()
	assert.Error(t, err)
}

func TestSecret_zeroReveal(t *testing.T) {
	_, err := Secret{}.Reveal()
	assert.Error(t, err)
}

func TestEncrypt_noRecipients(t *testing.T) {
	_, err := newTestRepo(t, map[string]string{"sensible.yml": ""}).open(t).Encrypt("x")
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
		map[string]string{"sensible.yml": "secrets:\n  identity_command: [echo, \"" + id.String() + "\"]\n"},
	).open(t).CommandIdentity()()
	require.NoError(t, err)
	assert.Equal(t, id.String(), got.(*age.X25519Identity).String())

	_, err = newTestRepo(t, map[string]string{"sensible.yml": ""}).open(t).CommandIdentity()()
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

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
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

	if _, ok := files["hosts.d/hosts.yml"]; !ok {
		files["hosts.d/hosts.yml"] = "alpha:\n  address: alpha.example.com\nbeta: {}\n"
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
			"hosts.d/hosts.yml": `
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
	assert.Equal(t, Set{"vim", "kitty-terminfo"}, c.Packages.Install)
	assert.Equal(t, Set{"autojump-rs"}, c.Packages.Remove)
	assert.Equal(t, Set{"autojump-rs-bin"}, c.AUR.Packages)
	assert.Equal(t, map[string]UserConfig{"chris": {Groups: []string{"wheel"}}}, c.Users)
	assert.Equal(t, Set{"chris"}, c.Zsh.Users)
	assert.Equal(t, map[string]string{"chris": "green", "root": "red"}, c.Zsh.PromptColours)
	assert.Equal(t, map[string]string{"ssh": "true", "relay-server-port": "40000"}, c.Tailscale.Settings)
	assert.Nil(t, c.SSHD)
	assert.Nil(t, c.Docker)

	c, err = r.HostConfig("beta", "debian")
	require.NoError(t, err)
	assert.Equal(t, Set{"autojump"}, c.Packages.Install)
	assert.Nil(t, c.AUR)
	assert.Equal(t, Set{"chris", "root"}, c.Zsh.Users)
	assert.Equal(t, map[string]string{"ssh": "true"}, c.Tailscale.Settings)
}

func TestHostConfig_roleGroups(t *testing.T) {
	r := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": `
alpha:
  roles:
    stacks: {users: [chris]}
beta:
  roles:
    stacks/one:
    bare:
`,
			"roles/stacks/role.yml":          "children: [one, two]\nparams:\n  users: []\ndocker:\n  users: !param users\n",
			"roles/stacks/one/role.yml":      "packages:\n  install: [a]\n",
			"roles/stacks/two/role.yml":      "packages:\n  install: [b]\n",
			"roles/stacks/two/role.arch.yml": "aur:\n  packages: [c]\n",
			"roles/bare/role.yml":            "children: [child]\n",
			"roles/bare/child/role.yml":      "vim:\n",
		},
	).open(t)

	c, err := r.HostConfig("alpha", "arch")
	require.NoError(t, err)
	assert.Equal(t, Set{"chris"}, c.Docker.Users)
	assert.ElementsMatch(t, []string{"a", "b"}, c.Packages.Install)
	assert.Equal(t, Set{"c"}, c.AUR.Packages)
	assert.Nil(t, c.Vim)

	c, err = r.HostConfig("beta", "arch")
	require.NoError(t, err)
	assert.Equal(t, Set{"a"}, c.Packages.Install)
	assert.Nil(t, c.Docker)
	assert.Nil(t, c.AUR)
	assert.NotNil(t, c.Vim)
}

func TestHostConfig_parentParamsDontReachChildren(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":         "alpha:\n  roles:\n    stacks: {users: [chris]}\n",
			"roles/stacks/role.yml":     "children: [one]\n",
			"roles/stacks/one/role.yml": "params:\n  users: []\ndocker:\n  users: !param users\n",
		},
	).open(t).HostConfig("alpha", "debian")
	require.ErrorContains(t, err, "role stacks:")
	assert.ErrorContains(t, err, `unknown parameter "users"`)
}

func TestHostConfig_bareModuleIsOn(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":     "alpha:\n  roles:\n    base:\n    docker:\n",
			"roles/base/role.yml":   "users:\n  chris:\nvim:\ndocker:\n",
			"roles/docker/role.yml": "docker:\n  users: [chris]\n",
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, map[string]UserConfig{"chris": {}}, c.Users)
	assert.Equal(t, &VimConfig{}, c.Vim)
	assert.Equal(t, Set{"chris"}, c.Docker.Users)
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
			"hosts.d/hosts.yml": "alpha:\n  roles:\n    base: {colours: !replace {chris: green}}\n",
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
	assert.Equal(t, Set{"nano"}, c.Packages.Install)
	assert.Equal(t, map[string]UserConfig{"chris": {Groups: []string{"docker"}}}, c.Users)
	assert.Equal(t, map[string]string{"chris": "green"}, c.Zsh.PromptColours)
}

func TestHostConfig_dockerDaemon(t *testing.T) {
	role := `
params:
  daemon:
    log-driver: local
    log-opts: {max-size: 10m, max-file: "3"}
    dns: [192.0.2.1, 192.0.2.2]
    live-restore: true
docker:
  daemon: !param daemon
`
	tests := []struct {
		name  string
		roles string
		want  map[string]any
	}{
		{
			name:  "defaults",
			roles: "docker:",
			want: map[string]any{
				"log-driver":   "local",
				"log-opts":     map[string]any{"max-size": "10m", "max-file": "3"},
				"dns":          []any{"192.0.2.1", "192.0.2.2"},
				"live-restore": true,
			},
		},
		{
			name:  "host overrides single settings and replaces lists",
			roles: "docker: {daemon: {log-opts: {max-size: 50m}, dns: [192.0.2.9], debug: true}}",
			want: map[string]any{
				"log-driver":   "local",
				"log-opts":     map[string]any{"max-size": "50m", "max-file": "3"},
				"dns":          []any{"192.0.2.9"},
				"live-restore": true,
				"debug":        true,
			},
		},
		{
			name:  "host replaces everything",
			roles: "docker: {daemon: !replace {debug: true}}",
			want:  map[string]any{"debug": true},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				c, err := newTestRepo(
					t,
					map[string]string{
						"hosts.d/hosts.yml":     "alpha:\n  roles: {" + tt.roles + "}\n",
						"roles/docker/role.yml": role,
					},
				).open(t).HostConfig("alpha", "debian")
				require.NoError(t, err)
				require.NotNil(t, c.Docker)
				assert.Equal(t, tt.want, c.Docker.Daemon)
			},
		)
	}
}

func TestHostConfig_dockerDaemonConflict(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {a:, b:}\n",
			"roles/a/role.yml":  "docker: {daemon: {log-driver: local}}\n",
			"roles/b/role.yml":  "docker: {daemon: {log-driver: journald}}\n",
		},
	).open(t).HostConfig("alpha", "debian")
	assert.ErrorContains(t, err, "docker.daemon.log-driver")
}

func TestHostConfig_conflictingRoles(t *testing.T) {
	files := func(second string) map[string]string {
		return map[string]string{
			"hosts.d/hosts.yml":  "alpha:\n  roles: {one: , two: }\n",
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
	assert.Equal(t, Set{"k1", "k2"}, c.SSHD.AuthorizedKeys["chris"])

	_, err = newTestRepo(t, files("sshd:\n  settings: {MaxAuthTries: 6}\n")).open(t).HostConfig("alpha", "debian")
	assert.ErrorContains(t, err, "role one and role two set sshd.settings.MaxAuthTries differently")
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
			files: map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles:\n    base: {colour: red}\n"},
			want:  []string{"hosts.d/hosts.yml", "[3:12]", `unknown parameter "colour"`},
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
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				if _, ok := tt.files["hosts.d/hosts.yml"]; !ok {
					tt.files["hosts.d/hosts.yml"] = "alpha:\n  roles: {base: }\n"
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
		{"wrong extension", map[string]string{"hosts.d/alpha.yaml": ""}, "alpha.yaml"},
		{"directory in hosts.d", map[string]string{"hosts.d/old/alpha.yml": ""}, "old"},
		{"unknown inventory key", map[string]string{"hosts.d/hosts.yml": "a: {addr: x}\n"}, "addr"},
		{"error names its file", map[string]string{"hosts.d/extra.yml": "alpha: {addr: x}\n"}, "hosts.d/extra.yml"},
		{"not a mapping", map[string]string{"hosts.d/extra.yml": "- alpha\n"}, "hosts.d/extra.yml"},
		{
			"invalid host key",
			map[string]string{"hosts.d/hosts.yml": "a: {host_keys: [ssh-ed25519 nope]}\n"},
			"host key",
		},
		{"plain credential", map[string]string{"hosts.d/hosts.yml": "a: {ssh_key: hunter2}\n"}, "encrypt"},
		{
			"role parameters not a mapping",
			map[string]string{"hosts.d/hosts.yml": "a: {roles: {base: [x]}}\n"},
			"mapping",
		},
		{"unknown role", map[string]string{"hosts.d/hosts.yml": "a: {roles: {base: }}\n"}, `role "base"`},
		{"file in roles", map[string]string{"roles/base.yml": ""}, "base.yml"},
		{"missing role.yml", map[string]string{"roles/base/role.arch.yml": ""}, "missing role.yml"},
		{
			"unknown OS",
			map[string]string{"roles/base/role.yml": "", "roles/base/role.archlinux.yml": ""},
			`"archlinux"`,
		},
		{"unexpected role file", map[string]string{"roles/base/role.yml": "", "roles/base/notes.txt": ""}, "notes.txt"},
		{"syntax error", map[string]string{"roles/base/role.yml": "users: [\n"}, "roles/base/role.yml"},
		{"role not a mapping", map[string]string{"roles/base/role.yml": "- a\n- b\n"}, "mapping"},
		{
			"child role missing role.yml",
			map[string]string{"roles/base/role.yml": "children: [child]\n", "roles/base/child/role.arch.yml": ""},
			"roles/base/child: missing role.yml",
		},
		{
			"empty child role",
			map[string]string{"roles/base/role.yml": "children: [child]\n", "roles/base/child/.keep": ""},
			"roles/base/child: missing role.yml",
		},
		{
			"grandchild role",
			map[string]string{
				"roles/base/role.yml":              "children: [child]\n",
				"roles/base/child/role.yml":        "children: [deeper]\n",
				"roles/base/child/deeper/role.yml": "",
			},
			"roles nest one level deep",
		},
		{
			"undeclared child",
			map[string]string{"roles/base/role.yml": "", "roles/base/child/role.yml": ""},
			"roles/base/child: unexpected directory",
		},
		{
			"child isn't a directory",
			map[string]string{"roles/base/role.yml": "children: [child]\n"},
			`"child" isn't a directory`,
		},
		{
			"parent without role.yml",
			map[string]string{"roles/base/child/role.yml": ""},
			"roles/base/child: unexpected directory",
		},
		{
			"unknown child role",
			map[string]string{
				"hosts.d/hosts.yml":       "a: {roles: {base/two: }}\n",
				"roles/base/role.yml":     "children: [one]\n",
				"roles/base/one/role.yml": "",
			},
			`role "base/two"`,
		},
		{
			"role and its parent",
			map[string]string{
				"hosts.d/hosts.yml":       "a: {roles: {base: , base/one: }}\n",
				"roles/base/role.yml":     "children: [one]\n",
				"roles/base/one/role.yml": "",
			},
			`a has role "base/one" and its parent "base"`,
		},
		{
			"compose settings without a compose file",
			map[string]string{"roles/web/role.yml": "compose:\n  files: [a]\n", "roles/web/a": ""},
			"compose.files needs a docker-compose.yml",
		},
		{
			"unlisted stack file",
			map[string]string{"roles/web/docker-compose.yml": "", "roles/web/nginx.conf": ""},
			"roles/web/nginx.conf: unexpected file",
		},
		{
			"unlisted stack directory",
			map[string]string{"roles/web/docker-compose.yml": "", "roles/web/conf/a": ""},
			"roles/web/conf: unexpected directory",
		},
		{
			"missing stack file",
			map[string]string{"roles/web/docker-compose.yml": "", "roles/web/role.yml": "compose:\n  files: [a]\n"},
			"compose.files",
		},
		{
			"stack file outside the role",
			map[string]string{
				"roles/web/docker-compose.yml": "",
				"roles/web/role.yml":           "compose:\n  files: [../other/role.yml]\n",
				"roles/other/role.yml":         "",
			},
			"isn't a path inside the role",
		},
		{
			"stack copies its role file",
			map[string]string{"roles/web/docker-compose.yml": "", "roles/web/role.yml": "compose:\n  files: [role.yml]\n"},
			"read by sensible",
		},
		{
			"stack file and its encrypted copy",
			map[string]string{
				"roles/web/docker-compose.yml": "",
				"roles/web/role.yml":           "compose:\n  files: [.env, .env.age]\n",
				"roles/web/.env":               "",
				"roles/web/.env.age":           "",
			},
			"would both be written as .env",
		},
		{
			"stack file listed with different modes",
			map[string]string{
				"roles/web/docker-compose.yml": "",
				"roles/web/role.yml":           "compose:\n  files: [conf, {path: conf/a, mode: 0o600}]\n",
				"roles/web/conf/a":             "",
			},
			"conf/a is listed more than once",
		},
		{
			"stack file without a path",
			map[string]string{"roles/web/docker-compose.yml": "", "roles/web/role.yml": "compose:\n  files: [{mode: 0o600}]\n"},
			"a file needs a path",
		},
		{
			"invalid project name",
			map[string]string{"roles/Web/docker-compose.yml": ""},
			"can't be a Docker Compose project name",
		},
		{
			"stacks with the same project name",
			map[string]string{
				"roles/a-b/role.yml":           "compose:\n  volumes: {data: }\n",
				"roles/a/role.yml":             "children: [b]\n",
				"roles/a/b/docker-compose.yml": "",
			},
			`would both use the stack name "a-b"`,
		},
		{
			"invalid volume name",
			map[string]string{
				"roles/web/docker-compose.yml": "",
				"roles/web/role.yml":           "compose:\n  volumes:\n    a/b: {}\n",
			},
			`invalid volume name "a/b"`,
		},
		{
			"stack OS variant without base",
			map[string]string{"roles/web/docker-compose.yml": "", "roles/web/role.arch.yml": ""},
			"roles/web: missing role.yml",
		},
		{"bad recipient", map[string]string{"sensible.yml": "secrets:\n  recipients: [nope]\n"}, "recipients"},
		{"unknown settings key", map[string]string{"sensible.yml": "identity: op://x\n"}, "identity"},
		{
			"plain DNS secret",
			map[string]string{"sensible.yml": "dns:\n  provider: mydnshost\n  mydnshost:\n    auth_key: hunter2\n"},
			"encrypt",
		},
		{
			"DNS without a provider",
			map[string]string{"sensible.yml": "dns:\n  vhosts:\n    - {type: CNAME, content: '{host}'}\n"},
			"sensible.yml: dns.provider isn't set",
		},
		{"unknown DNS provider", map[string]string{"sensible.yml": "dns:\n  provider: nope\n"}, `unknown provider "nope"`},
		{
			"MyDNSHost without credentials",
			map[string]string{"sensible.yml": "dns:\n  provider: mydnshost\n"},
			"dns.mydnshost: needs an auth_user and auth_key",
		},
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
						"roles/base/role.yml":       "",
						"roles/base/role.arch.yml":  "",
						"roles/base/.role.yml.swp":  "",
						"hosts.d/.alpha.yml.swp":    "",
						"hosts.d/empty.yml":         "",
						"hosts.d/alpha.address.yml": "alpha:\n  address: alpha.example.com\n",
					},
				).open(t).Inventory().Hosts["alpha"].Address,
			)
		},
	)

	t.Run(
		"missing hosts.d",
		func(t *testing.T) {
			_, err := Open(t.TempDir(), nil)
			assert.Error(t, err)
		},
	)
}

func TestOpen_mergesFragments(t *testing.T) {
	k1, k2 := testHostKey(t), testHostKey(t)
	inv := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":         "alpha:\n  address: a\n  host_keys: [" + k1.String() + "]\n  roles: {base: }\nbeta:\n",
			"hosts.d/alpha.zsh.yml":     "alpha:\n  roles:\n    zsh: {colours: !replace {chris: green}}\n",
			"hosts.d/alpha.state.yml":   "alpha:\n  host_keys: [" + k1.String() + ", " + k2.String() + "]\n",
			"hosts.d/everything.yml":    "alpha:\n  address: a\ngamma:\n  address: g\n",
			"roles/base/role.yml":       "",
			"roles/zsh/role.yml":        "params:\n  colours: {}\nzsh:\n  prompt_colours: !param colours\n",
			"roles/zsh/role.debian.yml": "",
		},
	).open(t).Inventory()

	assert.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, slices.Collect(maps.Keys(inv.Hosts)))
	alpha := inv.Hosts["alpha"]
	assert.Equal(t, "a", alpha.Address)
	assert.ElementsMatch(t, []string{"base", "zsh"}, slices.Collect(maps.Keys(alpha.Roles)))
	require.Len(t, alpha.HostKeys, 2)
	assert.Equal(t, k1.Marshal(), alpha.HostKeys[0].Marshal())
	assert.Equal(t, k2.Marshal(), alpha.HostKeys[1].Marshal())
	assert.Equal(t, "g", inv.Hosts["gamma"].Address)
}

func TestOpen_conflictingFragments(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{"hosts.d/extra.yml": "alpha:\n  address: elsewhere\n"},
	).tryOpen()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hosts.d/extra.yml")
	assert.Contains(t, err.Error(), "hosts.d/hosts.yml")
	assert.Contains(t, err.Error(), "alpha.address")
}

func TestHostConfig_paramErrorNamesFragment(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":   "alpha:\n  roles: {base: }\n",
			"hosts.d/alpha.yml":   "alpha:\n  roles:\n    base: {colour: red}\n",
			"roles/base/role.yml": "",
		},
	).open(t).HostConfig("alpha", "debian")
	assert.ErrorContains(t, err, "hosts.d/alpha.yml: [3:12] unknown parameter")
}

func TestCredentials(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	r := tr.open(t)
	assert.True(t, r.Inventory().Hosts["alpha"].SSHKey.IsZero())

	rotated := time.Date(2026, 10, 31, 12, 30, 0, 0, time.UTC)
	require.NoError(t, r.WriteCredentials("alpha", "old key", "old password", rotated.Add(-time.Hour)))
	require.NoError(t, r.WriteCredentials("alpha", "-----BEGIN KEY-----\nabc\n", "p@ss: word", rotated))

	path := filepath.Join(tr.dir, "hosts.d", "alpha.state.yml")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	for _, r := range []*Repo{r, tr.open(t)} {
		alpha := r.Inventory().Hosts["alpha"]
		assert.Equal(t, "alpha.example.com", alpha.Address)
		assert.True(t, rotated.Equal(alpha.Rotated))
		key, err := alpha.SSHKey.Reveal()
		require.NoError(t, err)
		assert.Equal(t, "-----BEGIN KEY-----\nabc\n", key)
		password, err := alpha.SudoPassword.Reveal()
		require.NoError(t, err)
		assert.Equal(t, "p@ss: word", password)
	}

	require.Error(t, r.WriteCredentials("gamma", "k", "p", rotated))
}

func TestStateFile_keepsWhatItDoesNotChange(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	r := tr.open(t)
	k1, k2 := testHostKey(t), testHostKey(t)
	rotated := time.Date(2026, 10, 31, 12, 30, 0, 0, time.UTC)

	require.NoError(t, r.AddHostKey("alpha", k1.PublicKey))
	require.NoError(t, r.WriteCredentials("alpha", "key", "password", rotated))
	require.NoError(t, r.AddHostKey("alpha", k2.PublicKey))

	alpha := tr.open(t).Inventory().Hosts["alpha"]
	require.Len(t, alpha.HostKeys, 2)
	assert.Equal(t, k1.Marshal(), alpha.HostKeys[0].Marshal())
	assert.Equal(t, k2.Marshal(), alpha.HostKeys[1].Marshal())
	key, err := alpha.SSHKey.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "key", key)
	assert.Equal(t, alpha.HostKeys, r.Inventory().Hosts["alpha"].HostKeys)
}

func TestAddHostKey_addsToHandWrittenKeys(t *testing.T) {
	k1, k2 := testHostKey(t), testHostKey(t)
	tr := newTestRepo(t, map[string]string{"hosts.d/hosts.yml": "alpha:\n  host_keys: [" + k1.String() + "]\n"})

	require.NoError(t, tr.open(t).AddHostKey("alpha", k2.PublicKey))

	hostKeys := tr.open(t).Inventory().Hosts["alpha"].HostKeys
	keys := make([]string, 0, len(hostKeys))
	for _, k := range hostKeys {
		keys = append(keys, k.String())
	}
	assert.ElementsMatch(t, []string{k1.String(), k2.String()}, keys)
}

func TestAddHostKey_unreadableStateFile(t *testing.T) {
	key := testHostKey(t)
	state := "alpha:\n  address: alpha.example.com\n"
	tr := newTestRepo(t, map[string]string{"hosts.d/alpha.state.yml": state})

	err := tr.open(t).AddHostKey("alpha", key.PublicKey)

	require.ErrorContains(t, err, key.String())
	content, err := os.ReadFile(filepath.Join(tr.dir, "hosts.d", "alpha.state.yml"))
	require.NoError(t, err)
	assert.Equal(t, state, string(content))
}

func TestWriteCredentials_refusedWhenSetElsewhere(t *testing.T) {
	tr := newTestRepo(t, map[string]string{"hosts.d/hosts.yml": "alpha:\n  rotated: 2026-01-01T00:00:00Z\n"})

	err := tr.open(t).WriteCredentials("alpha", "k", "p", time.Now())

	require.ErrorContains(t, err, "hosts.d/hosts.yml")
	assert.NoFileExists(t, filepath.Join(tr.dir, "hosts.d", "alpha.state.yml"))
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
	writeFile(t, tr.dir, "sensible.yml", string(settings)+myDNSHostSettings(user, key))
	r = tr.open(t)
	assert.Equal(t, 0, tr.fetches)

	got, err := r.DNS().MyDNSHost.AuthUser.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "alice", got)
	got, err = r.DNS().MyDNSHost.AuthKey.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "hunter2\nwith newline\n", got)
	assert.Equal(t, 1, tr.fetches)
}

func TestSecrets_identityErrorIsCached(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	enc, err := tr.open(t).Encrypt("x")
	require.NoError(t, err)
	writeFile(t, tr.dir, "sensible.yml", myDNSHostSettings(enc, enc))

	calls := 0
	r, err := Open(
		tr.dir,
		func() (age.Identity, error) {
			calls++
			return nil, errors.New("locked")
		},
	)
	require.NoError(t, err)
	_, err = r.DNS().MyDNSHost.AuthKey.Reveal()
	require.ErrorContains(t, err, "locked")
	_, err = r.DNS().MyDNSHost.AuthUser.Reveal()
	require.ErrorContains(t, err, "locked")
	assert.Equal(t, 1, calls)
}

func TestSecrets_wrongIdentity(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	enc, err := tr.open(t).Encrypt("x")
	require.NoError(t, err)
	writeFile(t, tr.dir, "sensible.yml", myDNSHostSettings(enc, enc))

	tr.identity, err = age.GenerateX25519Identity()
	require.NoError(t, err)
	_, err = tr.open(t).DNS().MyDNSHost.AuthKey.Reveal()
	assert.Error(t, err)
}

func TestPreview_secretsWithoutIdentityArePlaceholders(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	user, err := tr.open(t).Encrypt("alice")
	require.NoError(t, err)
	key, err := tr.open(t).Encrypt("hunter2")
	require.NoError(t, err)
	writeFile(t, tr.dir, "sensible.yml", myDNSHostSettings(user, key))

	r, err := Open(tr.dir, func() (age.Identity, error) { return nil, errors.New("locked") })
	require.NoError(t, err)
	var warnings []string
	r.Preview(func(msg string) { warnings = append(warnings, msg) })

	gotUser, err := r.DNS().MyDNSHost.AuthUser.Reveal()
	require.NoError(t, err)
	gotKey, err := r.DNS().MyDNSHost.AuthKey.Reveal()
	require.NoError(t, err)
	assert.Regexp(t, `^<age:[0-9a-f]{8}>$`, gotUser)
	assert.Equal(t, r.DNS().MyDNSHost.AuthUser.Placeholder(), gotUser)
	assert.NotEqual(t, gotUser, gotKey)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "locked")

	// The same ciphertext written elsewhere, differently indented, has the
	// same placeholder.
	writeFile(
		t,
		tr.dir,
		"sensible.yml",
		"dns:\n    provider: mydnshost\n    mydnshost:\n        auth_user: "+indent(user, "          ")+
			"\n        auth_key: "+indent(key, "          ")+"\n",
	)
	again, err := Open(tr.dir, func() (age.Identity, error) { return nil, errors.New("locked") })
	require.NoError(t, err)
	assert.Equal(t, gotUser, again.DNS().MyDNSHost.AuthUser.Placeholder())
}

func TestPreview_secretsForAnotherIdentityArePlaceholders(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	r := tr.open(t)
	r.recipients = []age.Recipient{other.Recipient()}
	foreign, err := r.Encrypt("theirs")
	require.NoError(t, err)
	mine, err := tr.open(t).Encrypt("mine")
	require.NoError(t, err)
	writeFile(t, tr.dir, "sensible.yml", myDNSHostSettings(foreign, mine))

	r = tr.open(t)
	var warnings []string
	r.Preview(func(msg string) { warnings = append(warnings, msg) })

	got, err := r.DNS().MyDNSHost.AuthUser.Reveal()
	require.NoError(t, err)
	assert.Equal(t, r.DNS().MyDNSHost.AuthUser.Placeholder(), got)
	got, err = r.DNS().MyDNSHost.AuthKey.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "mine", got)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], r.DNS().MyDNSHost.AuthUser.Placeholder())
}

func TestSecret_zeroReveal(t *testing.T) {
	_, err := Secret{}.Reveal()
	assert.Error(t, err)
}

func TestEncrypt_noRecipients(t *testing.T) {
	_, err := newTestRepo(t, map[string]string{"sensible.yml": ""}).open(t).Encrypt("x")
	assert.Error(t, err)
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
	_, err = commandIdentity("sh", "-c", "echo 'account locked' >&2; exit 1")()
	require.ErrorContains(t, err, "account locked")
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

func myDNSHostSettings(user, key string) string {
	return "dns:\n  provider: mydnshost\n  mydnshost:\n    auth_user: " + indent(user, "    ") +
		"\n    auth_key: " + indent(key, "    ") + "\n"
}

func TestHostConfig_dockerNetworks(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles:\n    a:\n    b:\n",
			"roles/a/role.yml":  "docker:\n  networks:\n    web:\n",
			"roles/b/role.yml":  "docker:\n  networks:\n    six: {ipv6: true, subnets: ['fd00:dead:beef::/48']}\n",
		},
	).open(t).HostConfig("alpha", "debian")

	require.NoError(t, err)
	assert.Equal(
		t,
		map[string]DockerNetworkConfig{"web": {}, "six": {IPv6: true, Subnets: []string{"fd00:dead:beef::/48"}}},
		c.Docker.Networks,
	)
}

func TestHostConfig_commands(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {a: , b: }\n",
			"roles/a/role.yml": `
params:
  copy: [cp, x, x]
jobs:
  copy: {command: !param copy, schedule: daily}
  sync: {command: [rsync, -a, src, dst], schedule: daily}
packages:
  install: [git, vim, git]
`,
			"roles/a/role.arch.yml": "jobs:\n  sync:\n    command: [rsync, -a, src, other]\n",
			"roles/b/role.yml": `
jobs:
  copy: {command: [cp, x, x]}
packages:
  install: [vim, curl]
`,
		},
	).open(t).HostConfig("alpha", "arch")
	require.NoError(t, err)
	assert.Equal(t, Command{"cp", "x", "x"}, c.Jobs["copy"].Command)
	assert.Equal(t, Command{"rsync", "-a", "src", "other"}, c.Jobs["sync"].Command)
	assert.Equal(t, Set{"git", "vim", "curl"}, c.Packages.Install)
}

func TestHostConfig_conflictingCommands(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {a: , b: }\n",
			"roles/a/role.yml":  "jobs:\n  copy: {command: [cp, x, y], schedule: daily}\n",
			"roles/b/role.yml":  "jobs:\n  copy: {command: [cp, x]}\n",
		},
	).open(t).HostConfig("alpha", "debian")
	assert.ErrorContains(t, err, "role a and role b set jobs.copy.command differently")
}

func newBackupsRepo(t *testing.T) *testRepo {
	t.Helper()
	return newTestRepo(
		t,
		map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {backups: }\n", "roles/backups/role.yml": ""},
	)
}

func TestHostConfig_resticEnv(t *testing.T) {
	tr := newBackupsRepo(t)
	password, err := tr.open(t).Encrypt("hunter2")
	require.NoError(t, err)
	key, err := tr.open(t).Encrypt("b2key")
	require.NoError(t, err)
	writeFile(
		t,
		tr.dir,
		"roles/backups/role.yml",
		"restic:\n  repository: rclone:b2:backups\n  password: "+nest(password)+"\n"+
			"  environment:\n"+
			"    RCLONE_CONFIG_B2_TYPE: b2\n"+
			"    RCLONE_CONFIG_B2_HARD_DELETE: false\n"+
			"    RCLONE_CONFIG_B2_KEY: "+nest(nest(key))+"\n",
	)

	c, err := tr.open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(
		t,
		map[string]string{
			"RESTIC_REPOSITORY":            "rclone:b2:backups",
			"RESTIC_PASSWORD":              "hunter2",
			"RCLONE_CONFIG_B2_TYPE":        "b2",
			"RCLONE_CONFIG_B2_HARD_DELETE": "false",
			"RCLONE_CONFIG_B2_KEY":         "b2key",
		},
		c.Restic.Env,
	)
	assert.ElementsMatch(t, []string{"hunter2", "b2key"}, c.Restic.Secrets)
}

func TestHostConfig_resticErrors(t *testing.T) {
	tests := []struct {
		name, restic, want string
	}{
		{"no repository", "restic:\n  password: PASSWORD\n", "restic needs a repository"},
		{"no password", "restic:\n  repository: r\n", "restic.password: secret is not set"},
		{"plain password", "restic:\n  repository: r\n  password: hunter2\n", "secrets must be encrypted"},
		{
			"environment overriding restic's",
			"restic:\n  repository: r\n  password: PASSWORD\n  environment: {RESTIC_REPOSITORY: other}\n",
			"RESTIC_REPOSITORY is set from restic's own settings",
		},
		{
			"environment that isn't a scalar",
			"restic:\n  repository: r\n  password: PASSWORD\n  environment: {A: [b]}\n",
			"expected a scalar or an !age secret",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				tr := newBackupsRepo(t)
				password, err := tr.open(t).Encrypt("hunter2")
				require.NoError(t, err)
				writeFile(t, tr.dir, "roles/backups/role.yml", strings.ReplaceAll(tt.restic, "PASSWORD", nest(password)))
				_, err = tr.open(t).HostConfig("alpha", "debian")
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestDNSVhostRecords(t *testing.T) {
	tr := newTestRepo(t, map[string]string{})
	enc, err := tr.open(t).Encrypt("x")
	require.NoError(t, err)
	settings, err := os.ReadFile(filepath.Join(tr.dir, "sensible.yml"))
	require.NoError(t, err)
	dns := string(settings) + myDNSHostSettings(enc, enc)

	writeFile(t, tr.dir, "sensible.yml", dns+"  vhosts:\n    - {type: rrclone, content: '(A,AAAA) {host}'}\n")
	assert.Equal(t, []VhostRecord{{Type: "RRCLONE", Content: "(A,AAAA) {host}"}}, tr.open(t).DNS().Vhosts)

	writeFile(t, tr.dir, "sensible.yml", dns+"  vhosts:\n    - {type: CNAME}\n")
	_, err = tr.tryOpen()
	assert.ErrorContains(t, err, "dns.vhosts[0]: needs a type and content")
}

func TestHostConfig_dockerRegistries(t *testing.T) {
	tr := newTestRepo(t, map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {a: }\n", "roles/a/role.yml": ""})
	password, err := tr.open(t).Encrypt("hunter2")
	require.NoError(t, err)
	writeFile(
		t,
		tr.dir,
		"roles/a/role.yml",
		"docker:\n  registries:\n    registry.example.com:\n"+
			"      username: alice\n      password: "+nest(nest(nest(password)))+"\n",
	)

	c, err := tr.open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"registry.example.com": "YWxpY2U6aHVudGVyMg=="}, c.Docker.Auths)
}

func TestHostConfig_dockerRegistryErrors(t *testing.T) {
	tests := []struct {
		name, registry, want string
	}{
		{"no username", "password: PASSWORD\n", "docker.registries.r.example.com needs a username"},
		{"no password", "username: alice\n", "docker.registries.r.example.com.password: secret is not set"},
		{"plain password", "username: alice\npassword: hunter2\n", "secrets must be encrypted"},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				tr := newTestRepo(t, map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {a: }\n", "roles/a/role.yml": ""})
				password, err := tr.open(t).Encrypt("hunter2")
				require.NoError(t, err)
				writeFile(
					t,
					tr.dir,
					"roles/a/role.yml",
					"docker:\n  registries:\n    r.example.com:\n      "+
						nest(nest(nest(strings.ReplaceAll(tt.registry, "PASSWORD", nest(password))))),
				)
				_, err = tr.open(t).HostConfig("alpha", "debian")
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}
}

package config

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostConfig_stacks(t *testing.T) {
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": `
alpha:
  roles:
    web: {image: nginx:2, labels: {a: b}}
    group:
`,
			"roles/web/role.yml": `
params:
  image: nginx:1
  labels: {}
  command: [serve, --port, "80"]
  extra: ~
compose:
  files:
    - nginx.conf
    - {path: conf, owner: "1000", mode: 0o644}
    - .env.age
  volumes:
    data: {owner: 70, mode: 0700}
    uploads: {owner: alice, group: users, mode: 0o750}
`,
			"roles/web/docker-compose.yml": "",
			"roles/web/.env.age":           "",
			"roles/web/nginx.conf":         "server {}\n",
			"roles/web/conf/.hidden":       "h\n",
			"roles/web/conf/sub/site.conf": "s\n",
			"roles/web/.role.yml.swp":      "ignored",
			"roles/group/role.yml":         "children: [one]\ncompose:\n  volumes: {blobs: {owner: \"33\"}}\n",
			"roles/group/one/docker-compose.yml": `services:
  app:
    volumes: [!volume ../blobs:/b]
`,
		},
	)
	r := tr.open(t)
	password, err := r.Encrypt("pa$$word")
	require.NoError(t, err)
	env, err := r.EncryptFile("TOKEN=t$\n")
	require.NoError(t, err)
	writeFile(t, tr.dir, "roles/web/.env.age", env)
	writeFile(
		t,
		tr.dir,
		"roles/web/docker-compose.yml",
		strings.Replace(readTestdata(t, "stack.yml"), "SECRET", strings.ReplaceAll(password, "\n", "\n        "), 1),
	)

	c, err := tr.open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	require.Len(t, c.Stacks, 2)
	defaults := Perms{Owner: "root", Group: "docker", Mode: 0o640}
	assert.Equal(t, "group-one", c.Stacks[0].Name)
	assert.Equal(
		t,
		[]StackFile{
			{
				Path:    "docker-compose.yml",
				Content: "services:\n  app:\n    volumes: [\"/srv/volumes/group/blobs:/b\"]\n",
				Perms:   defaults,
			},
		},
		c.Stacks[0].Files,
	)

	web := c.Stacks[1]
	conf := Perms{Owner: "1000", Mode: 0o644}
	confDir := Perms{Owner: "1000", Mode: 0o755}
	assert.Equal(t, map[string]Perms{"conf": confDir, "conf/sub": confDir}, web.Dirs)
	assert.Equal(t, "web", web.Name)
	assert.Equal(t, "/srv/compose/web", web.Dir())
	assert.Equal(
		t,
		[]Volume{
			{Path: "/srv/volumes/group/blobs", Owner: "33"},
			{Path: "/srv/volumes/web/data", Owner: "70", Mode: 0o700},
			{Path: "/srv/volumes/web/uploads", Owner: "alice", Group: "users", Mode: fs.FileMode(0o750)},
		},
		c.Volumes,
	)
	assert.Equal(
		t,
		[]StackFile{
			{
				Path:    "docker-compose.yml",
				Content: readTestdata(t, "stack.rendered.yml"),
				Perms:   defaults,
				Secrets: []string{"pa$$$$word"},
			},
			{Path: ".env", Content: "TOKEN=t$\n", Perms: defaults, Hidden: true},
			{Path: "conf/.hidden", Content: "h\n", Perms: conf},
			{Path: "conf/sub/site.conf", Content: "s\n", Perms: conf},
			{Path: "nginx.conf", Content: "server {}\n", Perms: defaults},
		},
		web.Files,
	)
}

func TestHostConfig_stackErrors(t *testing.T) {
	tests := []struct {
		name    string
		compose string
		files   map[string]string
		want    string
	}{
		{
			"undeclared volume",
			"services:\n  a:\n    volumes: [!volume db:/x]\n",
			nil,
			`volume "db" isn't in role web's compose.volumes`,
		},
		{
			"parent volume without a parent",
			"services:\n  a:\n    volumes: [!volume ../db:/x]\n",
			nil,
			"role web has no parent",
		},
		{"unknown parameter", "services:\n  a:\n    image: !param image\n", nil, `unknown parameter "image"`},
		{"plain secret", "services:\n  a:\n    image: !age x\n", nil, "ASCII-armored"},
		{"invalid YAML", "services: [\n", nil, "docker-compose.yml"},
		{
			"unencrypted .age file",
			"services: {}\n",
			map[string]string{"roles/web/role.yml": "compose:\n  files: [a.age]\n", "roles/web/a.age": "plain"},
			"roles/web/a.age: expected an ASCII-armored age file",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := map[string]string{
					"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\n",
					"roles/web/docker-compose.yml": tt.compose,
				}
				maps.Copy(files, tt.files)
				_, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")
				require.ErrorContains(t, err, tt.want)
				assert.ErrorContains(t, err, "role web")
			},
		)
	}
}

func TestHostConfig_parentVolumesWithOnlyAChild(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":        "alpha:\n  roles: {group/one: }\n",
			"roles/group/role.yml":     "children: [one]\ncompose:\n  volumes: {blobs: }\n",
			"roles/group/one/role.yml": "",
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, []Volume{{Path: "/srv/volumes/group/blobs"}}, c.Volumes)

	_, err = newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":                  "alpha:\n  roles: {group: }\n",
			"roles/group/role.yml":               "children: [two]\ncompose:\n  volumes: {blobs: }\n",
			"roles/group/two/docker-compose.yml": "services:\n  a:\n    volumes: [!volume ../missing:/x]\n",
		},
	).open(t).HostConfig("alpha", "debian")
	assert.ErrorContains(t, err, `volume "missing" isn't in role group's compose.volumes`)
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(b)
}

func TestHostConfig_volumesInRoleFiles(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {group: , web: }\n",
			"roles/group/role.yml": `
children: [one]
compose:
  volumes: {blobs: }
`,
			"roles/group/one/role.yml": `
compose:
  volumes: {cache: }
ntp:
  servers: [!volume cache, !volume ../blobs:/b]
`,
			"roles/web/role.yml": `
compose:
  volumes: {data: }
params:
  first: !volume data
ntp:
  servers: [!param first]
`,
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.ElementsMatch(
		t,
		[]string{"/srv/volumes/group-one/cache", "/srv/volumes/group/blobs:/b", "/srv/volumes/web/data"},
		c.NTP.Servers,
	)
}

func TestOpen_volumeInHosts(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":  "alpha:\n  roles: {web: {first: !volume data}}\n",
			"roles/web/role.yml": "compose:\n  volumes: {data: }\nparams:\n  first: ~\n",
		},
	).tryOpen()
	require.ErrorContains(t, err, "!volume only works in roles")
	assert.ErrorContains(t, err, "hosts.yml")
}

func TestHostConfig_undeclaredVolumeInRoleFile(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":       "alpha:\n  roles: {web: }\n",
			"roles/web/role.yml":      "compose:\n  volumes: {data: }\n",
			"roles/web/role.arch.yml": "ntp:\n  servers: [!volume db]\n",
		},
	).open(t).HostConfig("alpha", "arch")
	require.ErrorContains(t, err, `volume "db" isn't in role web's compose.volumes`)
	assert.ErrorContains(t, err, "role.arch.yml")
}

func TestVhosts(t *testing.T) {
	r := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": `
alpha:
  roles: {web: , group: }
beta:
  roles: {web: {name: other.example.com}}
gamma:
  roles: {web: {name: !vhost gamma.example.com www.gamma.example.com}}
`,
			"roles/web/role.yml": `
params:
  name: !vhost default.example.com
ntp:
  servers: [!param name, !vhost Shared.Example.com.]
`,
			"roles/web/docker-compose.yml":  "services:\n  a:\n    labels:\n      vhost: !vhost a.example.com,b.example.com\n",
			"roles/group/role.yml":          "children: [one]\n",
			"roles/group/one/role.arch.yml": "ntp:\n  servers: [!vhost arch.example.com]\n",
			"roles/group/one/role.yml":      "",
		},
	).open(t)

	assert.Equal(
		t,
		map[string][]string{
			"a.example.com":         {"alpha", "beta", "gamma"},
			"b.example.com":         {"alpha", "beta", "gamma"},
			"shared.example.com":    {"alpha", "beta", "gamma"},
			"default.example.com":   {"alpha"},
			"gamma.example.com":     {"gamma"},
			"www.gamma.example.com": {"gamma"},
			"arch.example.com":      {"alpha"},
		},
		r.Vhosts(),
	)

	c, err := r.HostConfig("gamma", "debian")
	require.NoError(t, err)
	assert.Equal(t, Set{"gamma.example.com www.gamma.example.com", "Shared.Example.com."}, c.NTP.Servers)
	assert.Equal(
		t,
		"services:\n  a:\n    labels:\n      vhost: \"a.example.com,b.example.com\"\n",
		c.Stacks[0].Files[0].Content,
	)
}

func TestVhosts_errors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			"outside role parameters",
			map[string]string{"hosts.d/hosts.yml": "alpha:\n  address: !vhost a.example.com\n  roles: {web: }\n"},
			"!vhost only works in roles and role parameters",
		},
		{
			"invalid name in a host",
			map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {web: {name: !vhost 'a.example.com, bad!name'}}\n"},
			`"bad!name" isn't a domain name`,
		},
		{
			"empty name",
			map[string]string{
				"roles/web/docker-compose.yml": "services:\n  a:\n    labels: {v: !vhost 'a.example.com,,b.example.com'}\n",
			},
			`"a.example.com,,b.example.com" has an empty domain name`,
		},
		{
			"invalid name in a role",
			map[string]string{"roles/web/docker-compose.yml": "services:\n  a:\n    labels: {v: !vhost localhost}\n"},
			`"localhost" isn't a domain name`,
		},
		{
			"not a string",
			map[string]string{"roles/web/docker-compose.yml": "services:\n  a:\n    labels: {v: !vhost [a.example.com]}\n"},
			"!vhost needs a domain name",
		},
		{
			"a host's dns_name",
			map[string]string{
				"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\nbeta:\n  dns_name: Beta.example.com\n",
				"roles/web/docker-compose.yml": "services:\n  a:\n    labels: {v: !vhost beta.example.com}\n",
			},
			"alpha: role web: vhost beta.example.com is beta's dns_name",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := map[string]string{
					"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\n",
					"roles/web/role.yml":           "params:\n  name: ~\n",
					"roles/web/docker-compose.yml": "services: {}\n",
				}
				maps.Copy(files, tt.files)
				_, err := newTestRepo(t, files).tryOpen()
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestVhosts_variantParamsMergeOverRoleYML(t *testing.T) {
	r := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":         "alpha:\n  roles: {web: }\n",
			"roles/web/role.yml":        "params:\n  name: !vhost base.example.com\nntp:\n  servers: [!param name]\n",
			"roles/web/role.debian.yml": "params:\n  name: !vhost deb.example.com\n",
		},
	).open(t)

	// Either may apply, depending on the host's OS.
	assert.Equal(t, map[string][]string{"base.example.com": {"alpha"}, "deb.example.com": {"alpha"}}, r.Vhosts())
	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, Set{"deb.example.com"}, c.NTP.Servers)
}

func TestVhosts_anchoredHostEntry(t *testing.T) {
	r := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":  "alpha: &a\n  roles: &r\n    web: {name: !vhost x.example.com}\n",
			"roles/web/role.yml": "params:\n  name: ~\n",
		},
	).open(t)

	assert.Equal(t, map[string][]string{"x.example.com": {"alpha"}}, r.Vhosts())
}

func stackFile(t *testing.T, s Stack, path string) StackFile {
	t.Helper()
	for _, f := range s.Files {
		if f.Path == path {
			return f
		}
	}
	require.Failf(t, "missing stack file", "%s has no %s", s.Name, path)
	return StackFile{}
}

func newGeneratedRepo(t *testing.T) *testRepo {
	t.Helper()
	return newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {app: }\nbeta:\n  roles: {app: }\n",
			"partials/postgres/partial.yml": `
params:
  password: ~
compose:
  env:
    PG_PASSWORD: "{password}"
`,
			"partials/postgres/docker-compose.yml": `
services:
  db:
    environment:
      POSTGRES_PASSWORD: "{password}"
`,
			"roles/app/role.yml": `
params:
  token: !generated token
partials:
  - {partial: postgres, password: !generated db}
compose:
  env:
    DB_PASSWORD: !generated db
    LOG_LEVEL: info
`,
			"roles/app/docker-compose.yml": `
services:
  app:
    environment:
      DATABASE_URL: postgres://app:${DB_PASSWORD}@db/app
      PASSWORD: !generated db
      TOKEN: !param token
`,
		},
	)
}

func TestHostConfig_generatedValues(t *testing.T) {
	tr := newGeneratedRepo(t)
	r := tr.open(t)

	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	s := c.Stacks[0]
	require.Len(t, s.Generated, 2)
	db, token := s.Generated["db"], s.Generated["token"]
	assert.NotEqual(t, db, token)

	compose := stackFile(t, s, "docker-compose.yml")
	assert.Equal(t, 2, strings.Count(compose.Content, db), "role and partial compose files")
	assert.Contains(t, compose.Content, token)
	assert.Contains(t, compose.Content, "${DB_PASSWORD}")
	assert.ElementsMatch(t, []string{db, db, token}, compose.Secrets)

	env := stackFile(t, s, ".env")
	assert.Equal(t, "DB_PASSWORD='"+db+"'\nLOG_LEVEL='info'\nPG_PASSWORD='"+db+"'\n", env.Content)
	assert.Equal(t, filePerms(Perms{}), env.Perms)
	assert.Equal(t, []string{db, db}, env.Secrets)
	assert.False(t, env.Hidden)

	again, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.NotEqual(t, db, again.Stacks[0].Generated["db"], "unsaved values aren't reused")

	require.NoError(t, r.SaveGenerated("alpha", c.Stacks))
	for _, r := range []*Repo{r, tr.open(t)} {
		saved, err := r.HostConfig("alpha", "debian")
		require.NoError(t, err)
		assert.Empty(t, saved.Stacks[0].Generated)
		assert.Equal(t, compose.Content, stackFile(t, saved.Stacks[0], "docker-compose.yml").Content)
		assert.Equal(t, env.Content, stackFile(t, saved.Stacks[0], ".env").Content)

		beta, err := r.HostConfig("beta", "debian")
		require.NoError(t, err)
		assert.NotEqual(t, db, beta.Stacks[0].Generated["db"], "each host has its own values")
	}
}

func TestSaveGenerated_keepsSavedValues(t *testing.T) {
	tr := newGeneratedRepo(t)
	r := tr.open(t)
	rotated := time.Date(2026, 10, 31, 12, 30, 0, 0, time.UTC)
	require.NoError(t, r.WriteCredentials("alpha", "key", "password", rotated))
	existing, err := r.Encrypt("hand-written")
	require.NoError(t, err)
	b, err := os.ReadFile(filepath.Join(tr.dir, "hosts.d", "alpha.state.yml"))
	require.NoError(t, err)
	writeFile(
		t,
		tr.dir,
		"hosts.d/alpha.state.yml",
		string(b)+"  generated:\n    app:\n      db: "+indent(existing, "      ")+"\n",
	)
	r = tr.open(t)

	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, []string{"token"}, slices.Collect(maps.Keys(c.Stacks[0].Generated)))
	assert.Contains(t, stackFile(t, c.Stacks[0], ".env").Content, "DB_PASSWORD='hand-written'")

	stale := []Stack{{Name: "app", Generated: map[string]string{"db": "other", "token": "t"}}}
	require.NoError(t, r.SaveGenerated("alpha", stale))
	alpha := tr.open(t).Inventory().Hosts["alpha"]
	for name, want := range map[string]string{"db": "hand-written", "token": "t"} {
		got, err := alpha.Generated["app"][name].Reveal()
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	key, err := alpha.SSHKey.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "key", key)
}

func TestHostConfig_composeEnv(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {web: {port: 8080}}\n",
			"partials/x/partial.yml": `
params:
  name: web
compose:
  volumes:
    data: {owner: "1000"}
  env:
    NAME: "{name}"
    MODE: dev
`,
			"roles/web/role.yml": `
params:
  port: 80
  site: site
  unset: ~
partials:
  - {partial: x, name: !param site}
compose:
  env:
    PORT: !param port
    MODE: !replace prod
    UNSET: !param unset
`,
			"roles/web/docker-compose.yml": "services: {}\n",
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	env := stackFile(t, c.Stacks[0], ".env")
	assert.Equal(t, "MODE='prod'\nNAME='site'\nPORT='8080'\n", env.Content)
	assert.Empty(t, env.Secrets)
}

func TestHostConfig_noComposeEnvNoFile(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\n",
			"roles/web/docker-compose.yml": "services: {}\n",
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	require.Len(t, c.Stacks[0].Files, 1)
	assert.Nil(t, c.Stacks[0].Generated)
}

func TestHostConfig_generatedErrors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			"in role settings",
			map[string]string{"roles/web/role.yml": "jobs:\n  a: {command: [!generated x], schedule: daily}\n"},
			"!generated only works in a stack's compose file and compose.env",
		},
		{
			"in role settings through a param",
			map[string]string{"roles/web/role.yml": "params: {p: !generated x}\nntp:\n  servers: [!param p]\n"},
			"!generated only works",
		},
		{
			"in partial settings",
			map[string]string{
				"partials/x/partial.yml": "ntp:\n  servers: [!generated x]\n",
				"roles/web/role.yml":     "partials: [{partial: x}]\n",
			},
			"!generated only works",
		},
		{
			"invalid name",
			map[string]string{"roles/web/docker-compose.yml": "services:\n  a:\n    image: !generated a/b\n"},
			"!generated needs a name",
		},
		{
			"invalid variable name",
			map[string]string{"roles/web/role.yml": "compose:\n  env: {A-B: x}\n"},
			`roles/web/role.yml: compose.env: [2:9] "A-B" isn't a variable name`,
		},
		{
			"quote in a variable",
			map[string]string{"roles/web/role.yml": "compose:\n  env: {A: \"it's\"}\n"},
			"A can't be written to .env",
		},
		{
			"mapping in a variable",
			map[string]string{
				"partials/x/partial.yml": "compose:\n  env: {A: {b: c}}\n",
				"roles/web/role.yml":     "partials: [{partial: x}]\n",
			},
			"partials/x/partial.yml: compose.env: [2:12] a compose.env value must be a string, number or bool",
		},
		{
			".env in compose.files",
			map[string]string{
				"roles/web/role.yml": "compose:\n  files: [.env]\n  env: {A: b}\n",
				"roles/web/.env":     "A=c\n",
			},
			"can't also be in compose.files",
		},
		{
			"partial and role set a variable differently",
			map[string]string{
				"partials/x/partial.yml": "compose:\n  env: {A: b}\n",
				"roles/web/role.yml":     "partials: [{partial: x}]\ncompose:\n  env: {A: c}\n",
			},
			"compose.env: partial x and",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := map[string]string{
					"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\n",
					"roles/web/docker-compose.yml": "services: {}\n",
				}
				maps.Copy(files, tt.files)
				_, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")
				require.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestOpen_composeEnvNeedsAStack(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"role": {"roles/web/role.yml": "compose:\n  env: {A: b}\n"},
		"partial": {
			"partials/x/partial.yml": "compose:\n  env: {A: b}\n",
			"roles/web/role.yml":     "partials: [{partial: x}]\n",
		},
	} {
		t.Run(
			name,
			func(t *testing.T) {
				files["hosts.d/hosts.yml"] = "alpha:\n  roles: {web: }\n"
				_, err := newTestRepo(t, files).tryOpen()
				assert.ErrorContains(t, err, "compose.env needs a docker-compose.yml")
			},
		)
	}
}

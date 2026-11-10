package config

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/goccy/go-yaml"
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
		{
			"project name",
			"name: other\nservices: {}\n",
			nil,
			`roles/web/docker-compose.yml: [1:7] name must be "web", the stack's name`,
		},
		{
			"project name in a partial",
			"services: {}\n",
			map[string]string{
				"roles/web/role.yml":            "partials: [{partial: x}]\n",
				"partials/x/partial.yml":        "",
				"partials/x/docker-compose.yml": "name: other\n",
			},
			`partials/x/docker-compose.yml: [1:7] name must be "web", the stack's name`,
		},
		{
			"relative bind mount",
			"services:\n  a:\n    volumes: [./data:/x]\n",
			nil,
			"docker-compose.yml: service a mounts ./data, which isn't in stack web's compose.files",
		},
		{
			"long-form bind mount",
			"services:\n  a:\n    volumes:\n      - {type: bind, source: data/db, target: /x}\n",
			nil,
			"service a mounts data/db, which isn't in stack web's compose.files",
		},
		{
			"absolute bind mount",
			"services:\n  a:\n    volumes: [\"/srv/compose/web/data:/x:ro\"]\n",
			nil,
			"service a mounts /srv/compose/web/data,",
		},
		{
			"bind mount of the stack's directory",
			"services:\n  a:\n    volumes: [.:/x]\n",
			nil,
			"service a mounts .,",
		},
		{
			"bind mount beside a declared file",
			"services:\n  a:\n    volumes: [./conf/new:/x]\n",
			map[string]string{"roles/web/role.yml": "compose:\n  files: [conf]\n", "roles/web/conf/a": ""},
			"service a mounts ./conf/new,",
		},
		{
			"bind mount in a partial",
			"services: {}\n",
			map[string]string{
				"roles/web/role.yml":            "partials: [{partial: x}]\n",
				"partials/x/partial.yml":        "",
				"partials/x/docker-compose.yml": "services:\n  a:\n    volumes: !override [./data:/x]\n",
			},
			"service a mounts ./data,",
		},
		{
			"bind mount in another stack",
			"services:\n  a:\n    volumes: [../other/data:/x]\n",
			nil,
			"service a of stack web mounts ../other/data, which is in /srv/compose",
		},
		{
			"COMPOSE_PROJECT_NAME",
			"services: {}\n",
			map[string]string{"roles/web/role.yml": "compose:\n  env:\n    COMPOSE_PROJECT_NAME: other\n"},
			"COMPOSE_PROJECT_NAME can't be set",
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

func TestHostConfig_bindMountsOfStackFiles(t *testing.T) {
	_, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {web: }\n",
			"roles/web/role.yml": `
compose:
  files: [app.conf, conf, nested/site.conf]
  volumes: {data: }
  env: {A: b}
`,
			"roles/web/app.conf":         "",
			"roles/web/conf/sub/a.conf":  "",
			"roles/web/nested/site.conf": "",
			"roles/web/docker-compose.yml": `services:
  a:
    volumes:
      - ./app.conf:/etc/app.conf:ro
      - /srv/compose/web/conf:/etc/conf
      - ./nested:/nested
      - ./conf/sub/a.conf:/a
      - ./.env:/env
      - ./docker-compose.yml:/compose.yml
      - !volume data:/data
      - named:/named
      - /var/lib/x:/x
      - /srv/compose:/srv/compose:ro
      - ${DATA}:/d
      - /anonymous
      - {type: volume, source: ./named, target: /n}
      - {type: bind, source: ./conf, target: /c}
`,
		},
	).open(t).HostConfig("alpha", "debian")
	assert.NoError(t, err)
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
			"invalid name once filled",
			map[string]string{
				"roles/web/docker-compose.yml": "services:\n  a:\n    labels: {v: !vhost \"{host}.{{host}}.example.com\"}\n",
			},
			`docker-compose.yml: [3:17] "alpha.{host}.example.com" isn't a domain name`,
		},
		{
			"placeholder in a host",
			map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {web: {name: !vhost \"{host}.example.com\"}}\n"},
			`"{host}.example.com" isn't a domain name`,
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

func TestVhosts_placeholders(t *testing.T) {
	r := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":        "alpha:\n  roles: {web: }\nbeta:\n  roles: {web: {name: !vhost own.example.com}}\n",
			"partials/ntp/partial.yml": "params:\n  server: ~\nntp:\n  servers: [\"{server}\"]\n",
			"roles/web/role.yml": `
params:
  name: !vhost "name.{host}.example.com"
partials:
  - {partial: ntp, server: !vhost "ntp.{host}.example.com"}
ntp:
  servers: [!param name, !vhost "{stack}.{host}.example.com"]
`,
			"roles/web/docker-compose.yml": "services:\n  a:\n    labels: {vhost: !vhost \"app.{host}.example.com\"}\n",
		},
	).open(t)

	assert.Equal(
		t,
		map[string][]string{
			"app.alpha.example.com":  {"alpha"},
			"app.beta.example.com":   {"beta"},
			"web.alpha.example.com":  {"alpha"},
			"web.beta.example.com":   {"beta"},
			"ntp.alpha.example.com":  {"alpha"},
			"ntp.beta.example.com":   {"beta"},
			"name.alpha.example.com": {"alpha"},
			"own.example.com":        {"beta"},
		},
		r.Vhosts(),
	)

	for host, name := range map[string]string{"alpha": "name.alpha.example.com", "beta": "own.example.com"} {
		c, err := r.HostConfig(host, "debian")
		require.NoError(t, err)
		assert.ElementsMatch(
			t,
			Set{"ntp." + host + ".example.com", name, "web." + host + ".example.com"},
			c.NTP.Servers,
		)
		assert.Equal(
			t,
			map[string]any{"services": map[string]any{"a": map[string]any{
				"labels": map[string]any{"vhost": "app." + host + ".example.com"},
			}}},
			normaliseYAML(t, c.Stacks[0].Files[0].Content),
		)
	}
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

func TestHostConfig_generatedLengths(t *testing.T) {
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\n",
			"roles/web/docker-compose.yml": "services: {}\n",
			"roles/web/role.yml":           "compose:\n  env: {A: !generated a, B: !generated b 40, C: !generated c 8}\n",
		},
	)
	r := tr.open(t)

	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	g := c.Stacks[0].Generated
	assert.Len(t, g["a"], 26)
	assert.Len(t, g["b"], 40)
	assert.Len(t, g["c"], 26, "never shorter than the default")

	short := map[string]string{"a": "x", "b": strings.Repeat("y", 39), "c": strings.Repeat("z", 26)}
	require.NoError(t, r.SaveGenerated("alpha", []Stack{{Name: "web", Generated: short}}))
	_, err = tr.open(t).HostConfig("alpha", "debian")
	require.ErrorContains(t, err, "generated value b is saved with 39 characters, fewer than the 40 asked for")
}

func TestHostConfig_previewSavedGeneratedWithoutIdentity(t *testing.T) {
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\n",
			"roles/web/docker-compose.yml": "services: {}\n",
			"roles/web/role.yml":           "compose:\n  env: {KEY: !generated key 48}\n",
		},
	)
	saved := map[string]string{"key": strings.Repeat("k", 48)}
	require.NoError(t, tr.open(t).SaveGenerated("alpha", []Stack{{Name: "web", Generated: saved}}))

	r, err := Open(tr.dir, func() (age.Identity, error) { return nil, errors.New("locked") })
	require.NoError(t, err)
	r.Preview(nil)
	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Empty(t, c.Stacks[0].Generated)
	assert.Regexp(t, `KEY='<age:[0-9a-f]{8}>'`, stackFile(t, c.Stacks[0], ".env").Content)
}

func TestHostConfig_previewDoesNotGenerate(t *testing.T) {
	r := newGeneratedRepo(t).open(t)
	r.Preview(nil)

	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	s := c.Stacks[0]
	assert.Empty(t, s.Generated)
	assert.Contains(t, stackFile(t, s, "docker-compose.yml").Content, `PASSWORD: "<generated:db>"`)
	assert.Contains(t, stackFile(t, s, ".env").Content, "DB_PASSWORD='<generated:db>'\n")
}

func TestHostConfig_previewAgeFileWithoutIdentity(t *testing.T) {
	tr := newTestRepo(t, map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {web: }\n"})
	settings, err := OpenSettings(tr.dir)
	require.NoError(t, err)
	armored, err := settings.EncryptFile("KEY=value\n")
	require.NoError(t, err)
	writeFile(t, tr.dir, "roles/web/role.yml", "compose:\n  files: [app.env.age]\n")
	writeFile(t, tr.dir, "roles/web/docker-compose.yml", "services:\n  web:\n    image: nginx\n")
	writeFile(t, tr.dir, "roles/web/app.env.age", armored)

	r, err := Open(tr.dir, func() (age.Identity, error) { return nil, errors.New("locked") })
	require.NoError(t, err)
	r.Preview(nil)
	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	secret, err := parseArmored(armored)
	require.NoError(t, err)
	assert.Equal(t, secret.Placeholder(), stackFile(t, c.Stacks[0], "app.env").Content)
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

func TestDropGenerated_dropsOnlyThatStack(t *testing.T) {
	tr := newGeneratedRepo(t)
	r := tr.open(t)
	stacks := []Stack{
		{Name: "app", Generated: map[string]string{"db": "app-db"}},
		{Name: "old", Generated: map[string]string{"db": "old-db", "token": "old-token"}},
	}
	require.NoError(t, r.SaveGenerated("alpha", stacks))
	require.NoError(t, r.SaveGenerated("beta", stacks))

	require.NoError(t, r.DropGenerated("alpha", "old", []string{"db", "token"}))

	for _, r := range []*Repo{r, tr.open(t)} {
		alpha := r.Inventory().Hosts["alpha"].Generated
		assert.Equal(t, []string{"app"}, slices.Collect(maps.Keys(alpha)))
		db, err := alpha["app"]["db"].Reveal()
		require.NoError(t, err)
		assert.Equal(t, "app-db", db)
		assert.Contains(t, r.Inventory().Hosts["beta"].Generated, "old")
	}
}

func TestDropGenerated_refusesValuesSetElsewhere(t *testing.T) {
	tr := newGeneratedRepo(t)
	r := tr.open(t)
	secret, err := r.Encrypt("by hand")
	require.NoError(t, err)
	writeFile(t, tr.dir, "hosts.d/extra.yml", "alpha:\n  generated:\n    old:\n      db: "+indent(secret, "      ")+"\n")
	r = tr.open(t)

	err = r.DropGenerated("alpha", "old", []string{"db"})

	require.ErrorContains(t, err, "extra.yml sets alpha's generated db for old")
	assert.Contains(t, tr.open(t).Inventory().Hosts["alpha"].Generated, "old")
}

func TestDropGenerated_dropsOnlyTheNamedValues(t *testing.T) {
	tr := newGeneratedRepo(t)
	r := tr.open(t)
	stacks := []Stack{{Name: "app", Generated: map[string]string{"db": "app-db", "old": "x", "older": "y"}}}
	require.NoError(t, r.SaveGenerated("alpha", stacks))

	require.NoError(t, r.DropGenerated("alpha", "app", []string{"old", "older"}))

	app := tr.open(t).Inventory().Hosts["alpha"].Generated["app"]
	assert.Equal(t, []string{"db"}, slices.Collect(maps.Keys(app)))
}

func TestHostConfig_unusedGeneratedValues(t *testing.T) {
	tr := newGeneratedRepo(t)
	r := tr.open(t)
	saved := map[string]string{"db": "a", "old": "b", "older": "c", "token": "d"}
	require.NoError(t, r.SaveGenerated("alpha", []Stack{{Name: "app", Generated: saved}}))

	c, err := tr.open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, []string{"old", "older"}, c.Stacks[0].Unused)

	beta, err := tr.open(t).HostConfig("beta", "debian")
	require.NoError(t, err)
	assert.Empty(t, beta.Stacks[0].Unused)
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

func TestHostConfig_stackProjectName(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":                "alpha:\n  roles: {web/app: }\n",
			"roles/web/role.yml":               "children: [app]\n",
			"roles/web/app/role.yml":           "partials: [{partial: x}]\n",
			"roles/web/app/docker-compose.yml": "name: \"{stack}\"\nservices: {}\n",
			"partials/x/partial.yml":           "",
			"partials/x/docker-compose.yml":    "name: web-app\n",
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, "name: \"web-app\"\nservices: {}\n", stackFile(t, c.Stacks[0], "docker-compose.yml").Content)
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

func TestHostConfig_placeholdersInRoleFiles(t *testing.T) {
	r := newTestRepo(t, readTestTree(t, "role-placeholders")).open(t)
	for _, host := range []string{"alpha", "beta"} {
		c, err := r.HostConfig(host, "debian")
		require.NoError(t, err)
		var compose struct {
			Services map[string]struct {
				Environment map[string]string `yaml:"environment"`
				Volumes     []string          `yaml:"volumes"`
			} `yaml:"services"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(stackFile(t, c.Stacks[0], "docker-compose.yml").Content), &compose))
		app := compose.Services["app"]
		assert.Equal(t, "adzeral-"+host, app.Environment["TASK_QUEUE"])
		assert.Equal(t, "adzeral-"+host, app.Environment["QUEUE"])
		assert.Equal(t, "{host} ${HOME} {{.Name}} {other}", app.Environment["LITERAL"])
		assert.Equal(t, "echo web\n", app.Environment["SCRIPT"])
		assert.Equal(t, []string{"/srv/volumes/web/web-data:/data"}, app.Volumes)
		assert.Equal(t, "HOST='"+host+"'\n", stackFile(t, c.Stacks[0], ".env").Content)
		assert.Equal(t, Command{"backup", "web"}, c.Jobs[host+"-backup"].Command)
		if host == "alpha" {
			assert.Equal(t, "{host}", app.Environment["LABEL"], "a host's values are used as written")
		}
	}
}

func TestHostConfig_placeholderErrors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			"host parameter",
			map[string]string{"roles/web/role.yml": "params:\n  host: a\n"},
			"roles/web/role.yml: [2:3] {host} is the host's name, so can't be a parameter",
		},
		{
			"stack parameter in a variant",
			map[string]string{"roles/web/role.debian.yml": "params:\n  stack: a\n"},
			"roles/web/role.debian.yml: [2:3] {stack} is the role's stack name, so can't be a parameter",
		},
		{
			"unquoted placeholder",
			map[string]string{"roles/web/docker-compose.yml": "services:\n  a:\n    image: {host}\n"},
			"roles/web/docker-compose.yml: [3:12] quote placeholders",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := map[string]string{
					"hosts.d/hosts.yml":            "alpha:\n  roles: {web: }\n",
					"roles/web/role.yml":           "",
					"roles/web/docker-compose.yml": "services: {}\n",
				}
				maps.Copy(files, tt.files)
				_, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestOpen_hostPlaceholderInFixedSettings(t *testing.T) {
	for _, setting := range []string{
		"compose:\n  volumes:\n    \"{host}\": {owner: \"1\"}\n",
		"compose:\n  files: [\"{host}.conf\"]\n",
		"children: [\"{host}\"]\n",
	} {
		_, err := newTestRepo(
			t,
			map[string]string{
				"roles/web/role.yml":           setting,
				"roles/web/docker-compose.yml": "services: {}\n",
			},
		).tryOpen()
		assert.ErrorContains(t, err, "{host} is the host's name, which differs between hosts, but ")
	}
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
			"!generated only works in a stack's compose file, compose.env, migrations' on and oidc_clients' secret",
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
			"invalid length",
			map[string]string{"roles/web/role.yml": "compose:\n  env: {A: !generated a 0}\n"},
			"a !generated length must be from 1 to 1024",
		},
		{
			"different lengths",
			map[string]string{"roles/web/role.yml": "compose:\n  env: {A: !generated a 40, B: !generated a}\n"},
			"generated value a is used with different lengths",
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

func TestHostConfig_migrations(t *testing.T) {
	c, err := newTestRepo(t, readTestTree(t, "migrations")).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	require.Len(t, c.Stacks, 2)

	assert.Equal(
		t,
		[]Migration{{
			Name:   "db-major",
			On:     "database",
			Before: Command{"sh", "-c", `pg_dumpall > "$MIGRATION_DIR/dump.sql" # other`},
			After:  Command{"sh", "-c", `psql < "$MIGRATION_DIR/dump.sql"`},
		}},
		c.Stacks[0].Migrations,
		"each stack has its own migrations, under the same names",
	)

	web := c.Stacks[1]
	require.Len(t, web.Migrations, 2)
	assert.Equal(t, "database-17", web.Migrations[0].On)
	assert.Equal(
		t,
		Migration{
			Name:   "password",
			On:     web.Generated["db"],
			Secret: true,
			After:  Command{"sh", "-c", `psql -c "ALTER USER app PASSWORD '$DB_PASSWORD'"`},
		},
		web.Migrations[1],
	)
}

func TestHostConfig_migrationErrors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			"no stack",
			map[string]string{
				"roles/web/role.yml":           "migrations:\n  m: {on: x, after: [true]}\n",
				"roles/web/docker-compose.yml": "",
			},
			"migrations only work in a role with a stack",
		},
		{
			"no on",
			map[string]string{"roles/web/role.yml": "migrations:\n  m: {after: [true]}\n"},
			"m needs on",
		},
		{
			"no commands",
			map[string]string{"roles/web/role.yml": "migrations:\n  m: {on: x}\n"},
			"m needs before, after or both",
		},
		{
			"bad name",
			map[string]string{"roles/web/role.yml": "migrations:\n  a/b: {on: x, after: [true]}\n"},
			`"a/b" can't be a migration's name`,
		},
		{
			"secret in a command",
			map[string]string{"roles/web/role.yml": "migrations:\n  m: {on: x, after: [echo, !generated db]}\n"},
			"a migration's commands can't hold secrets",
		},
		{
			"partial and role set a migration differently",
			map[string]string{
				"partials/x/partial.yml": "migrations:\n  m: {on: a, after: [true]}\n",
				"roles/web/role.yml":     "partials: [{partial: x}]\nmigrations:\n  m: {on: b, after: [true]}\n",
			},
			"set migrations.m.on differently",
		},
		{
			"!generated elsewhere",
			map[string]string{
				"roles/web/role.yml": "migrations:\n  m: {on: x, after: [true]}\nntp: {servers: [!generated a]}\n",
			},
			"!generated only works",
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
				if files["roles/web/docker-compose.yml"] == "" {
					delete(files, "roles/web/docker-compose.yml")
				}
				_, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")
				require.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestHostConfig_oidcClientSecretIsTheStacksGeneratedValue(t *testing.T) {
	tr := newTestRepo(t, readTestTree(t, "oidc-clients"))
	r := tr.open(t)

	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	client := c.OIDCClients["app-alpha"]
	secret := c.Stacks[0].Generated["oidc"]
	require.NotEmpty(t, secret)
	assert.Equal(t, secret, client.SecretValue)
	assert.Contains(t, stackFile(t, c.Stacks[0], "docker-compose.yml").Content, secret)
	assert.Equal(t, "app-alpha", client.Name)
	assert.Equal(t, Set{"https://app.example.com/callback"}, client.CallbackURLs)
	assert.Equal(t, Set{"admins"}, client.Groups)

	require.NoError(t, r.SaveGenerated("alpha", c.Stacks))
	saved, err := tr.open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, secret, saved.OIDCClients["app-alpha"].SecretValue)
	assert.Empty(t, saved.Stacks[0].Generated)
	assert.Empty(t, saved.Stacks[0].Unused)
}

// oidcClientYAML is role settings with one OIDC client, app, with a callback
// URL and the given settings.
func oidcClientYAML(settings string) string {
	return "oidc_clients:\n  app:\n    callback_urls: [https://app.example.com/cb]\n" + settings
}

func TestHostConfig_oidcClientSecretMayBeTheOnlyUse(t *testing.T) {
	files := readTestTree(t, "oidc-clients")
	files["roles/app/role.yml"] = oidcClientYAML("    secret: !generated other\n")

	c, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")

	require.NoError(t, err)
	assert.Equal(t, c.Stacks[0].Generated["other"], c.OIDCClients["app"].SecretValue)
}

func TestHostConfig_oidcClientWithoutCallbackURLsUsesOnlyClientCredentials(t *testing.T) {
	files := readTestTree(t, "oidc-clients")
	files["roles/app/role.yml"] = "oidc_clients:\n  app:\n    secret: !generated other\n"

	c, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")

	require.NoError(t, err)
	assert.Empty(t, c.OIDCClients["app"].CallbackURLs)
	assert.Equal(t, c.Stacks[0].Generated["other"], c.OIDCClients["app"].SecretValue)
}

func TestHostConfig_oidcClientSecretWithALength(t *testing.T) {
	files := readTestTree(t, "oidc-clients")
	files["roles/app/role.yml"] = oidcClientYAML("    secret: !generated other 48\n")

	c, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")

	require.NoError(t, err)
	assert.Len(t, c.OIDCClients["app"].SecretValue, 48)
}

func TestHostConfig_oidcClientSecretMayBeAnAgeSecret(t *testing.T) {
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":    "alpha:\n  roles: {plain: }\n",
			"roles/plain/role.yml": "",
		},
	)
	secret, err := tr.open(t).Encrypt("a-secret-from-elsewhere")
	require.NoError(t, err)
	tr.write(t, "roles/plain/role.yml", oidcClientYAML("    secret: "+strings.ReplaceAll(secret, "\n", "\n    ")+"\n"))

	c, err := tr.open(t).HostConfig("alpha", "debian")

	require.NoError(t, err)
	assert.Equal(t, "a-secret-from-elsewhere", c.OIDCClients["app"].SecretValue)
	assert.Empty(t, c.Stacks)
}

func TestHostConfig_oidcClientAgeSecretPreviewsWithoutTheIdentity(t *testing.T) {
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":    "alpha:\n  roles: {plain: }\n",
			"roles/plain/role.yml": "",
		},
	)
	secret, err := tr.open(t).Encrypt("a-secret-from-elsewhere")
	require.NoError(t, err)
	tr.write(t, "roles/plain/role.yml", oidcClientYAML("    secret: "+strings.ReplaceAll(secret, "\n", "\n    ")+"\n"))
	r, err := Open(tr.dir, func() (age.Identity, error) { return nil, errors.New("locked") })
	require.NoError(t, err)
	r.Preview(func(string) {})

	c, err := r.HostConfig("alpha", "debian")

	require.NoError(t, err)
	assert.Regexp(t, `^<age:[0-9a-f]{8}>$`, c.OIDCClients["app"].SecretValue)
}

func TestHostConfig_oidcClientLogosAreReadFromTheDeclaringFilesDirectory(t *testing.T) {
	files := readTestTree(t, "oidc-clients")
	files["hosts.d/hosts.yml"] = "alpha:\n  roles: {app: , other: }\n"
	files["roles/app/role.yml"] = oidcClientYAML(
		"    secret: !generated oidc\n    launch_url: https://app.example.com\n    logo: logos/app.svg\n",
	)
	files["roles/app/files/logos/app.svg"] = "<svg/>"
	files["roles/other/role.yml"] = "partials: [{partial: themed}]\n"
	files["partials/themed/partial.yml"] = "oidc_clients:\n  app:\n    dark_logo: dark.PNG\n"
	files["partials/themed/files/dark.PNG"] = "PNG"

	c, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")

	require.NoError(t, err)
	client := c.OIDCClients["app"]
	assert.Equal(t, "https://app.example.com", client.LaunchURL)
	assert.Equal(t, "app.svg", filepath.Base(client.Logo))
	assert.Equal(t, []byte("<svg/>"), client.LogoData)
	assert.Equal(t, []byte("PNG"), client.DarkLogoData)
}

func TestHostConfig_oidcClientErrors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			"generated secret without a stack",
			map[string]string{"roles/plain/role.yml": oidcClientYAML("    secret: !generated x\n")},
			"role plain: oidc_clients.app.secret: !generated needs a role with a stack",
		},
		{
			"generated elsewhere in a client",
			map[string]string{"roles/app/role.yml": oidcClientYAML("    name: !generated x\n")},
			"!generated only works",
		},
		{
			"plain secret",
			map[string]string{"roles/app/role.yml": oidcClientYAML("    secret: hunter2\n")},
			"expected a !generated or !age value",
		},
		{
			"public without callback URLs",
			map[string]string{"roles/app/role.yml": "oidc_clients:\n  app:\n    public: true\n"},
			"oidc_clients.app: a public client needs callback_urls",
		},
		{
			"logout callback URLs without callback URLs",
			map[string]string{
				"roles/app/role.yml": "oidc_clients:\n  app:\n    secret: !generated x\n" +
					"    logout_callback_urls: [https://app.example.com/]\n",
			},
			"oidc_clients.app: logout_callback_urls needs callback_urls",
		},
		{
			"launch URL without callback URLs",
			map[string]string{
				"roles/app/role.yml": "oidc_clients:\n  app:\n    secret: !generated x\n" +
					"    launch_url: https://app.example.com/\n",
			},
			"oidc_clients.app: launch_url needs callback_urls",
		},
		{
			"confidential without a secret",
			map[string]string{"roles/app/role.yml": oidcClientYAML("    name: App\n")},
			"oidc_clients.app: needs a !generated or !age secret, or public: true",
		},
		{
			"public with a secret",
			map[string]string{"roles/app/role.yml": oidcClientYAML("    public: true\n    secret: !generated x\n")},
			"oidc_clients.app: a public client has no secret",
		},
		{
			"two roles set the secret",
			map[string]string{
				"roles/app/role.yml":             oidcClientYAML("    secret: !generated x\n"),
				"roles/other/role.yml":           oidcClientYAML("    secret: !generated x\n"),
				"roles/other/docker-compose.yml": "services: {}\n",
			},
			"roles app and other both set oidc_clients.app.secret",
		},
		{
			"logo outside the files directory",
			map[string]string{"roles/app/role.yml": oidcClientYAML("    public: true\n    logo: ../role.yml\n")},
			`oidc_clients.app: logo "../role.yml" isn't a path in files`,
		},
		{
			"logo that isn't an image",
			map[string]string{
				"roles/app/role.yml":      oidcClientYAML("    public: true\n    dark_logo: app.txt\n"),
				"roles/app/files/app.txt": "text",
			},
			"a logo must be one of .png, .jpg",
		},
		{
			"missing logo",
			map[string]string{"roles/app/role.yml": oidcClientYAML("    public: true\n    logo: app.png\n")},
			"no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := map[string]string{
					"hosts.d/hosts.yml":            "alpha:\n  roles: {app: , plain: , other: }\n",
					"roles/app/docker-compose.yml": "services: {}\n",
					"roles/plain/role.yml":         "",
					"roles/other/role.yml":         "",
				}
				maps.Copy(files, tt.files)
				_, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")
				require.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestSaveOIDCClient_recordsClientsForTheHost(t *testing.T) {
	tr := newTestRepo(t, readTestTree(t, "oidc-clients"))
	r := tr.open(t)
	clients := func() map[string]SavedOIDCClient { return tr.open(t).Inventory().Hosts["alpha"].OIDCClients }
	logo := SavedOIDCClient{Logo: "abc"}

	require.NoError(t, r.SaveOIDCClient("alpha", "app", SavedOIDCClient{SecretID: "secret-1"}))
	require.NoError(t, r.SaveOIDCClient("alpha", "public", logo))
	require.NoError(t, r.SaveOIDCClient("alpha", "app", SavedOIDCClient{SecretID: "secret-2"}))
	assert.Equal(t, map[string]SavedOIDCClient{"app": {SecretID: "secret-2"}, "public": logo}, clients())

	require.NoError(t, r.DropOIDCClient("alpha", "app"))
	assert.Equal(t, map[string]SavedOIDCClient{"public": logo}, clients())
}

func TestHostConfig_oidcAPIGrantsMergeAcrossRoles(t *testing.T) {
	files := map[string]string{
		"hosts.d/hosts.yml": "alpha:\n  roles: {pb: , app: }\n",
		"roles/pb/role.yml": "oidc_apis:\n" +
			"  https://pb.example.net/:\n" +
			"    permissions:\n" +
			"      read: {name: Read records}\n" +
			"      write: {description: Change records}\n" +
			"    clients:\n" +
			"      backup:\n",
		"roles/app/role.yml": "oidc_apis:\n  https://pb.example.net/:\n" +
			"    clients:\n      app: [read, write]\n" +
			"    users:\n      app: [read]\n",
	}

	c, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")

	require.NoError(t, err)
	assert.Equal(
		t,
		map[string]OIDCAPIConfig{
			"https://pb.example.net": {
				Name: "https://pb.example.net",
				Permissions: map[string]OIDCPermissionConfig{
					"read":  {Name: "Read records"},
					"write": {Name: "write", Description: "Change records"},
				},
				Clients: map[string]Set{"app": {"read", "write"}, "backup": nil},
				Users:   map[string]Set{"app": {"read"}},
			},
		},
		c.OIDCAPIs,
	)
}

func TestHostConfig_oidcAPIErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			"grant of an undeclared permission",
			"oidc_apis:\n  https://pb.example.net:\n    clients:\n      app: [read]\n",
			`oidc_apis.https://pb.example.net.clients.app: no permission "read"`,
		},
		{
			"user grant of an undeclared permission",
			"oidc_apis:\n  https://pb.example.net:\n    users:\n      app: [read]\n",
			`oidc_apis.https://pb.example.net.users.app: no permission "read"`,
		},
		{
			"identifier declared twice",
			"oidc_apis:\n  https://pb.example.net: {}\n  https://pb.example.net/: {}\n",
			"oidc_apis.https://pb.example.net/: https://pb.example.net is already declared",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {pb: }\n", "roles/pb/role.yml": tt.yaml}
				_, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")
				require.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestSaveOIDCAPI_recordsAPIsForTheHost(t *testing.T) {
	tr := newTestRepo(t, readTestTree(t, "oidc-clients"))
	r := tr.open(t)
	apis := func() Set { return tr.open(t).Inventory().Hosts["alpha"].OIDCAPIs }

	require.NoError(t, r.SaveOIDCAPI("alpha", "https://b.example.net"))
	require.NoError(t, r.SaveOIDCAPI("alpha", "https://a.example.net"))
	require.NoError(t, r.SaveOIDCAPI("alpha", "https://b.example.net"))
	assert.ElementsMatch(t, Set{"https://a.example.net", "https://b.example.net"}, apis())

	require.NoError(t, r.DropOIDCAPI("alpha", "https://b.example.net"))
	assert.Equal(t, Set{"https://a.example.net"}, apis())
}

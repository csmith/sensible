package config

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readTestTree reads the files under a directory in testdata, by their
// paths within it.
func readTestTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	root := filepath.Join("testdata", dir)
	err := filepath.WalkDir(
		root,
		func(path string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			files[rel] = string(b)
			return nil
		},
	)
	require.NoError(t, err)
	return files
}

// withPartials adds the test partials to files.
func withPartials(t *testing.T, files map[string]string) map[string]string {
	t.Helper()
	maps.Copy(files, readTestTree(t, "partials/shared"))
	return files
}

func TestPartials_matchHandWrittenStack(t *testing.T) {
	handWritten := withPartials(t, readTestTree(t, "partials/hand-written"))
	fromPartials := withPartials(t, readTestTree(t, "partials/from-partials"))

	render := func(files map[string]string) Config {
		files["hosts.d/hosts.yml"] = "alpha:\n  roles: {web: {db_user: alice}}\n"
		tr := newTestRepo(t, files)
		password, err := tr.open(t).Encrypt("pa$$word")
		require.NoError(t, err)
		for _, name := range []string{"roles/web/role.yml", "roles/web/docker-compose.yml"} {
			writeFile(t, tr.dir, name, strings.Replace(files[name], "SECRET", strings.ReplaceAll(password, "\n", "\n      "), 1))
		}
		c, err := tr.open(t).HostConfig("alpha", "debian")
		require.NoError(t, err)
		return c
	}
	want := render(handWritten)
	got := render(fromPartials)

	assert.Equal(t, want.Volumes, got.Volumes)
	assert.Equal(t, want.Backups, got.Backups)
	require.Len(t, got.Stacks, 1)
	assert.Equal(t, want.Stacks[0].Name, got.Stacks[0].Name)
	compose := got.Stacks[0].Files[0]
	assert.Equal(t, want.Stacks[0].Files[0].Secrets, compose.Secrets)
	assert.Equal(t, normaliseYAML(t, want.Stacks[0].Files[0].Content), normaliseYAML(t, compose.Content))
	assert.Contains(t, compose.Content, "# The app.")
	assert.Contains(t, compose.Content, "# Comments in partials are kept.")
}

func normaliseYAML(t *testing.T, content string) any {
	t.Helper()
	var v any
	require.NoError(t, yaml.Unmarshal([]byte(content), &v), content)
	return v
}

func TestPartials_stackFromPartialsAlone(t *testing.T) {
	files := map[string]string{
		"hosts.d/hosts.yml": "alpha:\n  roles: {proxy: }\n",
		"roles/proxy/role.yml": `
partials:
  - {partial: tailscale-proxy, hostname: !vhost proxy.example.com, upstream: "http://app:80"}
`,
	}
	r := newTestRepo(t, withPartials(t, files)).open(t)
	assert.Equal(t, map[string][]string{"proxy.example.com": {"alpha"}}, r.Vhosts())

	c, err := r.HostConfig("alpha", "debian")
	require.NoError(t, err)
	require.Len(t, c.Stacks, 1)
	assert.Equal(
		t,
		map[string]any{
			"services": map[string]any{
				"thp": map[string]any{
					"image":     "thp:dev",
					"read_only": true,
					"restart":   "unless-stopped",
					"volumes":   []any{"/srv/volumes/proxy/tailscale:/config"},
					"environment": map[string]any{
						"REDIRECT":           "true",
						"UPSTREAM":           "http://app:80",
						"TAILSCALE_HOSTNAME": "proxy.example.com",
						"TEMPLATE":           "{hostname}",
					},
				},
			},
		},
		normaliseYAML(t, c.Stacks[0].Files[0].Content),
	)
	assert.Equal(t, map[string]BackupConfig{"proxy-tailscale": {Path: "/srv/volumes/proxy/tailscale"}}, c.Backups)
}

func TestPartials_nullDropsKey(t *testing.T) {
	files := map[string]string{
		"hosts.d/hosts.yml":    "alpha:\n  roles: {proxy: }\n",
		"roles/proxy/role.yml": "partials:\n  - {partial: tailscale-proxy}\n",
	}
	c, err := newTestRepo(t, withPartials(t, files)).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.NotContains(t, c.Stacks[0].Files[0].Content, "UPSTREAM")
	assert.NotContains(t, c.Stacks[0].Files[0].Content, "TAILSCALE_HOSTNAME")
}

func TestPartials_settingsOnly(t *testing.T) {
	c, err := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {tools: {extra: htop}}\n",
			"partials/apt/partial.yml": "params:\n  packages: []\n  uid: 0\n" +
				"packages:\n  install: \"{packages}\"\n" +
				"users:\n  \"u{uid}\": {}\n",
			"roles/tools/role.yml": "params:\n  extra: ~\n" +
				"partials:\n  - {partial: apt, packages: [vim, !param extra], uid: 7}\n" +
				"packages:\n  install: [git]\n",
			"partials/unused/partial.yml": "",
		},
	).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Empty(t, c.Stacks)
	assert.Equal(t, Set{"vim", "htop", "git"}, c.Packages.Install)
	assert.Equal(t, map[string]UserConfig{"u7": {}}, c.Users)
}

func TestPartials_nested(t *testing.T) {
	c, err := newTestRepo(t, readTestTree(t, "partials/nested")).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	require.Len(t, c.Stacks, 1)
	s := c.Stacks[0]
	db := s.Generated["db"]
	require.NotEmpty(t, db)

	assert.Equal(
		t,
		map[string]any{
			"services": map[string]any{
				"pg": map[string]any{"image": "postgres", "environment": map[string]any{"POSTGRES_PASSWORD": db}},
			},
		},
		normaliseYAML(t, stackFile(t, s, "docker-compose.yml").Content),
	)
	assert.Equal(t, "LOG_LEVEL='lvl-debug'\nPG_PASSWORD='"+db+"'\n", stackFile(t, s, ".env").Content)
	assert.Equal(
		t,
		[]Migration{{Name: "pg-password", On: db, Secret: true, After: Command{"psql", "-c", "ALTER USER u-pg"}}},
		s.Migrations,
	)
	assert.Equal(t, map[string]BackupConfig{"app-pg": {Command: Command{"dump", "pg"}}}, c.Backups)
}

func TestPartials_nestedDefaults(t *testing.T) {
	files := map[string]string{
		"hosts.d/hosts.yml":          "alpha:\n  roles: {tools: }\n",
		"partials/inner/partial.yml": "params:\n  pkg: vim\npackages:\n  install: [\"{pkg}\"]\n",
		"partials/outer/partial.yml": "params:\n  pkg: ~\npartials:\n  - {partial: inner, pkg: \"{pkg}\"}\n",
		"roles/tools/role.yml":       "partials: [{partial: outer}]\n",
	}
	c, err := newTestRepo(t, files).open(t).HostConfig("alpha", "debian")
	require.NoError(t, err)
	assert.Equal(t, Set{"vim"}, c.Packages.Install, "a null argument leaves the default")
}

func TestPartials_errors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			"unknown partial",
			map[string]string{"roles/web/role.yml": "partials: [{partial: nope}]\n"},
			`partial "nope" isn't in`,
		},
		{
			"unknown argument",
			map[string]string{"roles/web/role.yml": "partials: [{partial: tailscale-proxy, colour: red}]\n"},
			`unknown parameter "colour"`,
		},
		{
			"unknown placeholder",
			map[string]string{
				"partials/x/partial.yml": "jobs:\n  \"{name}\": {command: [a], schedule: daily}\n",
				"roles/web/role.yml":     "partials: [{partial: x}]\n",
			},
			"partials/x/partial.yml: [2:3] unknown placeholder {name}",
		},
		{
			"unquoted placeholder",
			map[string]string{
				"partials/x/partial.yml":        "params: {image: a}\n",
				"partials/x/docker-compose.yml": "services:\n  a:\n    image: {image}\n",
				"roles/web/role.yml":            "partials: [{partial: x}]\n",
			},
			"quote placeholders",
		},
		{
			"!param in a partial",
			map[string]string{"partials/x/partial.yml": "ntp:\n  servers: [!param a]\n"},
			"not !param",
		},
		{
			"missing partial.yml",
			map[string]string{"partials/x/docker-compose.yml": "services: {}\n"},
			"partials/x: missing partial.yml",
		},
		{
			"unexpected file",
			map[string]string{"partials/x/partial.yml": "", "partials/x/other.conf": ""},
			"partials/x/other.conf: unexpected file",
		},
		{
			"compose.files",
			map[string]string{"partials/x/partial.yml": "compose:\n  files: [a]\n"},
			"a partial can't set compose.files",
		},
		{
			"stack parameter",
			map[string]string{"partials/x/partial.yml": "params:\n  stack: a\n"},
			"can't be a parameter",
		},
		{
			"partials conflict",
			map[string]string{
				"roles/web/role.yml": "partials:\n" +
					"  - {partial: tailscale-proxy, volume: a, upstream: x}\n" +
					"  - {partial: tailscale-proxy, volume: b, upstream: y}\n",
			},
			"partial tailscale-proxy and partial tailscale-proxy set services.thp.environment.UPSTREAM differently",
		},
		{
			"role compose conflicts with a partial",
			map[string]string{
				"roles/web/role.yml":           "partials: [{partial: tailscale-proxy}]\n",
				"roles/web/docker-compose.yml": "services:\n  thp:\n    restart: always\n",
			},
			"partial tailscale-proxy and ",
		},
		{
			"role settings conflict with a partial",
			map[string]string{
				"roles/web/role.yml": "partials: [{partial: tailscale-proxy}]\nbackups:\n  web-tailscale: {path: /elsewhere}\n",
			},
			"set backups.web-tailscale.path differently",
		},
		{
			"role volume conflicts with a partial",
			map[string]string{
				"roles/web/role.yml": "partials: [{partial: tailscale-proxy}]\ncompose:\n  volumes: {tailscale: {owner: 1}}\n",
			},
			"role.yml and partial tailscale-proxy set volume tailscale differently",
		},
		{
			"volume from a role parameter",
			map[string]string{
				"roles/web/role.yml": "params: {v: a}\npartials: [{partial: tailscale-proxy, volume: !param v}]\n",
			},
			"volumes can't",
		},
		{
			"nested partials conflict",
			map[string]string{
				"partials/x/partial.yml": "partials: [{partial: tailscale-proxy, upstream: x}]\n",
				"roles/web/role.yml":     "partials: [{partial: x}, {partial: tailscale-proxy, upstream: y}]\n",
			},
			"partial x > tailscale-proxy and partial tailscale-proxy set services.thp.environment.UPSTREAM differently",
		},
		{
			"include cycle",
			map[string]string{
				"partials/a/partial.yml": "partials: [{partial: b}]\n",
				"partials/b/partial.yml": "partials: [{partial: c}]\n",
				"partials/c/partial.yml": "partials: [{partial: a}]\n",
			},
			"partials/c/partial.yml: partials include each other: a > b > c > a",
		},
		{
			"partial includes itself",
			map[string]string{"partials/a/partial.yml": "partials: [{partial: a}]\n"},
			"partials include each other: a > a",
		},
		{
			"unknown included partial",
			map[string]string{"partials/x/partial.yml": "partials: [{partial: nope}]\n"},
			`partials/x/partial.yml: [1:12] partial "nope" isn't in`,
		},
		{
			"unknown included argument",
			map[string]string{"partials/x/partial.yml": "partials: [{partial: tailscale-proxy, colour: red}]\n"},
			`partials/x/partial.yml: partial tailscale-proxy: [1:39] unknown parameter "colour"`,
		},
		{
			"unknown placeholder in an included argument",
			map[string]string{"partials/x/partial.yml": "partials: [{partial: tailscale-proxy, upstream: \"{nope}\"}]\n"},
			"unknown placeholder {nope}",
		},
		{
			"volume from a role parameter through a partial",
			map[string]string{
				"partials/x/partial.yml": "params: {v: ~}\npartials: [{partial: tailscale-proxy, volume: \"ts-{v}\"}]\n",
				"roles/web/role.yml":     "params: {v: a}\npartials: [{partial: x, v: !param v}]\n",
			},
			"volumes can't",
		},
		{
			"mapping in a longer string",
			map[string]string{
				"partials/x/partial.yml": "params: {a: {b: c}}\nntp:\n  servers: [\"x{a}\"]\n",
				"roles/web/role.yml":     "partials: [{partial: x}]\n",
			},
			"{a} must be a string, number or bool",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := withPartials(
					t,
					map[string]string{"hosts.d/hosts.yml": "alpha:\n  roles: {web: }\n", "roles/web/role.yml": ""},
				)
				maps.Copy(files, tt.files)
				r, err := newTestRepo(t, files).tryOpen()
				if err == nil {
					_, err = r.HostConfig("alpha", "debian")
				}
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}
}

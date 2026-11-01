package config

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
			"roles/group/role.yml":         "children: [one]\n",
			"roles/group/one/docker-compose.yml": `services:
  app:
    image: app
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
		[]StackFile{{Path: "docker-compose.yml", Content: "services:\n  app:\n    image: app\n", Perms: defaults}},
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
		map[string]Volume{
			"data":    {Owner: "70", Mode: 0o700},
			"uploads": {Owner: "alice", Group: "users", Mode: fs.FileMode(0o750)},
		},
		web.Volumes,
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
			`volume "db" isn't in the role's compose.volumes`,
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

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(b)
}

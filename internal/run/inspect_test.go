package run

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

func TestRunnerFacts_printsReachableHostsAndReportsTheRest(t *testing.T) {
	f := newRunnerFixture(t, nil)
	acidburn := &fakeAgent{facts: host.Facts{OSFamily: "debian", Release: "trixie"}}
	penderghast := &fakeAgent{facts: host.Facts{OSFamily: "arch"}}
	targets := []target{
		f.target("acidburn", acidburn),
		{name: "smarts", err: errors.New("no credentials")},
		f.target("penderghast", penderghast),
	}
	var out bytes.Buffer

	err := f.runner.Facts(t.Context(), targets, &out)

	require.ErrorIs(t, err, errFailed)
	var facts map[string]host.Facts
	require.NoError(t, json.Unmarshal(out.Bytes(), &facts))
	assert.Equal(
		t,
		map[string]host.Facts{
			"acidburn":    {OSFamily: "debian", Release: "trixie"},
			"penderghast": {OSFamily: "arch"},
		},
		facts,
	)
	assert.Contains(t, f.out.String(), "✗ smarts: no credentials")
	assert.Equal(t, []string{"FactsRequest", "Bye"}, acidburn.messages())
}

func TestRunnerFacts_succeedsWhenEveryHostIsReached(t *testing.T) {
	f := newRunnerFixture(t, nil)
	var out bytes.Buffer

	err := f.runner.Facts(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, &out)

	require.NoError(t, err)
	assert.Contains(t, out.String(), `"acidburn"`)
}

func TestEncryptSecret_ignoresInvalidRoles(t *testing.T) {
	_, dir, _ := testRepo(t)
	writeFile(t, filepath.Join(dir, "roles", "web", "role.yml"), "compose:\n  files: [.env.age]\n")
	writeFile(t, filepath.Join(dir, "roles", "web", "docker-compose.yml"), "")
	var out bytes.Buffer

	require.NoError(t, EncryptSecret(dir, true, strings.NewReader("A=b\n"), &out))

	assert.Contains(t, out.String(), "BEGIN AGE ENCRYPTED FILE")
}

func TestSecretAt(t *testing.T) {
	repo, dir, _ := testRepo(t)
	key, err := repo.Encrypt("very secret")
	require.NoError(t, err)
	file := filepath.Join(dir, "sensible.yml")
	writeFile(t, file, "dns:\n  hostname: acidburn.example.com\n  auth_key: "+indentYAML(key)+"\n")

	armored, err := secretAt(file, "dns.auth_key")
	require.NoError(t, err)
	assert.Contains(t, armored, "BEGIN AGE ENCRYPTED FILE")

	_, err = secretAt(file, "dns.hostname")
	assert.ErrorContains(t, err, "isn't an !age value")
}

func TestRunnerRender_textShowsFilesInFullAndTheRestOnALine(t *testing.T) {
	f := newRunnerFixture(
		t,
		host.ResourceList{
			host.File{
				Path:     "/etc/app.conf",
				Content:  "a = 1\nb = 2",
				Owner:    "root",
				Mode:     0o640,
				Validate: []string{"app", "-t", "%s"},
				Notify:   host.ResourceList{host.ServiceAction{Name: "app", Action: "reload"}},
			},
			host.Dir{Path: "/srv/app", Owner: "app", Group: "app", Mode: 0o750},
			host.Package{Name: "zsh"},
			host.Download{URL: "https://example.com/x", Path: "/usr/local/bin/x", SHA256: "abc", Mode: 0o755},
		},
	)
	var out bytes.Buffer

	err := f.runner.Render(
		t.Context(),
		[]target{{name: "acidburn"}, {name: "smarts"}},
		map[string]host.Facts{"acidburn": {OSFamily: "arch"}},
		&out,
		false,
	)

	require.ErrorIs(t, err, errFailed)
	want, err := os.ReadFile(filepath.Join("testdata", "render.txt"))
	require.NoError(t, err)
	assert.Equal(t, string(want), out.String())
	assert.Contains(t, f.out.String(), "✗ smarts: no facts for this host")
}

func TestRunnerRender_jsonConnectsForFacts(t *testing.T) {
	f := newRunnerFixture(t, nil)
	var facts host.Facts
	f.runner.Compile = func(_ target, got host.Facts) (compiled, error) {
		facts = got
		return compiled{resources: host.ResourceList{host.File{Path: "/etc/a", Content: "x"}}}, nil
	}
	agent := &fakeAgent{facts: host.Facts{OSFamily: "debian", Release: "trixie"}}
	var out bytes.Buffer

	err := f.runner.Render(t.Context(), []target{f.target("acidburn", agent)}, nil, &out, true)

	require.NoError(t, err)
	assert.Equal(t, host.Facts{OSFamily: "debian", Release: "trixie"}, facts)
	assert.Equal(t, []string{"FactsRequest", "Bye"}, agent.messages())
	var got map[string][]map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Len(t, got["acidburn"], 1)
	assert.Equal(t, "File", got["acidburn"][0]["type"])
	assert.Equal(t, "file:/etc/a", got["acidburn"][0]["id"])
	assert.Equal(t, "x", got["acidburn"][0]["content"])
}

func TestPreviewTarget_keyWithoutIdentityIsAPlaceholder(t *testing.T) {
	repo, dir, _ := testRepo(t)
	key, err := repo.Encrypt("a private key")
	require.NoError(t, err)
	writeFile(t, filepath.Join(dir, "hosts.d", "acidburn.state.yml"), "acidburn:\n  ssh_key: "+indentYAML(key)+"\n")

	locked, err := config.Open(dir, func() (age.Identity, error) { return nil, errors.New("locked") })
	require.NoError(t, err)
	locked.Preview(nil)
	tg := previewTarget(locked, "acidburn")
	require.NoError(t, tg.err)
	placeholder := locked.Inventory().Hosts["acidburn"].SSHKey.Placeholder()
	assert.Equal(t, placeholder+" sensible@acidburn", tg.sensibleKey)

	assert.ErrorContains(t, newTarget(locked, "acidburn", nil).err, "use --facts")
}

func TestRender_connectingNeedsTheIdentity(t *testing.T) {
	_, dir, _ := testRepo(t)

	err := Render(t.Context(), RenderOptions{ConfigDir: dir}, &bytes.Buffer{})

	assert.ErrorContains(t, err, "use --facts")
}

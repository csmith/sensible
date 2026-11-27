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
	acidburn := &fakeAgent{
		facts: host.Facts{OSFamily: "debian", Release: "trixie"},
	}
	penderghast := &fakeAgent{
		facts: host.Facts{OSFamily: "arch"},
	}
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

	err := f.runner.Facts(
		t.Context(),
		[]target{
			f.target("acidburn", &fakeAgent{}),
		},
		&out,
	)

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

	content, err := os.ReadFile(file)
	require.NoError(t, err)

	armored, err := secretAt(file, content, "dns.auth_key")
	require.NoError(t, err)
	assert.Contains(t, armored, "BEGIN AGE ENCRYPTED FILE")

	_, err = secretAt(file, content, "dns.hostname")
	assert.ErrorContains(t, err, "no !age value at dns.hostname")
}

func TestShowSecret_listsPathsThatItAccepts(t *testing.T) {
	repo, dir, _ := testRepo(t)
	encrypt := func(plain string) string {
		value, err := repo.Encrypt(plain)
		require.NoError(t, err)
		return strings.ReplaceAll(value, "\n", "\n        ")
	}
	file := filepath.Join(dir, "secrets.yml")
	writeFile(
		t,
		file,
		"plain: value\n"+
			"top: "+encrypt("top")+"\n"+
			"acidburn.example.com:\n"+
			"  key: "+encrypt("dotted")+"\n"+
			"\"quoted\": "+encrypt("quoted")+"\n"+
			"it's: "+encrypt("apostrophe")+"\n"+
			"anchored: &a "+encrypt("anchored")+"\n"+
			"alias: *a\n"+
			"replaced: !replace\n"+
			"  key: "+encrypt("replaced")+"\n"+
			"items:\n"+
			"  - name: first\n"+
			"  - name: second\n"+
			"    key: "+encrypt("item")+"\n",
	)
	var out bytes.Buffer

	require.NoError(t, ShowSecret(dir, "secrets.yml", "", &out))

	paths := strings.Split(strings.TrimSpace(out.String()), "\n")
	assert.Equal(
		t,
		[]string{
			"top",
			"'acidburn.example.com'.key",
			"quoted",
			`'it\'s'`,
			"anchored",
			"replaced.key",
			"items[1].key",
		},
		paths,
	)
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		content, err := os.ReadFile(file)
		require.NoError(t, err)
		armored, err := secretAt(file, content, path)
		require.NoError(t, err)
		value, err := repo.DecryptFile(armored)
		require.NoError(t, err)
		values = append(values, value)
	}
	assert.Equal(t, []string{"top", "dotted", "quoted", "apostrophe", "anchored", "replaced", "item"}, values)
}

func TestShowSecret_listsNothingWithoutAWorkingConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "secrets.yml"), "plain: value\n")
	var out bytes.Buffer

	require.NoError(t, ShowSecret(dir, "secrets.yml", "", &out))

	assert.Empty(t, out.String())
}

func TestShowSecret_decryptsAValueAtAPath(t *testing.T) {
	dir := secretRepo(t)
	encrypted := encryptWith(t, dir, false, "very secret")
	writeFile(t, filepath.Join(dir, "secrets.yml"), "key: "+indentYAML(strings.TrimSpace(encrypted))+"\n")
	var out bytes.Buffer

	require.NoError(t, ShowSecret(dir, "secrets.yml", "key", &out))

	assert.Equal(t, "very secret\n", out.String())
}

func TestShowSecret_decryptsAWholeFileSecret(t *testing.T) {
	dir := secretRepo(t)
	writeFile(t, filepath.Join(dir, "app.env.age"), encryptWith(t, dir, true, "A=b\nC=d\n"))
	var out bytes.Buffer

	require.NoError(t, ShowSecret(dir, "app.env.age", "", &out))

	assert.Equal(t, "A=b\nC=d\n", out.String())
}

func TestShowSecret_rejectsAPathInAWholeFileSecret(t *testing.T) {
	dir := secretRepo(t)
	writeFile(t, filepath.Join(dir, "app.env.age"), encryptWith(t, dir, true, "A=b\n"))
	var out bytes.Buffer

	err := ShowSecret(dir, "app.env.age", "A", &out)

	require.ErrorContains(t, err, "whole-file secret")
	assert.Empty(t, out.String())
}

// secretRepo is a config directory whose identity_command prints the
// identity its secrets are encrypted to, as ShowSecret uses the configured
// identity.
func secretRepo(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.txt"), id.String()+"\n")
	writeFile(t, filepath.Join(dir, "hosts.d", "acidburn.yml"), "acidburn:\n  address: 192.0.2.1\n")
	writeFile(
		t,
		filepath.Join(dir, "sensible.yml"),
		"secrets:\n"+
			"  recipients: ["+id.Recipient().String()+"]\n"+
			"  identity_command: [cat, "+filepath.Join(dir, "identity.txt")+"]\n",
	)
	return dir
}

func encryptWith(t *testing.T, dir string, raw bool, plaintext string) string {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, EncryptSecret(dir, raw, strings.NewReader(plaintext), &out))
	return out.String()
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
				Notify: host.ResourceList{
					host.ServiceAction{Name: "app", Action: "reload"},
				},
			},
			host.Dir{Path: "/srv/app", Owner: "app", Group: "app", Mode: 0o750},
			host.Package{Name: "zsh"},
			host.Download{URL: "https://example.com/x", Path: "/usr/local/bin/x", SHA256: "abc", Mode: 0o755},
		},
	)
	var out bytes.Buffer

	err := f.runner.Render(
		t.Context(),
		[]target{
			{name: "acidburn"},
			{name: "smarts"},
		},
		map[string]host.Facts{
			"acidburn": {OSFamily: "arch"},
		},
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
		return compiled{
			resources: host.ResourceList{
				host.File{Path: "/etc/a", Content: "x"},
			},
		}, nil
	}
	agent := &fakeAgent{
		facts: host.Facts{OSFamily: "debian", Release: "trixie"},
	}
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

	assert.ErrorContains(t, newTarget(locked, "acidburn").err, "use --facts")
}

func TestRender_connectingNeedsTheIdentity(t *testing.T) {
	_, dir, _ := testRepo(t)

	err := Render(t.Context(), RenderOptions{ConfigDir: dir}, &bytes.Buffer{})

	assert.ErrorContains(t, err, "use --facts")
}

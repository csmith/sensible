package run

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

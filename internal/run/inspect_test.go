package run

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShowConfig(t *testing.T) {
	_, dir, _ := testRepo(t)
	writeFile(t, filepath.Join(dir, "hosts.d", "acidburn.roles.yml"), "acidburn:\n  roles: {base: }\n")
	writeFile(t, filepath.Join(dir, "roles", "base", "role.yml"), "vim: {}\nzsh:\n  plugins: [git]\n")
	var out bytes.Buffer

	require.NoError(t, ShowConfig(t.Context(), dir, "acidburn", "debian", "", &out))

	assert.Equal(t, "zsh:\n  plugins:\n  - git\nvim: {}\n", out.String())
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

package run

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShowConfig_masksSecrets(t *testing.T) {
	repo, dir := testRepo(t)
	key, err := repo.Encrypt("very secret")
	require.NoError(t, err)
	writeFile(
		t,
		filepath.Join(dir, "hosts", "acidburn.yml"),
		"dns:\n  hostname: acidburn.example.com\n  auth_key: "+indentYAML(key)+"\nzsh:\n  plugins: [git]\n",
	)
	var out bytes.Buffer

	require.NoError(t, ShowConfig(t.Context(), dir, "", "acidburn", "debian", "", &out))

	assert.Contains(t, out.String(), "hostname: acidburn.example.com")
	assert.Contains(t, out.String(), "auth_key: <secret>")
	assert.NotContains(t, out.String(), "auth_user")
	assert.NotContains(t, out.String(), "AGE ENCRYPTED")
	assert.Contains(t, out.String(), "- git")
}

func TestSecretAt(t *testing.T) {
	repo, dir := testRepo(t)
	key, err := repo.Encrypt("very secret")
	require.NoError(t, err)
	file := filepath.Join(dir, "hosts", "acidburn.yml")
	writeFile(t, file, "dns:\n  hostname: acidburn.example.com\n  auth_key: "+indentYAML(key)+"\n")

	armored, err := secretAt(file, "dns.auth_key")
	require.NoError(t, err)
	assert.Contains(t, armored, "BEGIN AGE ENCRYPTED FILE")

	_, err = secretAt(file, "dns.hostname")
	assert.ErrorContains(t, err, "isn't an !age value")
}

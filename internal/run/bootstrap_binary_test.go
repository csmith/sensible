package run

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/features"
	"chameth.com/sensible/internal/host"
)

func TestBootstrapBinary_keyRoundTrips(t *testing.T) {
	agent := []byte("\x7fELF agent")
	gotAgent, key, ok := splitBootstrapBinary(withBootstrapKey(agent, "ssh-ed25519 AAAA sensible@bootstrap"))

	require.True(t, ok)
	assert.Equal(t, agent, gotAgent)
	assert.Equal(t, "ssh-ed25519 AAAA sensible@bootstrap", key)
}

func TestBootstrapBinary_otherFilesHaveNoKey(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("\x7fELF agent"),
		[]byte(bootstrapTrailer),
		append([]byte("\xff\xff\xff\xff\xff\xff\xff\xff"), bootstrapTrailer...),
	} {
		_, _, ok := splitBootstrapBinary(data)
		assert.False(t, ok)
	}
}

func TestReadHostKeys_putsEd25519FirstAndSkipsUnknownTypes(t *testing.T) {
	dir := t.TempDir()
	rsa := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDBVBcJ6YKlL4KJ/z2+XlOm1bW9ppLSqrPSzlX/rbqTyIaGfwVm+LmLgU8XYZdvsqZsL" +
		"v+nFdTEdC2dn+gc6/8ro9oovIqm8xzc4zjkTNjEhgWE3/B4RdBR1BnaCb6ka3PbdVe5JeKjdOuVKydr2iUeSgN3V9/C2QvhSjMsNxh0yw== test\n"
	ed := authorizedKey(testKey(t), "x") + "\n"
	writeFile(t, filepath.Join(dir, "ssh_host_rsa_key.pub"), rsa)
	writeFile(t, filepath.Join(dir, "ssh_host_ed25519_key.pub"), ed)
	writeFile(t, filepath.Join(dir, "ssh_host_ed25519_key"), "private")
	writeFile(t, filepath.Join(dir, "ssh_host_mldsa44_ed25519_key.pub"), "ssh-mldsa44-ed25519 not-base64 x\n")

	keys, err := readHostKeys(dir)

	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, ssh.KeyAlgoED25519, keys[0].Type())
	assert.Equal(t, ssh.KeyAlgoRSA, keys[1].Type())
}

type bootstrapKeyFixture struct {
	*rotateFixture
	bootstrap credentials
}

// newBootstrapKeyFixture is a host a bootstrap binary set up: it accepts
// only the bootstrap key, sudo needs no password, and its host key isn't
// known yet.
func newBootstrapKeyFixture(t *testing.T) *bootstrapKeyFixture {
	t.Helper()
	_, dir, source := testRepo(t)
	f := &rotateFixture{ssh: newSSHFixture(t, "", serverKey), dir: dir, source: source}
	f.ssh.server.agent.status = func(host.Resource) host.Status { return host.StatusDrifted }
	writeFile(t, filepath.Join(dir, "hosts.d", "acidburn.yml"), "acidburn:\n  address: "+f.ssh.server.addr+"\n")
	f.repo = f.reopen(t)
	signer, err := ssh.ParsePrivateKey([]byte(f.ssh.keyPEM))
	require.NoError(t, err)
	require.NoError(t, f.repo.SaveBootstrapKey(authorizedKey(signer.PublicKey(), bootstrapKeyName), f.ssh.keyPEM))
	f.repo = f.reopen(t)
	f.creds, err = newCredentials("acidburn")
	require.NoError(t, err)
	bootstrap, err := revealBootstrapKey(f.repo.BootstrapKey())
	require.NoError(t, err)
	return &bootstrapKeyFixture{rotateFixture: f, bootstrap: bootstrap}
}

func (f *bootstrapKeyFixture) run(t *testing.T) error {
	b := &bootstrapper{
		name:               "acidburn",
		address:            f.ssh.server.addr,
		creds:              f.creds,
		builds:             f.ssh.builds,
		hostKeyFingerprint: ssh.FingerprintSHA256(f.ssh.server.hostKey.PublicKey()),
		passwordFirst:      true,
		repo:               f.repo,
		done:               func(step string) { f.steps = append(f.steps, step) },
	}
	return b.rotate(t.Context(), f.bootstrap, f.repo.Inventory().Hosts["acidburn"])
}

func TestBootstrapKey_isReplacedByTheHostsOwnCredentials(t *testing.T) {
	f := newBootstrapKeyFixture(t)

	require.NoError(t, f.run(t))

	checks := f.ssh.server.agent.checks
	require.Len(t, checks, 2)
	command, ok := checks[0][0].(host.Command)
	require.True(t, ok, "the password should be set first")
	assert.Equal(t, f.creds.password, command.Env["SENSIBLE_PASSWORD"])
	assert.Equal(t, resourceList(features.AccessFiles(f.bootstrap.authorizedKey, f.creds.authorizedKey)), checks[0][1:])

	assert.Equal(t, []ssh.PublicKey{f.creds.signer.PublicKey()}, f.ssh.server.acceptedKeys())
	assert.Equal(t, f.creds.password, f.ssh.server.currentPassword())
	key, password, pending := f.saved(t)
	assert.Equal(t, f.creds.keyPEM, key)
	assert.Equal(t, f.creds.password, password)
	assert.Empty(t, pending)
	assert.Equal(
		t,
		config.HostKeys{
			{PublicKey: f.ssh.server.hostKey.PublicKey()},
		},
		f.reopen(t).Inventory().Hosts["acidburn"].HostKeys,
	)
}

func TestBootstrapKey_recoversWhenOnlyThePasswordWasSet(t *testing.T) {
	f := newBootstrapKeyFixture(t)
	pending, err := newCredentials("acidburn")
	require.NoError(t, err)
	require.NoError(t, f.repo.SavePendingCredentials("acidburn", pending.keyPEM, pending.password))
	f.ssh.server.applied(host.Command{
		Env: map[string]string{"SENSIBLE_PASSWORD": pending.password},
	})

	require.NoError(t, f.run(t))

	assert.Equal(t, []ssh.PublicKey{f.creds.signer.PublicKey()}, f.ssh.server.acceptedKeys())
	key, _, saved := f.saved(t)
	assert.Equal(t, f.creds.keyPEM, key)
	assert.Empty(t, saved)
}

func TestBootstrapKey_recoversAndSavesTheHostKeyFromAnInterruptedRun(t *testing.T) {
	f := newBootstrapKeyFixture(t)
	pending, err := newCredentials("acidburn")
	require.NoError(t, err)
	require.NoError(t, f.repo.SavePendingCredentials("acidburn", pending.keyPEM, pending.password))
	f.ssh.server.applied(host.Command{
		Env: map[string]string{"SENSIBLE_PASSWORD": pending.password},
	})
	f.ssh.server.applied(features.AccessFiles(f.bootstrap.authorizedKey, pending.authorizedKey)[2])

	require.NoError(t, f.run(t))

	assert.Contains(t, f.steps, "saved the pending credentials an earlier bootstrap left")
	assert.Equal(t, []ssh.PublicKey{f.creds.signer.PublicKey()}, f.ssh.server.acceptedKeys())
	entry := f.reopen(t).Inventory().Hosts["acidburn"]
	assert.Len(t, entry.HostKeys, 1)
	key, _, saved := f.saved(t)
	assert.Equal(t, f.creds.keyPEM, key)
	assert.Empty(t, saved)
}

func TestBootstrap_bootstrapKeyNeedsOneToHaveBeenMade(t *testing.T) {
	_, dir, _ := testRepo(t)

	err := Bootstrap(t.Context(), BootstrapOptions{ConfigDir: dir, Host: "acidburn", BootstrapKey: true})

	require.ErrorContains(t, err, "bootstrap-binary")
}

func TestBootstrapBinary_makesTheKeyOnceAndEmbedsItsPublicHalf(t *testing.T) {
	_, dir, source := testRepo(t)
	builds := newFakeBuilds(t)
	writeAgent := func(path string) {
		t.Helper()
		require.NoError(t, writeBootstrapBinary(t.Context(), mustOpen(t, dir, source), builds, "amd64", path))
	}
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	writeAgent(first)
	writeAgent(second)

	a, err := os.ReadFile(first)
	require.NoError(t, err)
	b, err := os.ReadFile(second)
	require.NoError(t, err)
	assert.Equal(t, a, b, "building again should give the same binary")

	agent, key, ok := splitBootstrapBinary(a)
	require.True(t, ok)
	assert.Equal(t, builds["amd64"].Binary, agent)
	saved := mustOpen(t, dir, source).BootstrapKey()
	assert.Equal(t, saved.PublicKey, key)
	revealed, err := revealBootstrapKey(saved)
	require.NoError(t, err)
	assert.Equal(t, revealed.authorizedKey, key)
}

func mustOpen(t *testing.T, dir string, source config.IdentitySource) *config.Repo {
	t.Helper()
	repo, err := config.Open(dir, source)
	require.NoError(t, err)
	return repo
}

package run

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/features"
	"chameth.com/sensible/internal/host"
)

func currentOwner(t *testing.T) (string, string) {
	t.Helper()
	u, err := user.Current()
	require.NoError(t, err)
	g, err := user.LookupGroupId(u.Gid)
	require.NoError(t, err)
	return u.Username, g.Name
}

func runScript(t *testing.T, script string) error {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "sh", "-c", script).CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

func TestWriteFileScript_writesExactContentAndMode(t *testing.T) {
	owner, group := currentOwner(t)
	path := filepath.Join(t.TempDir(), "new dir", "it's here")
	content := "line one\n'quoted' \"double\" $HOME `cmd` \\ %s\nno trailing newline"

	err := runScript(
		t,
		"set -eu\n"+writeFileScript(host.File{Path: path, Content: content, Owner: owner, Group: group, Mode: 0o640}),
	)

	require.NoError(t, err)
	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, string(written))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestWriteFileScript_validatesBeforeReplacing(t *testing.T) {
	owner, group := currentOwner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))
	file := host.File{
		Path:     path,
		Owner:    owner,
		Group:    group,
		Mode:     0o600,
		Validate: []string{"grep", "-qx", "valid", "%s"},
	}

	file.Content = "invalid"
	err := runScript(t, "set -eu\n"+writeFileScript(file))
	require.Error(t, err)
	written, _ := os.ReadFile(path)
	assert.Equal(t, "original", string(written))
	entries, _ := os.ReadDir(dir)
	assert.Len(t, entries, 1, "temporary file should be removed")

	file.Content = "valid"
	require.NoError(t, runScript(t, "set -eu\n"+writeFileScript(file)))
	written, _ = os.ReadFile(path)
	assert.Equal(t, "valid", string(written))
}

func TestBootstrapScript_isValidShell(t *testing.T) {
	for _, ensureSSHD := range []bool{false, true} {
		out, err := exec.CommandContext(
			t.Context(),
			"sh",
			"-n",
			"-c",
			bootstrapScript("PASSWORD'", "/tmp/tmp.abc", "deadbeef", "ssh-ed25519 AAAA sensible@x", ensureSSHD),
		).CombinedOutput()
		assert.NoError(t, err, string(out))
	}
}

func TestBootstrapScript_onlyEnsuresSSHDWhenAsked(t *testing.T) {
	const enable = `systemctl enable --now "$sshd"`
	assert.Contains(t, bootstrapScript("p", "/tmp/t", "h", "k", true), enable)
	assert.NotContains(t, bootstrapScript("p", "/tmp/t", "h", "k", false), enable)
}

func TestReadLocalHostKey(t *testing.T) {
	key := testKey(t)
	path := filepath.Join(t.TempDir(), "host_key.pub")
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0o600))

	b := &bootstrapper{name: "newbox"}
	require.NoError(t, b.readLocalHostKey(path))
	assert.Equal(t, key.Marshal(), b.newHostKey.Marshal())

	b = &bootstrapper{name: "newbox", hostKeyFingerprint: ssh.FingerprintSHA256(key)}
	require.NoError(t, b.readLocalHostKey(path))
	assert.Equal(t, key.Marshal(), b.newHostKey.Marshal())

	b = &bootstrapper{name: "newbox", hostKeyFingerprint: ssh.FingerprintSHA256(testKey(t))}
	require.ErrorContains(t, b.readLocalHostKey(path), ssh.FingerprintSHA256(key))
	assert.Nil(t, b.newHostKey)
}

func TestReadLocalHostKey_knownKeysAreLeftToTheConnection(t *testing.T) {
	b := &bootstrapper{name: "acidburn", known: []config.HostKey{{PublicKey: testKey(t)}}}

	require.NoError(t, b.readLocalHostKey(filepath.Join(t.TempDir(), "missing")))
	assert.Nil(t, b.newHostKey)
}

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return key
}

type hostKeyFixture struct {
	known   ssh.PublicKey
	remote  net.Addr
	prompts []string
}

func newHostKeyFixture(t *testing.T) *hostKeyFixture {
	t.Helper()
	return &hostKeyFixture{known: testKey(t), remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}}
}

// bootstrapper is for a host that already has the fixture's key if it's
// acidburn, and has no keys otherwise.
func (f *hostKeyFixture) bootstrapper(name string, answer bool) *bootstrapper {
	var known []config.HostKey
	if name == "acidburn" {
		known = []config.HostKey{{PublicKey: f.known}}
	}
	return &bootstrapper{
		name:  name,
		known: known,
		confirm: func(prompt string) (bool, error) {
			f.prompts = append(f.prompts, prompt)
			return answer, nil
		},
	}
}

func TestBootstrapHostKey_knownKeyMatches(t *testing.T) {
	f := newHostKeyFixture(t)
	b := f.bootstrapper("acidburn", false)

	require.NoError(t, b.hostKey()("192.0.2.1:22", f.remote, f.known))
	assert.Empty(t, f.prompts)
	assert.Nil(t, b.newHostKey)
}

func TestBootstrapHostKey_changedKeyIsRefusedWithoutAsking(t *testing.T) {
	f := newHostKeyFixture(t)

	require.Error(t, f.bootstrapper("acidburn", true).hostKey()("192.0.2.1:22", f.remote, testKey(t)))
	assert.Empty(t, f.prompts)
}

func TestBootstrapHostKey_unknownKeyIsAcceptedAfterConfirmation(t *testing.T) {
	f := newHostKeyFixture(t)
	key := testKey(t)
	b := f.bootstrapper("newbox", true)

	require.NoError(t, b.hostKey()("192.0.2.1:22", f.remote, key))
	require.Len(t, f.prompts, 1)
	assert.Contains(t, f.prompts[0], ssh.FingerprintSHA256(key))
	assert.Equal(t, key, b.newHostKey)
}

func TestBootstrapHostKey_unknownKeyIsRefusedIfNotConfirmed(t *testing.T) {
	f := newHostKeyFixture(t)
	b := f.bootstrapper("newbox", false)

	require.Error(t, b.hostKey()("192.0.2.1:22", f.remote, testKey(t)))
	assert.Nil(t, b.newHostKey)
}

func TestBootstrapHostKey_unknownKeyIsCheckedAgainstGivenFingerprint(t *testing.T) {
	f := newHostKeyFixture(t)
	key := testKey(t)

	b := f.bootstrapper("newbox", false)
	b.hostKeyFingerprint = ssh.FingerprintSHA256(key)
	require.NoError(t, b.hostKey()("192.0.2.1:22", f.remote, key))
	assert.Equal(t, key, b.newHostKey)

	other := f.bootstrapper("newbox", true)
	other.hostKeyFingerprint = ssh.FingerprintSHA256(testKey(t))
	require.ErrorContains(t, other.hostKey()("192.0.2.1:22", f.remote, key), ssh.FingerprintSHA256(key))
	assert.Nil(t, other.newHostKey)
	assert.Empty(t, f.prompts)
}

func TestBootstrapVerify_retriesRefusedConnectionsUntilTimeout(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := l.Addr().String()
	require.NoError(t, l.Close())

	timeout, interval := verifyTimeout, verifyRetryInterval
	verifyTimeout, verifyRetryInterval = 300*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { verifyTimeout, verifyRetryInterval = timeout, interval })

	creds, err := newCredentials("newbox")
	require.NoError(t, err)
	b := &bootstrapper{name: "newbox", address: address, creds: creds, builds: newFakeBuilds(t)}

	start := time.Now()
	err = b.verify(t.Context())
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
	assert.GreaterOrEqual(t, time.Since(start), verifyTimeout)
}

func TestNewCredentials(t *testing.T) {
	creds, err := newCredentials("acidburn")
	require.NoError(t, err)

	signer, err := ssh.ParsePrivateKey([]byte(creds.keyPEM))
	require.NoError(t, err)
	assert.Equal(t, creds.signer.PublicKey().Marshal(), signer.PublicKey().Marshal())
	assert.Equal(t, authorizedKey(signer.PublicKey(), "acidburn"), creds.authorizedKey)
	assert.NotEmpty(t, creds.password)

	other, err := newCredentials("acidburn")
	require.NoError(t, err)
	assert.NotEqual(t, creds.password, other.password)
}

func TestRotate_setsPasswordAndKeyThroughExistingAgent(t *testing.T) {
	repo, _, _ := testRepo(t)
	f := newSSHFixture(t, "hunter2", serverKey)
	require.NoError(t, repo.WriteCredentials("acidburn", f.keyPEM, "hunter2", time.Now()))
	existing := repo.Inventory().Hosts["acidburn"]
	creds, err := newCredentials("acidburn")
	require.NoError(t, err)

	b := &bootstrapper{
		name:    "acidburn",
		address: f.server.addr,
		creds:   creds,
		builds:  f.builds,
		known:   serverKey(f.server),
	}
	signer, password, err := revealCredentials(existing)
	require.NoError(t, err)
	require.NoError(t, b.rotate(t.Context(), signer, password))

	require.Len(t, f.server.agent.checks, 1)
	resources := f.server.agent.checks[0]
	command, ok := resources[0].(host.Command)
	require.True(t, ok)
	assert.Equal(t, creds.password, command.Env["SENSIBLE_PASSWORD"])
	files := make([]host.File, len(resources)-1)
	for i, r := range resources[1:] {
		files[i] = r.(host.File)
	}
	assert.Equal(t, features.AccessFiles(creds.authorizedKey), files)
	assert.Contains(t, f.server.agent.messages(), "Apply")
}

func TestBootstrap_acceptsAnyAccount(t *testing.T) {
	_, dir, _ := testRepo(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := Bootstrap(ctx, BootstrapOptions{ConfigDir: dir, Host: "acidburn", User: "deploy"})
	assert.ErrorIs(t, err, context.Canceled, "should get as far as connecting")
}

type sudoFixture struct {
	accepted map[string]bool
	commands []string
	stdins   []string
	prompts  int
}

func (f *sudoFixture) run(command string, stdin io.Reader) error {
	f.commands = append(f.commands, command)
	in := ""
	if stdin != nil {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		in = string(data)
	}
	f.stdins = append(f.stdins, in)
	if !f.accepted[command+" "+in] {
		return errors.New("sudo: a password is required")
	}
	return nil
}

func (f *sudoFixture) password() (string, error) {
	f.prompts++
	return "hunter2", nil
}

func TestSudoShell_usesSudoAsItIsWhenItNeedsNoPassword(t *testing.T) {
	f := &sudoFixture{accepted: map[string]bool{"sudo -n true ": true}}

	command, input, err := sudoShell(f.run, f.password)

	require.NoError(t, err)
	assert.Equal(t, "sudo sh -s", command)
	assert.Empty(t, input)
	assert.Zero(t, f.prompts)
}

func TestSudoShell_givesThePasswordAheadOfTheScript(t *testing.T) {
	f := &sudoFixture{accepted: map[string]bool{"sudo -k -S -p '' true hunter2\n": true}}

	command, input, err := sudoShell(f.run, f.password)

	require.NoError(t, err)
	assert.Equal(t, "sudo -k -S -p '' sh -s", command)
	assert.Equal(t, "hunter2\n", input)
	assert.Equal(t, 1, f.prompts)
}

func TestSudoShell_rejectedPasswordIsReported(t *testing.T) {
	f := &sudoFixture{}

	_, _, err := sudoShell(f.run, f.password)

	require.ErrorContains(t, err, "a password is required")
	assert.Equal(t, []string{"sudo -n true", "sudo -k -S -p '' true"}, f.commands)
}

func TestSudoShell_passwordPromptFailureIsReported(t *testing.T) {
	f := &sudoFixture{}

	_, _, err := sudoShell(f.run, func() (string, error) { return "", errNoTerminal })

	require.ErrorIs(t, err, errNoTerminal)
	assert.Equal(t, []string{"sudo -n true"}, f.commands)
}

func TestBootstrap_thisMachineRefusesUser(t *testing.T) {
	_, dir, _ := testRepo(t)
	hostname, err := os.Hostname()
	require.NoError(t, err)
	writeFile(t, filepath.Join(dir, "hosts.d", "local.yml"), hostname+":\n  address: 192.0.2.2\n")

	err = Bootstrap(t.Context(), BootstrapOptions{ConfigDir: dir, Host: hostname, User: "deploy"})
	assert.ErrorContains(t, err, "remove --user")
}

func TestBootstrap_requiresUserUnlessRotating(t *testing.T) {
	_, dir, _ := testRepo(t)

	err := Bootstrap(t.Context(), BootstrapOptions{ConfigDir: dir, Host: "acidburn"})
	assert.EqualError(t, err, "--user is required")
}

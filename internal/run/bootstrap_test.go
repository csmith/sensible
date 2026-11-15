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

// rotateFixture is acidburn, bootstrapped with the SSH fixture's key and
// password, being rotated to new credentials.
type rotateFixture struct {
	ssh    *sshFixture
	dir    string
	source config.IdentitySource
	repo   *config.Repo
	creds  credentials
	steps  []string
}

func newRotateFixture(t *testing.T) *rotateFixture {
	t.Helper()
	_, dir, source := testRepo(t)
	f := &rotateFixture{ssh: newSSHFixture(t, "hunter2", serverKey), dir: dir, source: source}
	f.ssh.server.agent.status = func(host.Resource) host.Status { return host.StatusDrifted }
	writeFile(
		t,
		filepath.Join(dir, "hosts.d", "acidburn.yml"),
		"acidburn:\n  address: "+f.ssh.server.addr+"\n  host_keys: ["+serverKey(f.ssh.server)[0].String()+"]\n",
	)
	f.repo = f.reopen(t)
	require.NoError(t, f.repo.WriteCredentials("acidburn", f.ssh.keyPEM, "hunter2", time.Now()))
	var err error
	f.creds, err = newCredentials("acidburn")
	require.NoError(t, err)
	return f
}

func (f *rotateFixture) reopen(t *testing.T) *config.Repo {
	t.Helper()
	repo, err := config.Open(f.dir, f.source)
	require.NoError(t, err)
	return repo
}

func (f *rotateFixture) rotate(t *testing.T) error {
	entry := f.repo.Inventory().Hosts["acidburn"]
	b := &bootstrapper{
		name:    "acidburn",
		address: entry.Address,
		creds:   f.creds,
		builds:  f.ssh.builds,
		known:   entry.HostKeys,
		repo:    f.repo,
		done:    func(step string) { f.steps = append(f.steps, step) },
	}
	return b.rotate(t.Context(), entry)
}

// saved is the key and password the repo has for acidburn, and its pending
// key.
func (f *rotateFixture) saved(t *testing.T) (string, string, string) {
	t.Helper()
	entry := f.reopen(t).Inventory().Hosts["acidburn"]
	key, err := entry.SSHKey.Reveal()
	require.NoError(t, err)
	password, err := entry.SudoPassword.Reveal()
	require.NoError(t, err)
	if entry.PendingSSHKey.IsZero() {
		return key, password, ""
	}
	pending, err := entry.PendingSSHKey.Reveal()
	require.NoError(t, err)
	return key, password, pending
}

func publicKey(t *testing.T, keyPEM string) ssh.PublicKey {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	require.NoError(t, err)
	return signer.PublicKey()
}

func TestRotate_authorizesBothKeysThenDropsTheOldOne(t *testing.T) {
	f := newRotateFixture(t)
	oldKey := authorizedKey(publicKey(t, f.ssh.keyPEM), "acidburn")

	require.NoError(t, f.rotate(t))

	checks := f.ssh.server.agent.checks
	require.Len(t, checks, 2)
	authorize := checks[0]
	command, ok := authorize[len(authorize)-1].(host.Command)
	require.True(t, ok, "the password should be set last")
	assert.Equal(t, f.creds.password, command.Env["SENSIBLE_PASSWORD"])
	assert.Equal(t, resourceList(features.AccessFiles(oldKey, f.creds.authorizedKey)), authorize[:len(authorize)-1])
	assert.Equal(t, resourceList(features.AccessFiles(f.creds.authorizedKey)), checks[1])

	assert.Equal(t, []ssh.PublicKey{f.creds.signer.PublicKey()}, f.ssh.server.acceptedKeys())
	assert.Equal(t, f.creds.password, f.ssh.server.currentPassword())
	key, password, pending := f.saved(t)
	assert.Equal(t, f.creds.keyPEM, key)
	assert.Equal(t, f.creds.password, password)
	assert.Empty(t, pending)
}

func TestRotate_failureBeforeThePasswordKeepsTheOldCredentials(t *testing.T) {
	f := newRotateFixture(t)
	f.ssh.server.agent.applyFailure = "file:/etc/ssh/authorized_keys/sensible"

	require.ErrorContains(t, f.rotate(t), "boom")

	assert.Equal(t, "hunter2", f.ssh.server.currentPassword())
	key, password, pending := f.saved(t)
	assert.Equal(t, f.ssh.keyPEM, key)
	assert.Equal(t, "hunter2", password)
	assert.Equal(t, f.creds.keyPEM, pending)
}

// A rotation that changed the password but stopped before saving it leaves
// the host with the pending credentials.
func interruptedRotation(t *testing.T, f *rotateFixture) {
	t.Helper()
	pending, err := newCredentials("acidburn")
	require.NoError(t, err)
	require.NoError(t, f.repo.SavePendingCredentials("acidburn", pending.keyPEM, pending.password))
	f.ssh.server.applied(host.Command{Env: map[string]string{"SENSIBLE_PASSWORD": pending.password}})
	f.ssh.server.applied(
		features.AccessFiles(
			authorizedKey(publicKey(t, f.ssh.keyPEM), "acidburn"),
			pending.authorizedKey,
		)[2],
	)
}

func TestRotate_recoversFromAnInterruptedRotation(t *testing.T) {
	f := newRotateFixture(t)
	interruptedRotation(t, f)

	require.NoError(t, f.rotate(t))

	assert.Contains(t, f.steps, "saved the pending credentials an earlier bootstrap left")
	assert.Equal(t, []ssh.PublicKey{f.creds.signer.PublicKey()}, f.ssh.server.acceptedKeys())
	key, _, pending := f.saved(t)
	assert.Equal(t, f.creds.keyPEM, key)
	assert.Empty(t, pending)
}

func TestConnect_triesPendingCredentialsWhenCurrentAreRejected(t *testing.T) {
	f := newRotateFixture(t)
	interruptedRotation(t, f)

	runs := (&Runner{Builds: f.ssh.builds}).connect(t.Context(), []target{newTarget(f.reopen(t), "acidburn")})
	<-runs[0].done
	defer byeAll(runs)

	require.NoError(t, runs[0].err)
	assert.Equal(t, "debian", runs[0].facts.OSFamily)
}

func TestRotate_rejectedCredentialsPointAtAnotherAccount(t *testing.T) {
	f := newRotateFixture(t)
	f.ssh.server.applied(host.Command{Env: map[string]string{"SENSIBLE_PASSWORD": "changed by hand"}})

	err := f.rotate(t)

	require.ErrorIs(t, err, errCredentialsRejected)
	assert.ErrorContains(t, err, "--rotate --user")
}

func TestBootstrap_acceptsAnyAccount(t *testing.T) {
	_, dir, source := testRepo(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := Bootstrap(ctx, BootstrapOptions{ConfigDir: dir, Host: "acidburn", User: "deploy"})
	require.ErrorIs(t, err, context.Canceled, "should get as far as connecting")

	repo, err := config.Open(dir, source)
	require.NoError(t, err)
	assert.False(t, repo.Inventory().Hosts["acidburn"].PendingSSHKey.IsZero(), "should save the credentials first")
}

func TestBootstrap_checksCredentialsCanBeSavedBeforeConnecting(t *testing.T) {
	_, dir, _ := testRepo(t)
	writeFile(t, filepath.Join(dir, "sensible.yml"), "{}\n")
	t.Setenv("SSH_AUTH_SOCK", "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := Bootstrap(ctx, BootstrapOptions{ConfigDir: dir, Host: "acidburn", User: "deploy"})
	assert.ErrorContains(t, err, "no secrets.recipients")
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

func resourceList(files []host.File) host.ResourceList {
	list := make(host.ResourceList, 0, len(files))
	for _, file := range files {
		list = append(list, file)
	}
	return list
}

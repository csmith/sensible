package run

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"syscall"
	"text/template"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/features"
	"chameth.com/sensible/internal/host"
)

type BootstrapOptions struct {
	ConfigDir string
	Host      string
	// User is the account to log in as, with the SSH agent's keys or a
	// password. Accounts other than root install through sudo, which is
	// given a password if it asks for one. With Rotate
	// it may be empty, in which case the host's existing sensible access is
	// used. It must be empty for the machine this runs on, which is set up
	// with sudo directly.
	User   string
	Rotate bool
	// BootstrapKey connects with the repo's bootstrap key, which a bootstrap
	// binary set the host up for, instead of an account on it.
	BootstrapKey bool
	// HostKey is the SHA256 fingerprint the host's key must have when it
	// has no host_keys yet. Empty means asking on the terminal.
	HostKey string
}

// Bootstrap gives a host its sensible account and agent, then saves
// its credentials once the normal path is proven to work.
func Bootstrap(ctx context.Context, opts BootstrapOptions) error {
	out := os.Stdout
	repo, err := openRepo(opts.ConfigDir, out)
	if err != nil {
		return err
	}
	entry, ok := repo.Inventory().Hosts[opts.Host]
	address := hostAddress(opts.Host, entry)
	local := isLocal(opts.Host)
	switch {
	case !ok:
		return unknownHost(repo.Inventory(), opts.Host)
	case address == "":
		return fmt.Errorf("%s has no address", opts.Host)
	case opts.BootstrapKey && opts.User != "":
		return errors.New("--bootstrap-key and --user can't be used together")
	case opts.BootstrapKey && repo.BootstrapKey().SSHKey.IsZero():
		return errors.New("there's no bootstrap key yet; bootstrap-binary makes one")
	case local && opts.User != "":
		return fmt.Errorf("%s is this machine, which is set up with sudo; remove --user", opts.Host)
	case !local && opts.User == "" && !opts.Rotate && !opts.BootstrapKey:
		return errors.New("--user is required")
	}
	bootstrapped := !entry.SSHKey.IsZero()
	if bootstrapped && !opts.Rotate {
		return fmt.Errorf("%s already has credentials; use --rotate to replace them", opts.Host)
	}
	if !local && !bootstrapped && opts.User == "" && !opts.BootstrapKey {
		return fmt.Errorf("%s has no credentials to rotate; use --user", opts.Host)
	}

	// Found now, as the host is changed before its credentials are saved.
	if err := repo.CheckCredentials(opts.Host); err != nil {
		return err
	}

	// Revealed before the section, as fetching the identity prints its own.
	var current credentials
	switch {
	case opts.BootstrapKey:
		current, err = revealBootstrapKey(repo.BootstrapKey())
	case !local && opts.User == "":
		current, err = revealCredentials(opts.Host, entry.SSHKey, entry.SudoPassword)
	}
	if err != nil {
		return err
	}

	creds, err := newCredentials(opts.Host)
	if err != nil {
		return err
	}
	r := newRenderer(out)
	r.section("Bootstrapping " + opts.Host)
	b := &bootstrapper{
		name:               opts.Host,
		address:            address,
		creds:              creds,
		builds:             NewEmbeddedBuilds(),
		known:              entry.HostKeys,
		confirm:            confirmOnTerminal,
		askPassword:        passwordFromTerminal,
		hostKeyFingerprint: opts.HostKey,
		hostKeySource:      "the provider console",
		repo:               repo,
		done:               func(step string) { r.item(r.p.ok("✓") + " " + step) },
	}
	switch {
	case opts.BootstrapKey:
		b.hostKeySource = "what the bootstrap binary printed"
		b.passwordFirst = true
		return b.rotate(ctx, current, entry)
	case local:
		return b.setUp(ctx, b.installLocal)
	case opts.User == "":
		return b.rotate(ctx, current, entry)
	default:
		keyring := sshAgent(ctx)
		return b.setUp(ctx, func(ctx context.Context) error { return b.install(ctx, opts.User, keyring) })
	}
}

// setUp installs the new credentials and agent with install, which replaces
// whatever access the host had.
func (b *bootstrapper) setUp(ctx context.Context, install func(context.Context) error) error {
	if err := b.repo.SavePendingCredentials(b.name, b.creds.keyPEM, b.creds.password); err != nil {
		return err
	}
	if err := install(ctx); err != nil {
		return err
	}
	b.done("installed credentials and agent")
	return b.save(ctx)
}

// rotate replaces the key and password through the host's existing agent,
// reached with current. Each step can be recovered from if the next fails:
// the new pair is saved as pending before the host has it, and the old key
// is only dropped once the new pair is saved as current.
func (b *bootstrapper) rotate(ctx context.Context, current credentials, entry config.HostEntry) error {
	a, old, err := b.connectExisting(ctx, current, entry)
	if err != nil {
		return err
	}
	err = b.repo.SavePendingCredentials(b.name, b.creds.keyPEM, b.creds.password)
	if err == nil {
		resources := host.ResourceList{}
		for _, f := range features.AccessFiles(old.authorizedKey, b.creds.authorizedKey) {
			resources = append(resources, f)
		}
		// The password normally goes last, so the old one still works if
		// the files fail. A host on its bootstrap key has no password, and
		// the files make sudo ask for one, so it goes first there.
		if b.passwordFirst {
			resources = append(host.ResourceList{setPassword(b.creds.password)}, resources...)
		} else {
			resources = append(resources, setPassword(b.creds.password))
		}
		err = applyAccess(a, resources)
	}
	a.bye()
	if err != nil {
		return err
	}
	b.done("authorized the new key and set the new password")
	if err := b.save(ctx); err != nil {
		return err
	}

	a, _, err = connect(ctx, b.transport(b.creds.signer, b.creds.password), b.builds)
	if err != nil {
		return fmt.Errorf("removing the old key, which the next apply also does: %w", err)
	}
	defer a.bye()
	resources := host.ResourceList{}
	for _, f := range features.AccessFiles(b.creds.authorizedKey) {
		resources = append(resources, f)
	}
	if err := applyAccess(a, resources); err != nil {
		return fmt.Errorf("removing the old key, which the next apply also does: %w", err)
	}
	b.done("removed the old key")
	return nil
}

// save proves the new credentials work, then saves them and any new host
// key.
func (b *bootstrapper) save(ctx context.Context) error {
	if err := b.verify(ctx); err != nil {
		return err
	}
	b.done("connected as sensible")

	// Credentials go first: a host key that can't be added is reported for
	// adding by hand, which is easier than bootstrapping again.
	if err := b.repo.WriteCredentials(b.name, b.creds.keyPEM, b.creds.password, time.Now()); err != nil {
		return err
	}
	b.done("saved credentials")
	return b.saveHostKey()
}

// saveHostKey saves a host key accepted during this bootstrap, after which
// it's known like any other.
func (b *bootstrapper) saveHostKey() error {
	if b.newHostKey == nil {
		return nil
	}
	if err := b.repo.AddHostKey(b.name, b.newHostKey); err != nil {
		return err
	}
	b.known = append(b.known, config.HostKey{PublicKey: b.newHostKey})
	b.newHostKey = nil
	b.done("saved host key")
	return nil
}

// connectExisting connects with current or, if it's rejected, with pending
// credentials an earlier bootstrap left. Pending ones that work are saved as
// current, as the host has them. A bootstrap that stopped after setting the
// pending password but before authorizing the pending key leaves the host
// with current's key and the pending password, so that's tried last.
func (b *bootstrapper) connectExisting(
	ctx context.Context,
	current credentials,
	entry config.HostEntry,
) (*agent, credentials, error) {
	a, _, err := connect(ctx, b.transport(current.signer, current.password), b.builds)
	if err == nil || !errors.Is(err, errCredentialsRejected) || entry.PendingSSHKey.IsZero() {
		return a, current, err
	}
	pending, perr := revealCredentials(b.name, entry.PendingSSHKey, entry.PendingSudoPassword)
	if perr != nil {
		return nil, credentials{}, err
	}
	a, _, err = connect(ctx, b.transport(pending.signer, pending.password), b.builds)
	if errors.Is(err, errCredentialsRejected) {
		mixed := current
		mixed.password = pending.password
		a, _, err = connect(ctx, b.transport(mixed.signer, mixed.password), b.builds)
		return a, mixed, err
	}
	if err != nil {
		return nil, credentials{}, err
	}
	if err := b.repo.WriteCredentials(b.name, pending.keyPEM, pending.password, time.Now()); err != nil {
		a.bye()
		return nil, credentials{}, err
	}
	b.done("saved the pending credentials an earlier bootstrap left")
	if err := b.saveHostKey(); err != nil {
		a.bye()
		return nil, credentials{}, err
	}
	return a, pending, nil
}

type credentials struct {
	keyPEM        string
	signer        ssh.Signer
	password      string
	authorizedKey string
}

func newCredentials(name string) (credentials, error) {
	creds, err := newKey(name)
	creds.password = rand.Text()
	return creds, err
}

// newKey is credentials with no password.
func newKey(name string) (credentials, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return credentials{}, err
	}
	block, err := ssh.MarshalPrivateKey(priv, features.SensibleUser+"@"+name)
	if err != nil {
		return credentials{}, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return credentials{}, err
	}
	return credentials{
		keyPEM:        string(pem.EncodeToMemory(block)),
		signer:        signer,
		authorizedKey: authorizedKey(signer.PublicKey(), name),
	}, nil
}

func sshAgent(ctx context.Context) sshagent.ExtendedAgent {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil
	}
	return sshagent.NewClient(conn)
}

type bootstrapper struct {
	name        string
	address     string
	creds       credentials
	builds      Builds
	known       []config.HostKey
	confirm     func(prompt string) (bool, error)
	askPassword func(prompt string) (string, error)
	// hostKeyFingerprint, if set, replaces the confirmation of a new key.
	hostKeyFingerprint string
	// hostKeySource is where to check a new key's fingerprint.
	hostKeySource string
	// passwordFirst sets the new password before the access files when
	// rotating, for a host with no password yet.
	passwordFirst bool
	// newHostKey is a key accepted during this bootstrap, to be saved once
	// it has worked.
	newHostKey ssh.PublicKey
	repo       *config.Repo
	// done reports a finished step.
	done func(step string)
}

// install connects as an account that already works on the host, uploads
// the agent and runs the setup script.
func (b *bootstrapper) install(ctx context.Context, user string, keyring sshagent.ExtendedAgent) error {
	var auth []ssh.AuthMethod
	if keyring != nil {
		auth = append(auth, ssh.PublicKeysCallback(keyring.Signers))
	}
	var password string
	ask := func() (string, error) {
		if password != "" {
			return password, nil
		}
		var err error
		password, err = b.askPassword(fmt.Sprintf("%s@%s password: ", user, b.name))
		return password, err
	}
	answer := func(_, _ string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range questions {
			if echos[i] {
				return nil, errors.New("unexpected keyboard-interactive question")
			}
			p, err := ask()
			if err != nil {
				return nil, err
			}
			answers[i] = p
		}
		return answers, nil
	}
	auth = append(auth, ssh.PasswordCallback(ask), ssh.KeyboardInteractive(answer))

	client, err := dialSSH(
		ctx,
		b.address,
		&ssh.ClientConfig{
			User:              user,
			Auth:              auth,
			HostKeyCallback:   b.hostKey(),
			HostKeyAlgorithms: hostKeyAlgorithms(b.known),
		},
	)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	sudo := user != "root"
	forward := sudo && keyring != nil
	if forward {
		if err := sshagent.ForwardToAgent(client, keyring); err != nil {
			return err
		}
	}

	machine, err := runRemote(client, "uname -m", nil, false)
	if err != nil {
		return fmt.Errorf("detecting architecture: %w", err)
	}
	arch, err := goarch(strings.TrimSpace(machine))
	if err != nil {
		return err
	}
	build, err := b.builds.Build(ctx, arch)
	if err != nil {
		return err
	}
	tmp, err := runRemote(
		client,
		`umask 077 && t=$(mktemp) && cat > "$t" && printf '%s\n' "$t"`,
		bytes.NewReader(build.Binary),
		false,
	)
	if err != nil {
		return fmt.Errorf("uploading agent: %w", err)
	}

	command, input := "sh -s", ""
	if sudo {
		run := func(command string, stdin io.Reader) error {
			_, err := runRemote(client, command, stdin, forward)
			return err
		}
		sudoPassword := func() (string, error) {
			if password != "" {
				return password, nil
			}
			return b.askPassword(fmt.Sprintf("%s@%s sudo password: ", user, b.name))
		}
		if command, input, err = sudoShell(run, sudoPassword); err != nil {
			return err
		}
	}
	input += setupScript{
		Password:  b.creds.password,
		AgentTmp:  strings.TrimSpace(tmp),
		AgentHash: build.Hash,
		Access:    features.AccessFiles(b.creds.authorizedKey),
	}.String()
	if _, err := runRemote(client, command, strings.NewReader(input), forward); err != nil {
		return fmt.Errorf("running setup: %w", err)
	}
	return nil
}

// sudoShell returns a command that runs a script from stdin as root, and
// what stdin must start with. Sudo that needs no password, such as with
// NOPASSWD or pam_rssh, is used as it is; otherwise the password goes on
// the first line of stdin, ahead of the script.
func sudoShell(
	run func(command string, stdin io.Reader) error,
	password func() (string, error),
) (string, string, error) {
	if run("sudo -n true", nil) == nil {
		return "sudo sh -s", "", nil
	}
	p, err := password()
	if err != nil {
		return "", "", err
	}
	// The password is checked on its own first, as sudo reads its retries
	// from stdin, which would otherwise be the script.
	if err := run("sudo -k -S -p '' true", strings.NewReader(p+"\n")); err != nil {
		return "", "", fmt.Errorf("sudo: %w", err)
	}
	return "sudo -k -S -p '' sh -s", p + "\n", nil
}

// installLocal sets up the machine this runs on with sudo, which prompts on
// the terminal if it needs to. Unlike a remote host, it may not have sshd yet.
func (b *bootstrapper) installLocal(ctx context.Context) error {
	build, err := b.builds.Build(ctx, runtime.GOARCH)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "sensible-agent-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(build.Binary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "sudo", "sh", "-s")
	cmd.Stdin = strings.NewReader(
		setupScript{
			Password:   b.creds.password,
			AgentTmp:   tmp.Name(),
			AgentHash:  build.Hash,
			Access:     features.AccessFiles(b.creds.authorizedKey),
			EnsureSSHD: true,
		}.String(),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("running setup: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return b.readLocalHostKey(localHostKeyPath)
}

const localHostKeyPath = "/etc/ssh/ssh_host_ed25519_key.pub"

// readLocalHostKey needs no confirmation of a new key, as it comes from this
// machine's disk rather than over the network.
func (b *bootstrapper) readLocalHostKey(path string) error {
	if len(b.known) > 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var key config.HostKey
	if err := key.UnmarshalText(data); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if got := ssh.FingerprintSHA256(key); b.hostKeyFingerprint != "" && got != b.hostKeyFingerprint {
		return fmt.Errorf("%s host key is %s, not %s", b.name, got, b.hostKeyFingerprint)
	}
	b.newHostKey = key.PublicKey
	return nil
}

// hostKey checks the host's key against its host_keys, asking about the key
// if it has none yet.
func (b *bootstrapper) hostKey() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if len(b.known) > 0 {
			return checkHostKey(b.name, b.known)(hostname, remote, key)
		}
		if b.hostKeyFingerprint != "" {
			if got := ssh.FingerprintSHA256(key); got != b.hostKeyFingerprint {
				return fmt.Errorf("%s host key is %s, not %s", b.name, got, b.hostKeyFingerprint)
			}
			b.newHostKey = key
			return nil
		}
		ok, err := b.confirm(
			fmt.Sprintf(
				"%s host key is %s %s\nDoes it match %s? [y/N] ",
				b.name,
				key.Type(),
				ssh.FingerprintSHA256(key),
				b.hostKeySource,
			),
		)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("host key not accepted")
		}
		b.newHostKey = key
		return nil
	}
}

func runRemote(client *ssh.Client, command string, stdin io.Reader, forwardAgent bool) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()
	if forwardAgent {
		if err := sshagent.RequestAgentForwarding(session); err != nil {
			return "", err
		}
	}
	var stdout, stderr strings.Builder
	session.Stdin = stdin
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Run(command); err != nil {
		return "", fmt.Errorf("%w\n%s", err, printable(strings.TrimSpace(stderr.String()+stdout.String())))
	}
	return stdout.String(), nil
}

func setPassword(password string) host.Command {
	return host.Command{
		Name: "sensible-password",
		CheckArgv: []string{
			"false",
		},
		ApplyArgv: []string{
			"/bin/sh",
			"-c",
			`printf '%s:%s\n' "$1" "$SENSIBLE_PASSWORD" | /usr/sbin/chpasswd`,
			"sh",
			features.SensibleUser,
		},
		Env: map[string]string{"SENSIBLE_PASSWORD": password},
	}
}

// applyAccess checks and applies resources, stopping at the first failure.
func applyAccess(a *agent, resources host.ResourceList) error {
	checked, err := a.check(host.Check{Resources: resources})
	if err != nil {
		return err
	}
	for _, c := range checked {
		if c.Status == host.StatusFailed {
			return fmt.Errorf("checking %s: %s", c.ID, c.Error)
		}
	}
	var failure error
	done, err := a.apply(
		func(host.Applying) {},
		func(r host.Applied) {
			if r.Status == host.StatusFailed && failure == nil {
				failure = fmt.Errorf("applying %s: %s", r.ID, r.Error)
			}
		},
	)
	if err != nil {
		return err
	}
	if failure != nil {
		return failure
	}
	if done.Failed {
		return errors.New("applying failed")
	}
	return nil
}

// verify connects the normal way. Reloading sshd re-executes its listener,
// so connections are refused for a moment afterwards; those are retried.
func (b *bootstrapper) verify(ctx context.Context) error {
	deadline := time.Now().Add(verifyTimeout)
	for {
		a, _, err := connect(ctx, b.transport(b.creds.signer, b.creds.password), b.builds)
		if err == nil {
			a.bye()
			return nil
		}
		if !errors.Is(err, syscall.ECONNREFUSED) || time.Now().After(deadline) {
			return fmt.Errorf("connecting with the new credentials: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(verifyRetryInterval):
		}
	}
}

var (
	verifyTimeout       = 15 * time.Second
	verifyRetryInterval = 500 * time.Millisecond
)

func (b *bootstrapper) transport(signer ssh.Signer, password string) *OpenSSH {
	hostKey := b.hostKey()
	algos := hostKeyAlgorithms(b.known)
	if b.newHostKey != nil {
		hostKey = ssh.FixedHostKey(b.newHostKey)
		algos = keyAlgorithms(b.newHostKey.Type())
	}
	return &OpenSSH{
		Name:              b.name,
		Address:           b.address,
		Signer:            signer,
		Password:          password,
		HostKey:           hostKey,
		HostKeyAlgorithms: algos,
	}
}

//go:embed bootstrap.sh.tmpl
var bootstrapTemplateText string

var bootstrapTemplate = template.Must(
	template.New("bootstrap").Funcs(template.FuncMap{"q": quote}).Parse(bootstrapTemplateText),
)

type setupScript struct {
	// Password is the account's sudo password. Empty locks it, for
	// BootstrapAccessFiles.
	Password  string
	AgentTmp  string
	AgentHash string
	Access    []host.File
	// EnsureSSHD installs and starts sshd, for a machine that wasn't
	// reached through it.
	EnsureSSHD bool
}

// String is the script, which is run as root with sh. It's idempotent, so
// re-running bootstrap repairs a host whose access has broken.
func (s setupScript) String() string {
	files := make([]string, len(s.Access))
	for i, f := range s.Access {
		files[i] = writeFileScript(f)
	}
	var out strings.Builder
	err := bootstrapTemplate.Execute(
		&out,
		map[string]any{
			"User":       features.SensibleUser,
			"Home":       features.SensibleHome,
			"Password":   s.Password,
			"AgentTmp":   s.AgentTmp,
			"AgentHash":  s.AgentHash,
			"AgentDir":   path.Dir(host.AgentPath),
			"AgentPath":  host.AgentPath,
			"Files":      files,
			"EnsureSSHD": s.EnsureSSHD,
		},
	)
	if err != nil {
		panic(err)
	}
	return out.String()
}

// writeFileScript writes a file through a temporary copy in the same
// directory, which is validated before it's moved into place.
func writeFileScript(f host.File) string {
	owner, group := f.Owner, f.Group
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "root"
	}
	var s strings.Builder
	_, _ = fmt.Fprintf(&s, "mkdir -p %s\n", quote(path.Dir(f.Path)))
	_, _ = fmt.Fprintf(&s, "t=$(mktemp %s)\n", quote(path.Join(path.Dir(f.Path), ".sensible.XXXXXX")))
	_, _ = fmt.Fprintf(&s, "printf '%%s' %s > \"$t\"\n", quote(f.Content))
	_, _ = fmt.Fprintf(&s, "chown %s \"$t\"\n", quote(owner+":"+group))
	_, _ = fmt.Fprintf(&s, "chmod %04o \"$t\"\n", f.Mode.Perm())
	if len(f.Validate) > 0 {
		args := make([]string, len(f.Validate))
		for i, arg := range f.Validate {
			parts := strings.Split(arg, "%s")
			for j := range parts {
				parts[j] = quote(parts[j])
			}
			args[i] = strings.Join(parts, `"$t"`)
		}
		_, _ = fmt.Fprintf(&s, "if ! %s; then rm -f \"$t\"; exit 1; fi\n", strings.Join(args, " "))
	}
	_, _ = fmt.Fprintf(&s, "mv -f \"$t\" %s\n", quote(f.Path))
	return s.String()
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

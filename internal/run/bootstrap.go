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
	"path"
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
	// User is the account to log in as with the SSH agent's keys. Root may
	// also use a password; other accounts install through sudo. With Rotate
	// it may be empty, in which case the host's existing sensible access is
	// used.
	User   string
	Rotate bool
	// HostKey is the SHA256 fingerprint the host's key must have when it
	// has no host_keys yet. Empty means asking on the terminal.
	HostKey string
}

// Bootstrap gives a remote host its sensible account and agent, then saves
// its credentials once the normal path is proven to work.
func Bootstrap(ctx context.Context, opts BootstrapOptions) error {
	out := os.Stdout
	repo, err := openRepo(opts.ConfigDir, out)
	if err != nil {
		return err
	}
	entry, ok := repo.Inventory().Hosts[opts.Host]
	switch {
	case !ok:
		return unknownHost(repo.Inventory(), opts.Host)
	case isLocal(opts.Host):
		return fmt.Errorf("%s is this machine, which is reached with sudo and needs no bootstrap", opts.Host)
	case entry.Address == "":
		return fmt.Errorf("%s has no address", opts.Host)
	case opts.User == "" && !opts.Rotate:
		return errors.New("--user is required")
	}
	bootstrapped := !entry.SSHKey.IsZero()
	if bootstrapped && !opts.Rotate {
		return fmt.Errorf("%s already has credentials; use --rotate to replace them", opts.Host)
	}
	if !bootstrapped && opts.User == "" {
		return fmt.Errorf("%s has no credentials to rotate; use --user", opts.Host)
	}

	creds, err := newCredentials(opts.Host)
	if err != nil {
		return err
	}
	var signer ssh.Signer
	var password string
	if opts.User == "" {
		if signer, password, err = revealCredentials(entry); err != nil {
			return err
		}
	}
	r := newRenderer(out)
	r.section("Bootstrapping " + opts.Host)
	b := &bootstrapper{
		name:               opts.Host,
		address:            entry.Address,
		creds:              creds,
		builds:             NewEmbeddedBuilds(),
		known:              entry.HostKeys,
		confirm:            confirmOnTerminal,
		hostKeyFingerprint: opts.HostKey,
	}
	step := "installed credentials and agent"
	if opts.User == "" {
		step = "replaced credentials"
		err = b.rotate(ctx, signer, password)
	} else {
		err = b.install(ctx, opts.User, sshAgent(ctx))
	}
	if err != nil {
		return err
	}
	r.item(r.p.ok("✓") + " " + step)
	if err := b.verify(ctx); err != nil {
		return err
	}
	r.item(r.p.ok("✓") + " connected as sensible")

	// Credentials go first: a host key that can't be added is reported for
	// adding by hand, which is easier than bootstrapping again.
	if err := repo.WriteCredentials(opts.Host, creds.keyPEM, creds.password, time.Now()); err != nil {
		return err
	}
	r.item(r.p.ok("✓") + " saved credentials")
	if b.newHostKey != nil {
		if err := repo.AddHostKey(opts.Host, b.newHostKey); err != nil {
			return err
		}
		r.item(r.p.ok("✓") + " saved host key")
	}
	return nil
}

type credentials struct {
	keyPEM        string
	signer        ssh.Signer
	password      string
	authorizedKey string
}

func newCredentials(name string) (credentials, error) {
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
		password:      rand.Text(),
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
	name    string
	address string
	creds   credentials
	builds  Builds
	known   []config.HostKey
	confirm func(prompt string) (bool, error)
	// hostKeyFingerprint, if set, replaces the confirmation of a new key.
	hostKeyFingerprint string
	// newHostKey is a key accepted during this bootstrap, to be saved once
	// it has worked.
	newHostKey ssh.PublicKey
}

// install connects as an account that already works on the host, uploads
// the agent and runs the setup script.
func (b *bootstrapper) install(ctx context.Context, user string, keyring sshagent.ExtendedAgent) error {
	var auth []ssh.AuthMethod
	if keyring != nil {
		auth = append(auth, ssh.PublicKeysCallback(keyring.Signers))
	}
	if user == "root" {
		var password string
		ask := func() (string, error) {
			if password != "" {
				return password, nil
			}
			var err error
			password, err = passwordFromTerminal(fmt.Sprintf("root@%s password: ", b.name))
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
	}
	if len(auth) == 0 {
		return errors.New("no SSH agent to authenticate with (SSH_AUTH_SOCK isn't set)")
	}

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
	if sudo {
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

	script := bootstrapScript(b.creds.password, strings.TrimSpace(tmp), build.Hash, b.creds.authorizedKey)
	command := "sh -s"
	if sudo {
		command = "sudo sh -s"
	}
	if _, err := runRemote(client, command, strings.NewReader(script), sudo); err != nil {
		return fmt.Errorf("running setup: %w", err)
	}
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
				"%s host key is %s %s\nDoes it match the provider console? [y/N] ",
				b.name,
				key.Type(),
				ssh.FingerprintSHA256(key),
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
		return "", fmt.Errorf("%w\n%s", err, strings.TrimSpace(stderr.String()+stdout.String()))
	}
	return stdout.String(), nil
}

// rotate replaces the key and password through the host's existing agent.
func (b *bootstrapper) rotate(ctx context.Context, signer ssh.Signer, password string) error {
	a, _, err := connect(ctx, b.transport(signer, password), b.builds)
	if err != nil {
		return err
	}
	defer a.bye()

	resources := host.ResourceList{
		host.Command{
			Name:      "sensible-password",
			CheckArgv: []string{"false"},
			ApplyArgv: []string{
				"/bin/sh",
				"-c",
				`printf '%s:%s\n' "$1" "$SENSIBLE_PASSWORD" | /usr/sbin/chpasswd`,
				"sh",
				features.SensibleUser,
			},
			Env: map[string]string{"SENSIBLE_PASSWORD": b.creds.password},
		},
	}
	for _, f := range features.AccessFiles(b.creds.authorizedKey) {
		resources = append(resources, f)
	}
	checked, err := a.check(resources)
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
		return errors.New("rotating credentials failed")
	}
	return nil
}

// verify connects the normal way with the new credentials.
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
	hostKey := checkHostKey(b.name, b.known)
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

// bootstrapScript is run as root with sh. It's idempotent, so re-running
// bootstrap repairs a host whose access has broken.
func bootstrapScript(password, agentTmp, agentHash, authorizedKey string) string {
	access := features.AccessFiles(authorizedKey)
	files := make([]string, len(access))
	for i, f := range access {
		files[i] = writeFileScript(f)
	}
	var s strings.Builder
	err := bootstrapTemplate.Execute(
		&s,
		map[string]any{
			"User":      features.SensibleUser,
			"Home":      features.SensibleHome,
			"Password":  password,
			"AgentTmp":  agentTmp,
			"AgentHash": agentHash,
			"AgentDir":  path.Dir(host.AgentPath),
			"AgentPath": host.AgentPath,
			"Files":     files,
		},
	)
	if err != nil {
		panic(err)
	}
	return s.String()
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

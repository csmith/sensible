package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/features"
)

var errCredentialsRejected = errors.New("credentials rejected, re-run bootstrap")

// OpenSSH starts a remote host's agent through its sensible account, whose
// forced command runs the agent under sudo.
type OpenSSH struct {
	// Name is the inventory name, which host keys are checked under.
	Name     string
	Address  string
	Signer   ssh.Signer
	Password string
	HostKey  ssh.HostKeyCallback
	// HostKeyAlgorithms restricts the host key types offered, so a host
	// with a known key isn't asked for a different type. Empty allows any.
	HostKeyAlgorithms []string
}

func (o *OpenSSH) Start(ctx context.Context) (*AgentPipe, error) {
	client, err := dialSSH(
		ctx,
		o.Address,
		&ssh.ClientConfig{
			User:              features.SensibleUser,
			Auth:              []ssh.AuthMethod{ssh.PublicKeys(o.Signer)},
			HostKeyCallback:   o.HostKey,
			HostKeyAlgorithms: o.HostKeyAlgorithms,
		},
	)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	closeAll := func() error {
		_ = session.Close()
		return client.Close()
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = closeAll()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = closeAll()
		return nil, err
	}
	session.Stderr = &agentStderr{host: o.Name}
	// The forced command replaces whatever's asked for.
	if err := session.Start("sensible-agent"); err != nil {
		_ = closeAll()
		return nil, err
	}
	if _, err := io.WriteString(stdin, o.Password+"\n"); err != nil {
		_ = closeAll()
		return nil, err
	}
	return &AgentPipe{
		Reader:    stdout,
		Writer:    stdin,
		Close:     closeAll,
		EarlyExit: errCredentialsRejected,
	}, nil
}

func dialSSH(ctx context.Context, address string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "22")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, address, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// checkHostKey accepts only the host's keys from hosts.yml, whatever
// address was dialled.
func checkHostKey(name string, known []config.HostKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if len(known) == 0 {
			return fmt.Errorf("%s has no host_keys in hosts.yml", name)
		}
		for _, k := range known {
			if bytes.Equal(k.Marshal(), key.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("%s host key %s %s isn't in its host_keys", name, key.Type(), ssh.FingerprintSHA256(key))
	}
}

// hostKeyAlgorithms lists the types of the known keys, so a host isn't asked
// for a type it has no known key of.
func hostKeyAlgorithms(known []config.HostKey) []string {
	algos := make([]string, 0, len(known))
	for _, k := range known {
		algos = append(algos, keyAlgorithms(k.Type())...)
	}
	if len(algos) == 0 {
		return preferredHostKeyAlgorithms
	}
	return algos
}

// preferredHostKeyAlgorithms puts ed25519 first for hosts with no known keys
// yet, so the key shown for confirmation is the one consoles usually list.
var preferredHostKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

func keyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// authorizedKey is the sensible account's authorized_keys line, without
// options.
func authorizedKey(key ssh.PublicKey, name string) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + features.SensibleUser + "@" + name
}

type agentStderr struct {
	host string
}

func (w *agentStderr) Write(p []byte) (int, error) {
	for line := range strings.SplitSeq(strings.TrimRight(string(p), "\n"), "\n") {
		debugf("%s agent: %s", w.host, line)
	}
	return len(p), nil
}

// Local runs the agent on this machine with sudo, straight from the build
// cache.
type Local struct {
	Builds Builds
}

func (l *Local) Start(ctx context.Context) (*AgentPipe, error) {
	build, err := l.Builds.Build(ctx, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "sudo", build.Path, "agent")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &AgentPipe{
		Reader: out,
		Writer: stdin,
		Close: func() error {
			_ = stdin.Close()
			return cmd.Wait()
		},
		EarlyExit: errors.New("sudo failed"),
	}, nil
}

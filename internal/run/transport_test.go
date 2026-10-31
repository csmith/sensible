package run

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"chameth.com/sensible/internal/host"
)

// sshServer accepts the sensible user with one key and, like the forced
// sudo command, starts the agent only if the first line of input is the
// password.
type sshServer struct {
	addr     string
	hostKey  ssh.Signer
	password string
	agent    *fakeAgent
	commands chan string
}

func newSSHServer(t *testing.T, client ssh.PublicKey, password string, agent *fakeAgent) *sshServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostKey, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() == "sensible" && bytes.Equal(key.Marshal(), client.Marshal()) {
				return nil, nil
			}
			return nil, assert.AnError
		},
	}
	cfg.AddHostKey(hostKey)

	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	s := &sshServer{
		addr:     l.Addr().String(),
		hostKey:  hostKey,
		password: password,
		agent:    agent,
		commands: make(chan string, 10),
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go s.handle(conn, cfg)
		}
	}()
	return s
}

func (s *sshServer) handle(conn net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range requests {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				_ = req.Reply(true, nil)
				var payload struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &payload)
				s.commands <- payload.Command
				go s.runAgent(ch)
			}
		}()
	}
}

func (s *sshServer) runAgent(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	in := bufio.NewReader(ch)
	line, err := in.ReadString('\n')
	if err != nil || line != s.password+"\n" {
		return
	}
	r, w := io.Pipe()
	go func() {
		_, _ = io.Copy(w, in)
		_ = w.Close()
	}()
	s.agent.serve(r, nopCloser{ch})
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

type sshFixture struct {
	keyPEM    string
	server    *sshServer
	transport *OpenSSH
	builds    fakeBuilds
}

func newSSHFixture(t *testing.T, serverPassword string, knownHostsLine func(*sshServer) string) *sshFixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	builds := newFakeBuilds(t)
	server := newSSHServer(
		t,
		signer.PublicKey(),
		serverPassword,
		&fakeAgent{hash: builds["amd64"].Hash, facts: host.Facts{OSFamily: "debian"}},
	)

	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(knownHostsLine(server)+"\n"), 0o600))
	known, err := loadKnownHosts(path)
	require.NoError(t, err)

	return &sshFixture{
		keyPEM: string(pem.EncodeToMemory(block)),
		server: server,
		builds: builds,
		transport: &OpenSSH{
			Name:              "acidburn",
			Address:           server.addr,
			Signer:            signer,
			Password:          "hunter2",
			HostKey:           inventoryHostKey("acidburn", known),
			HostKeyAlgorithms: knownHostKeyAlgorithms(path, "acidburn"),
		},
	}
}

func knownUnderInventoryName(s *sshServer) string {
	return knownhosts.Line([]string{"acidburn"}, s.hostKey.PublicKey())
}

func TestOpenSSH_connectsAndChecksHostKeyUnderInventoryName(t *testing.T) {
	f := newSSHFixture(t, "hunter2", knownUnderInventoryName)

	a, upgraded, err := connect(t.Context(), f.transport, f.builds)
	require.NoError(t, err)
	facts, err := a.facts()
	require.NoError(t, err)
	a.bye()

	assert.False(t, upgraded)
	assert.Equal(t, "debian", facts.OSFamily)
	assert.Equal(t, "sensible-agent", <-f.server.commands)
}

func TestOpenSSH_wrongPasswordIsReportedAsRejectedCredentials(t *testing.T) {
	f := newSSHFixture(t, "something else", knownUnderInventoryName)

	_, _, err := connect(t.Context(), f.transport, f.builds)

	assert.ErrorIs(t, err, errCredentialsRejected)
}

func TestOpenSSH_rejectsKeyKnownOnlyUnderAddress(t *testing.T) {
	f := newSSHFixture(
		t,
		"hunter2",
		func(s *sshServer) string { return knownhosts.Line([]string{s.addr}, s.hostKey.PublicKey()) },
	)

	_, _, err := connect(t.Context(), f.transport, f.builds)

	var keyErr *knownhosts.KeyError
	assert.ErrorAs(t, err, &keyErr)
}

func TestOpenSSH_rejectsChangedHostKey(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherKey, err := ssh.NewSignerFromKey(other)
	require.NoError(t, err)
	f := newSSHFixture(
		t,
		"hunter2",
		func(*sshServer) string { return knownhosts.Line([]string{"acidburn"}, otherKey.PublicKey()) },
	)

	_, _, err = connect(t.Context(), f.transport, f.builds)

	var keyErr *knownhosts.KeyError
	require.ErrorAs(t, err, &keyErr)
	assert.NotEmpty(t, keyErr.Want)
}

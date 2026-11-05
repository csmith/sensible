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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"chameth.com/sensible/internal/config"
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

func newSSHFixture(t *testing.T, serverPassword string, hostKeys func(*sshServer) []config.HostKey) *sshFixture {
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

	known := hostKeys(server)
	return &sshFixture{
		keyPEM: string(pem.EncodeToMemory(block)),
		server: server,
		builds: builds,
		transport: &OpenSSH{
			Name:              "acidburn",
			Address:           server.addr,
			Signer:            signer,
			Password:          "hunter2",
			HostKey:           checkHostKey("acidburn", known),
			HostKeyAlgorithms: hostKeyAlgorithms(known),
		},
	}
}

func serverKey(s *sshServer) []config.HostKey {
	return []config.HostKey{{PublicKey: s.hostKey.PublicKey()}}
}

func TestOpenSSH_connectsAndChecksHostKey(t *testing.T) {
	f := newSSHFixture(t, "hunter2", serverKey)

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
	f := newSSHFixture(t, "something else", serverKey)

	_, _, err := connect(t.Context(), f.transport, f.builds)

	assert.ErrorIs(t, err, errCredentialsRejected)
}

func TestOpenSSH_rejectsHostWithNoKeys(t *testing.T) {
	f := newSSHFixture(t, "hunter2", func(*sshServer) []config.HostKey { return nil })

	_, _, err := connect(t.Context(), f.transport, f.builds)

	assert.ErrorContains(t, err, "no host_keys")
}

func TestOpenSSH_rejectsChangedHostKey(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherKey, err := ssh.NewSignerFromKey(other)
	require.NoError(t, err)
	f := newSSHFixture(
		t,
		"hunter2",
		func(*sshServer) []config.HostKey { return []config.HostKey{{PublicKey: otherKey.PublicKey()}} },
	)

	_, _, err = connect(t.Context(), f.transport, f.builds)

	assert.ErrorContains(t, err, ssh.FingerprintSHA256(f.server.hostKey.PublicKey()))
}

func TestHostAddress(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err)

	tests := []struct {
		name    string
		host    string
		address string
		want    string
	}{
		{"remote host", "not-" + hostname, "203.0.113.1:2222", "203.0.113.1:2222"},
		{"remote host with no address", "not-" + hostname, "", ""},
		{"this machine", hostname, "203.0.113.1", "127.0.0.1"},
		{"this machine with a port", hostname, "203.0.113.1:2222", "127.0.0.1:2222"},
		{"this machine with no address", hostname, "", "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				assert.Equal(t, tt.want, hostAddress(tt.host, config.HostEntry{Address: tt.address}))
			},
		)
	}
}

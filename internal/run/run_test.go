package run

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	api "github.com/mydnshost/mydnshost-go-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

// fakeAgent speaks the agent side of the protocol.
type fakeAgent struct {
	hash  string
	arch  string
	facts host.Facts
	// status decides each resource's check result; nil means in sync.
	status func(r host.Resource) host.Status
	// applyFailure, if set, fails the resource with this ID during apply.
	applyFailure string
	// upgradeError, if set, is reported instead of upgrading.
	upgradeError string
	// silent exits before Hello, as sudo does when it rejects a password.
	silent bool

	mu       sync.Mutex
	received []string
	upgrades [][]byte
	checks   []host.ResourceList
}

func (f *fakeAgent) serve(r io.ReadCloser, w io.WriteCloser) {
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if f.silent {
		return
	}
	if f.arch == "" {
		f.arch = "amd64"
	}
	conn := host.NewConn(r, w)
	if conn.Send(host.Hello{Proto: host.ProtocolVersion, Hash: f.hash, Arch: f.arch}) != nil {
		return
	}
	var resources host.ResourceList
	var checked []host.Checked
	for {
		msg, err := conn.Receive()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.received = append(f.received, strings.TrimPrefix(fmt.Sprintf("%T", msg), "host."))
		f.mu.Unlock()
		switch m := msg.(type) {
		case host.Upgrade:
			if f.upgradeError != "" {
				_ = conn.Send(host.Error{Message: f.upgradeError})
				continue
			}
			f.mu.Lock()
			f.upgrades = append(f.upgrades, m.Binary)
			f.mu.Unlock()
			sum := sha256.Sum256(m.Binary)
			f.hash = hex.EncodeToString(sum[:])
			_ = conn.Send(host.Hello{Proto: host.ProtocolVersion, Hash: f.hash, Arch: f.arch})
		case host.FactsRequest:
			_ = conn.Send(host.FactsReply{Facts: f.facts})
		case host.Check:
			f.mu.Lock()
			f.checks = append(f.checks, m.Resources)
			f.mu.Unlock()
			resources, checked = m.Resources, nil
			for _, res := range resources {
				c := host.Checked{ID: res.ID(), Status: host.StatusInSync}
				if f.status != nil {
					c.Status = f.status(res)
				}
				if c.Status == host.StatusDrifted {
					c.Diff = "- old\n+ new\n"
				}
				checked = append(checked, c)
				_ = conn.Send(c)
			}
			_ = conn.Send(host.Done{})
		case host.Apply:
			failed := false
			for i, res := range resources {
				a := host.Applied{ID: res.ID(), Status: host.StatusInSync}
				switch {
				case failed:
					a.Status = host.StatusSkipped
				case res.ID() == f.applyFailure:
					a.Status, a.Error, failed = host.StatusFailed, "boom", true
				case checked[i].Status != host.StatusInSync:
					a.Status = host.StatusChanged
				}
				_ = conn.Send(a)
			}
			_ = conn.Send(host.Done{Failed: failed})
		case host.Bye:
			return
		}
	}
}

func (f *fakeAgent) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

var errTestRejected = errors.New("rejected")

type pipeTransport struct {
	agent *fakeAgent
}

// Start connects the fake agent through OS pipes, which buffer like the real
// transports do.
func (p pipeTransport) Start(context.Context) (*AgentPipe, error) {
	controllerRead, agentWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	agentRead, controllerWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		p.agent.serve(agentRead, agentWrite)
		close(done)
	}()
	return &AgentPipe{
		Reader: controllerRead,
		Writer: controllerWrite,
		Close: func() error {
			_ = controllerWrite.Close()
			<-done
			return controllerRead.Close()
		},
		EarlyExit: errTestRejected,
	}, nil
}

type fakeBuilds map[string]Build

func newFakeBuilds(t *testing.T) fakeBuilds {
	t.Helper()
	builds := fakeBuilds{}
	for _, arch := range agentArchs {
		binary := []byte("agent for " + arch)
		sum := sha256.Sum256(binary)
		builds[arch] = Build{Binary: binary, Hash: hex.EncodeToString(sum[:])}
	}
	return builds
}

func (f fakeBuilds) Build(_ context.Context, goarch string) (Build, error) {
	b, ok := f[goarch]
	if !ok {
		return Build{}, errors.New("no build")
	}
	return b, nil
}

func TestConnect_currentAgentIsNotUpgraded(t *testing.T) {
	builds := newFakeBuilds(t)
	fake := &fakeAgent{hash: builds["arm64"].Hash, arch: "arm64"}

	a, upgraded, err := connect(t.Context(), pipeTransport{fake}, builds)
	require.NoError(t, err)
	a.bye()

	assert.False(t, upgraded)
	assert.Equal(t, []string{"Bye"}, fake.messages())
}

func TestConnect_upgradesStaleAgentForItsArch(t *testing.T) {
	builds := newFakeBuilds(t)
	fake := &fakeAgent{hash: "stale", arch: "arm64"}

	a, upgraded, err := connect(t.Context(), pipeTransport{fake}, builds)
	require.NoError(t, err)
	a.bye()

	assert.True(t, upgraded)
	require.Len(t, fake.upgrades, 1)
	assert.Equal(t, "agent for arm64", string(fake.upgrades[0]))
	assert.Equal(t, []string{"Upgrade", "Bye"}, fake.messages())
}

func TestConnect_reportsFailedUpgrade(t *testing.T) {
	fake := &fakeAgent{hash: "stale", arch: "amd64", upgradeError: "disk full"}

	_, _, err := connect(t.Context(), pipeTransport{fake}, newFakeBuilds(t))

	assert.ErrorContains(t, err, "disk full")
}

func TestConnect_reportsEarlyExit(t *testing.T) {
	_, _, err := connect(t.Context(), pipeTransport{&fakeAgent{silent: true}}, newFakeBuilds(t))
	assert.ErrorIs(t, err, errTestRejected)
}

func TestConnect_unsupportedArch(t *testing.T) {
	fake := &fakeAgent{hash: "stale", arch: "riscv64"}
	_, _, err := connect(t.Context(), pipeTransport{fake}, newFakeBuilds(t))
	assert.ErrorContains(t, err, "riscv64")
}

type runnerFixture struct {
	runner    *Runner
	out       *bytes.Buffer
	confirmed []string
	answer    bool
}

func newRunnerFixture(t *testing.T, resources host.ResourceList) *runnerFixture {
	t.Helper()
	f := &runnerFixture{out: &bytes.Buffer{}, answer: true}
	f.runner = &Runner{
		Out: f.out,
		Confirm: func(prompt string) (bool, error) {
			f.confirmed = append(f.confirmed, prompt)
			return f.answer, nil
		},
		Builds: newFakeBuilds(t),
		Compile: func(target, host.Facts) (host.ResourceList, config.DNSConfig, error) {
			return resources, config.DNSConfig{}, nil
		},
	}
	return f
}

func (f *runnerFixture) target(name string, agent *fakeAgent) target {
	agent.hash = f.runner.Builds.(fakeBuilds)["amd64"].Hash
	return target{name: name, transport: pipeTransport{agent}}
}

var testResources = host.ResourceList{
	host.File{
		Path:   "/etc/ssh/sshd_config.d/10-sensible.conf",
		Notify: host.ResourceList{host.ServiceAction{Name: "ssh", Action: "reload"}},
	},
	host.Package{Name: "zsh"},
	host.Service{Name: "docker"},
}

func deferDocker(r host.Resource) host.Status {
	switch r.ID() {
	case "file:/etc/ssh/sshd_config.d/10-sensible.conf":
		return host.StatusDrifted
	case "service:docker":
		return host.StatusDeferred
	default:
		return host.StatusInSync
	}
}

func TestExecute_planShowsChangesAndReportsUnreachableHosts(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	changed := &fakeAgent{status: deferDocker}
	clean := &fakeAgent{}
	targets := []target{
		f.target("acidburn", changed),
		{name: "smarts", err: errors.New("no credentials")},
		f.target("penderghast", clean),
	}

	err := f.runner.Execute(t.Context(), targets, false, false)

	require.ErrorIs(t, err, errFailed)
	out := f.out.String()
	assert.Contains(t, out, "agents      acidburn ✓  smarts ✗  penderghast ✓\n")
	assert.Contains(t, out, "smarts      ✗ no credentials\n")
	assert.Contains(
		t,
		out,
		"acidburn    ~ file /etc/ssh/sshd_config.d/10-sensible.conf\n"+
			"              - old\n              + new\n              ↻ then reload ssh\n"+
			"            ? service docker  deferred\n",
	)
	assert.Contains(t, out, "penderghast ✓ 3 unchanged\n")
	assert.Contains(t, out, "1 change on 1 target; 1 more will be checked during apply\n")
	assert.Empty(t, f.confirmed)
	assert.Equal(t, []string{"FactsRequest", "Check", "Bye"}, changed.messages())
}

func TestExecute_appliesAfterConfirmation(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	changed := &fakeAgent{status: deferDocker}
	clean := &fakeAgent{}

	err := f.runner.Execute(
		t.Context(),
		[]target{f.target("acidburn", changed), f.target("penderghast", clean)},
		true,
		false,
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"Apply 1 change on 1 target; 1 more will be checked during apply? [y/N] "}, f.confirmed)
	assert.Equal(t, []string{"FactsRequest", "Check", "Apply", "Bye"}, changed.messages())
	assert.Equal(t, []string{"FactsRequest", "Check", "Bye"}, clean.messages())
	assert.Contains(t, f.out.String(), "acidburn    ✓ file /etc/ssh/sshd_config.d/10-sensible.conf\n")
	assert.Contains(t, f.out.String(), "acidburn    ✓ service docker\n")
}

func TestExecute_declinedDoesNotApply(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	f.answer = false
	changed := &fakeAgent{status: deferDocker}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", changed)}, true, false)

	require.NoError(t, err)
	assert.Equal(t, []string{"FactsRequest", "Check", "Bye"}, changed.messages())
}

func TestExecute_yesSkipsConfirmation(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	changed := &fakeAgent{status: deferDocker}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", changed)}, true, true)

	require.NoError(t, err)
	assert.Empty(t, f.confirmed)
	assert.Contains(t, changed.messages(), "Apply")
}

func TestExecute_failureSkipsRestOfHost(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	changed := &fakeAgent{status: deferDocker, applyFailure: "file:/etc/ssh/sshd_config.d/10-sensible.conf"}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", changed)}, true, true)

	require.ErrorIs(t, err, errFailed)
	assert.Contains(t, f.out.String(), "acidburn    ✗ file /etc/ssh/sshd_config.d/10-sensible.conf: boom\n")
	assert.Contains(t, f.out.String(), "acidburn    - 2 skipped\n")
}

func TestExecute_nothingToDo(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	clean := &fakeAgent{}

	err := f.runner.Execute(t.Context(), []target{f.target("penderghast", clean)}, true, false)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "No changes\n")
	assert.Empty(t, f.confirmed)
}

func TestExecute_compileErrorIsReportedForThatHost(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	f.runner.Compile = func(t target, _ host.Facts) (host.ResourceList, config.DNSConfig, error) {
		if t.name == "weird" {
			return nil, config.DNSConfig{}, errors.New("unsupported OS family")
		}
		return testResources, config.DNSConfig{}, nil
	}
	weird := &fakeAgent{}
	changed := &fakeAgent{status: deferDocker}

	err := f.runner.Execute(
		t.Context(),
		[]target{f.target("weird", weird), f.target("acidburn", changed)},
		true,
		true,
	)

	require.ErrorIs(t, err, errFailed)
	assert.Contains(t, f.out.String(), "weird       ✗ unsupported OS family\n")
	assert.Equal(t, []string{"FactsRequest", "Bye"}, weird.messages())
	assert.Contains(t, changed.messages(), "Apply")
}

// testRepo opens a config directory whose secrets are encrypted to a fresh
// identity. Other files can be written to it afterwards.
func testRepo(t *testing.T) (*config.Repo, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	dir := t.TempDir()
	hostsYAML := "hosts:\n  acidburn:\n    address: 192.0.2.1\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hostsYAML), 0o600))
	secretsYAML := "recipients: [" + id.Recipient().String() + "]\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yml"), []byte(secretsYAML), 0o600))
	repo, err := config.Open(dir, func() (age.Identity, error) { return id, nil })
	require.NoError(t, err)
	return repo, dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestExecute_dnsIsPlannedFromFactsAndAppliedAfterHosts(t *testing.T) {
	repo, dir := testRepo(t)
	user, err := repo.Encrypt("me@example.com")
	require.NoError(t, err)
	key, err := repo.Encrypt("key")
	require.NoError(t, err)
	writeFile(
		t,
		filepath.Join(dir, "hosts", "acidburn.yml"),
		"dns:\n  hostname: acidburn.example.com\n  auth_user: "+indentYAML(user)+"\n  auth_key: "+indentYAML(key)+"\n",
	)

	f := newRunnerFixture(t, testResources)
	f.runner.Compile = func(t target, facts host.Facts) (host.ResourceList, config.DNSConfig, error) {
		cfg, err := repo.HostConfig(t.name, facts.OSFamily)
		return testResources, cfg.DNS, err
	}
	client := &fakeDNS{
		domains: []string{"example.com"},
		records: []api.ExistingRecord{
			{Id: 1, Name: "acidburn", Type: "A", Content: "203.0.113.1"},
			{Id: 2, Name: "acidburn", Type: "AAAA", Content: "2001:db8::1"},
		},
	}
	var account []string
	f.runner.DNS = func(user, key string) dnsClient {
		account = []string{user, key}
		return client
	}
	agent := &fakeAgent{
		status: deferDocker,
		facts:  host.Facts{DefaultIPv4: "203.0.113.2", DefaultIPv6: "2001:0db8:0::1"},
	}

	err = f.runner.Execute(t.Context(), []target{f.target("acidburn", agent)}, true, true)

	require.NoError(t, err)
	assert.Equal(t, []string{"me@example.com", "key"}, account)
	out := f.out.String()
	assert.Contains(
		t,
		out,
		"dns         ~ A acidburn.example.com  203.0.113.1 → 203.0.113.2\n            ✓ 1 unchanged\n",
	)
	assert.NotContains(t, out, "AAAA")
	assert.Contains(t, out, "2 changes on 2 targets")
	assert.Greater(
		t,
		strings.Index(out, "dns         ✓ A acidburn.example.com"),
		strings.Index(out, "acidburn    ✓ service docker"),
	)
	require.Len(t, client.modified, 1)
	assert.Equal(t, "example.com", client.modified[0].domain)
}

func indentYAML(s string) string {
	return strings.ReplaceAll(s, "\n", "\n  ")
}

func TestUnknownHost(t *testing.T) {
	inv := config.Inventory{
		Hosts: map[string]config.HostEntry{
			"acidburn": {Address: "acidburn.929w.net"},
			"smarts":   {Address: "192.0.2.5"},
		},
	}

	require.ErrorContains(t, unknownHost(inv, "acidburn.929w.net"), "address of acidburn")
	require.ErrorContains(t, unknownHost(inv, "nope"), "acidburn, smarts")
}

package run

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

// fakeAgent speaks the agent side of the protocol.
type fakeAgent struct {
	hash string
	arch string
	// proto, if set, is reported in the first Hello; upgrades report the
	// current version.
	proto int
	facts host.Facts
	// status decides each resource's check result; nil means in sync.
	status func(r host.Resource) host.Status
	// applyFailure, if set, fails the resource with this ID during apply.
	applyFailure string
	// applyWarnings are reported once each changed resource, by ID, is
	// applied.
	applyWarnings map[string]string
	// upgradeError, if set, is reported instead of upgrading.
	upgradeError string
	// silent exits before Hello, as sudo does when it rejects a password.
	silent bool
	// gate, if set, is called with each message's type before it's handled.
	gate func(msg string)
	// leftovers are reported for Prune, by resource ID.
	leftovers map[string][]string
	// removeFailure, if set, fails removing this item.
	removeFailure string
	// listFailure, if set, fails listing the leftovers of the resource with
	// this ID.
	listFailure string
	// previews are what Preview replies with, by item.
	previews map[string]host.Previewed

	mu       sync.Mutex
	received []string
	upgrades [][]byte
	checks   []host.ResourceList
	removed  []string
	// ignored is what the last Check said to ignore.
	ignored map[string][]string
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
	if f.proto == 0 {
		f.proto = host.ProtocolVersion
	}
	conn := host.NewConn(r, w)
	if conn.Send(host.Hello{Proto: f.proto, Hash: f.hash, Arch: f.arch}) != nil {
		return
	}
	var resources host.ResourceList
	checked := make([]host.Checked, 0, len(resources))
	for {
		msg, err := conn.Receive()
		if err != nil {
			return
		}
		name := strings.TrimPrefix(fmt.Sprintf("%T", msg), "host.")
		f.mu.Lock()
		f.received = append(f.received, name)
		f.mu.Unlock()
		if f.gate != nil {
			f.gate(name)
		}
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
			resources = m.Resources
			f.mu.Lock()
			f.ignored = m.Ignored
			f.mu.Unlock()
			checked = f.check(conn, resources)
		case host.Apply:
			f.apply(conn, resources, checked)
		case host.Prune:
			for _, res := range resources {
				if res.ID() == f.listFailure {
					_ = conn.Send(host.Leftovers{ID: res.ID(), Error: "denied"})
				} else if items := f.leftovers[res.ID()]; len(items) > 0 {
					_ = conn.Send(host.Leftovers{ID: res.ID(), Items: items})
				}
			}
			_ = conn.Send(host.Done{})
		case host.Remove:
			r := host.Removed{ID: m.ID, Item: m.Item}
			if m.Item == f.removeFailure {
				r.Error = "busy"
			} else {
				f.mu.Lock()
				f.removed = append(f.removed, m.Item)
				f.mu.Unlock()
			}
			_ = conn.Send(r)
		case host.Preview:
			p, ok := f.previews[m.Item]
			if !ok {
				p.Error = "not found"
			}
			p.ID, p.Item = m.ID, m.Item
			_ = conn.Send(p)
		case host.Bye:
			return
		}
	}
}

func (f *fakeAgent) check(conn *host.Conn, resources host.ResourceList) []host.Checked {
	f.mu.Lock()
	f.checks = append(f.checks, resources)
	f.mu.Unlock()
	checked := make([]host.Checked, 0, len(resources))
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
	return checked
}

func (f *fakeAgent) apply(conn *host.Conn, resources host.ResourceList, checked []host.Checked) {
	failed := false
	for i, res := range resources {
		a := host.Applied{ID: res.ID(), Status: host.StatusInSync}
		switch {
		case failed:
			a.Status = host.StatusSkipped
		case res.ID() == f.applyFailure:
			a.Status, a.Error, failed = host.StatusFailed, "boom", true
		case checked[i].Status != host.StatusInSync:
			a.Status, a.Warning = host.StatusChanged, f.applyWarnings[res.ID()]
			_ = conn.Send(host.Applying{ID: res.ID()})
		}
		_ = conn.Send(a)
	}
	_ = conn.Send(host.Done{Failed: failed})
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

func TestConnect_upgradeReplacesOldProtocol(t *testing.T) {
	fake := &fakeAgent{hash: "stale", arch: "amd64", proto: host.ProtocolVersion - 1}
	a, _, err := connect(t.Context(), pipeTransport{fake}, newFakeBuilds(t))
	require.NoError(t, err)
	a.bye()
}

func TestConnect_refusesCurrentBuildWithOldProtocol(t *testing.T) {
	builds := newFakeBuilds(t)
	fake := &fakeAgent{hash: builds["amd64"].Hash, arch: "amd64", proto: host.ProtocolVersion - 1}
	_, _, err := connect(t.Context(), pipeTransport{fake}, builds)
	assert.ErrorContains(t, err, "go generate")
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
		Ask: func(prompt string) (string, error) {
			f.confirmed = append(f.confirmed, prompt)
			if f.answer {
				return "y", nil
			}
			return "n", nil
		},
		Builds: newFakeBuilds(t),
		Compile: func(target, host.Facts) (compiled, error) {
			return compiled{resources: resources}, nil
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

	f.answer = false
	err := f.runner.Execute(t.Context(), targets, false)

	require.ErrorIs(t, err, errFailed)
	out := f.out.String()
	assert.Contains(t, out, "> Connecting to agents\n  ✓ acidburn\n  ✗ smarts: no credentials\n  ✓ penderghast\n")
	assert.Contains(
		t,
		out,
		"> Resolving changes on acidburn\n"+
			"  ~ file /etc/ssh/sshd_config.d/10-sensible.conf\n"+
			"    - old\n    + new\n    ↻ then reload ssh\n"+
			"  ? service docker  deferred\n",
	)
	assert.Contains(t, out, "> Resolving changes on penderghast\n  ✓ 3 unchanged\n")
	assert.NotContains(t, out, "Resolving changes on smarts")
	assert.Equal(t, []string{"Apply 1 change on 1 target; 1 more will be checked during apply? [y/N] "}, f.confirmed)
	assert.Equal(t, []string{"FactsRequest", "Check", "Bye"}, changed.messages())
}

// headingWatcher closes each channel once its heading has been written.
type headingWatcher struct {
	out      bytes.Buffer
	headings map[string]chan struct{}
}

func (w *headingWatcher) Write(p []byte) (int, error) {
	n, _ := w.out.Write(p)
	for heading, ch := range w.headings {
		if strings.Contains(w.out.String(), "> "+heading+"\n") {
			close(ch)
			delete(w.headings, heading)
		}
	}
	return n, nil
}

func TestExecute_headingsAreShownBeforeWaiting(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	w := &headingWatcher{
		headings: map[string]chan struct{}{
			"Connecting to agents":          make(chan struct{}),
			"Resolving changes on acidburn": make(chan struct{}),
		},
	}
	f.runner.Out = w
	waits := map[string]chan struct{}{
		"FactsRequest": w.headings["Connecting to agents"],
		"Check":        w.headings["Resolving changes on acidburn"],
	}
	var timedOut []string
	agent := &fakeAgent{
		gate: func(msg string) {
			if ch, ok := waits[msg]; ok {
				select {
				case <-ch:
				case <-time.After(5 * time.Second):
					timedOut = append(timedOut, msg)
				}
			}
		},
	}

	require.NoError(t, f.runner.Execute(t.Context(), []target{f.target("acidburn", agent)}, false))
	assert.Empty(t, timedOut)
	assert.Contains(t, w.out.String(), "> Resolving changes on acidburn\n  ✓ 3 unchanged\n")
}

func TestExecute_appliesAfterConfirmation(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	changed := &fakeAgent{status: deferDocker}
	clean := &fakeAgent{}

	err := f.runner.Execute(
		t.Context(),
		[]target{f.target("acidburn", changed), f.target("penderghast", clean)},
		false,
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"Apply 1 change on 1 target; 1 more will be checked during apply? [y/N] "}, f.confirmed)
	assert.Equal(t, []string{"FactsRequest", "Check", "Apply", "Bye"}, changed.messages())
	assert.Equal(t, []string{"FactsRequest", "Check", "Bye"}, clean.messages())
	assert.Contains(
		t,
		f.out.String(),
		"> Applying changes on acidburn\n  ✓ file /etc/ssh/sshd_config.d/10-sensible.conf\n  ✓ service docker\n",
	)
	assert.NotContains(t, f.out.String(), "Applying changes on penderghast")
}

func TestExecute_declinedDoesNotApply(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	f.answer = false
	changed := &fakeAgent{status: deferDocker}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", changed)}, false)

	require.NoError(t, err)
	assert.Equal(t, []string{"FactsRequest", "Check", "Bye"}, changed.messages())
}

func TestExecute_yesSkipsConfirmation(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	changed := &fakeAgent{status: deferDocker}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", changed)}, true)

	require.NoError(t, err)
	assert.Empty(t, f.confirmed)
	assert.Contains(t, changed.messages(), "Apply")
}

func TestExecute_failureSkipsRestOfHost(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	changed := &fakeAgent{status: deferDocker, applyFailure: "file:/etc/ssh/sshd_config.d/10-sensible.conf"}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", changed)}, true)

	require.ErrorIs(t, err, errFailed)
	assert.Contains(t, f.out.String(), "  ✗ file /etc/ssh/sshd_config.d/10-sensible.conf: boom\n  - 2 skipped\n")
}

func TestExecute_nothingToDo(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	clean := &fakeAgent{}

	err := f.runner.Execute(t.Context(), []target{f.target("penderghast", clean)}, false)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "No changes\n")
	assert.Empty(t, f.confirmed)
}

func TestExecute_failuresDontClaimNoChanges(t *testing.T) {
	f := newRunnerFixture(t, testResources)

	err := f.runner.Execute(t.Context(), []target{{name: "smarts", err: errors.New("no credentials")}}, false)

	require.ErrorIs(t, err, errFailed)
	assert.NotContains(t, f.out.String(), "No changes")
}

func TestExecute_compileErrorIsReportedForThatHost(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	f.runner.Compile = func(t target, _ host.Facts) (compiled, error) {
		if t.name == "weird" {
			return compiled{}, errors.New("unsupported OS family")
		}
		return compiled{resources: testResources}, nil
	}
	weird := &fakeAgent{}
	changed := &fakeAgent{status: deferDocker}

	err := f.runner.Execute(
		t.Context(),
		[]target{f.target("weird", weird), f.target("acidburn", changed)},
		true,
	)

	require.ErrorIs(t, err, errFailed)
	assert.Contains(t, f.out.String(), "> Resolving changes on weird\n  ✗ unsupported OS family\n")
	assert.Equal(t, []string{"FactsRequest", "Bye"}, weird.messages())
	assert.Contains(t, changed.messages(), "Apply")
}

// testRepo opens a config directory whose secrets are encrypted to a fresh
// identity. Other files can be written to it afterwards.
func testRepo(t *testing.T) (*config.Repo, string, config.IdentitySource) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.d", "acidburn.yml"), "acidburn:\n  address: 192.0.2.1\n")
	settingsYAML := "secrets:\n  recipients: [" + id.Recipient().String() + "]\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sensible.yml"), []byte(settingsYAML), 0o600))
	source := func() (age.Identity, error) { return id, nil }
	repo, err := config.Open(dir, source)
	require.NoError(t, err)
	return repo, dir, source
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestExecute_dnsIsPlannedFromFactsAndAppliedAfterHosts(t *testing.T) {
	f, provider, opened := dnsFixture(t)
	acidburn := f.target(
		"acidburn",
		&fakeAgent{
			status: deferDocker,
			facts:  host.Facts{DefaultIPv4: "203.0.113.2", DefaultIPv6: "2001:0db8:0::1"},
		},
	)
	acidburn.dnsName = "acidburn.example.com"

	err := f.runner.Execute(t.Context(), []target{acidburn, f.target("smarts", &fakeAgent{})}, true)

	require.NoError(t, err)
	assert.Equal(t, "mydnshost", opened.Provider)
	user, err := opened.MyDNSHost.AuthUser.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "me@example.com", user)
	out := f.out.String()
	assert.Contains(
		t,
		out,
		"> Resolving DNS changes\n  ~ A acidburn.example.com  203.0.113.1 → 203.0.113.2\n  ✓ 1 unchanged\n",
	)
	assert.NotContains(t, out, "AAAA")
	assert.Contains(t, out, "2 changes on 2 targets")
	assert.Greater(
		t,
		strings.Index(out, "> Applying DNS changes\n  ✓ A acidburn.example.com\n"),
		strings.Index(out, "✓ service docker"),
	)
	require.Len(t, provider.applied, 1)
	assert.Equal(t, "example.com", provider.applied[0].zone)
}

func TestExecute_dnsIsHeldBackWhenAHostFailsToPlan(t *testing.T) {
	f, provider, _ := dnsFixture(t)
	acidburn := f.target("acidburn", &fakeAgent{status: deferDocker, facts: host.Facts{DefaultIPv4: "203.0.113.2"}})
	acidburn.dnsName = "acidburn.example.com"

	err := f.runner.Execute(
		t.Context(),
		[]target{acidburn, {name: "smarts", err: errors.New("no credentials")}},
		true,
	)

	require.ErrorIs(t, err, errFailed)
	out := f.out.String()
	assert.Contains(t, out, "~ A acidburn.example.com  203.0.113.1 → 203.0.113.2")
	assert.Contains(t, out, "! DNS changes won't be applied, as not every host could be planned")
	assert.Contains(t, out, "✓ service docker")
	assert.NotContains(t, out, "Applying DNS changes")
	assert.Empty(t, provider.applied)
}

func TestExecute_dnsRemovesRetiredNames(t *testing.T) {
	f, provider, _ := dnsFixture(t)
	provider.records = append(
		provider.records,
		dnsRecord{id: "3", name: "old", rtype: "CNAME", content: "acidburn.example.com"},
		dnsRecord{id: "4", name: "old", rtype: "MX", content: "mail.example.com"},
	)
	var saved []map[string][]string
	f.runner.DNSState = map[string][]string{"old.example.com": {"A", "AAAA", "CNAME"}}
	f.runner.SaveDNSState = func(s map[string][]string) error {
		saved = append(saved, s)
		return nil
	}
	acidburn := f.target("acidburn", &fakeAgent{facts: host.Facts{DefaultIPv4: "203.0.113.2"}})
	acidburn.dnsName = "acidburn.example.com"
	f.runner.DNSNames = map[string]string{"acidburn": "acidburn.example.com"}

	err := f.runner.Execute(t.Context(), []target{acidburn}, true)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "- CNAME old.example.com  acidburn.example.com")
	assert.NotContains(t, f.out.String(), "MX")
	require.Len(t, provider.applied, 2)
	assert.Equal(t, []dnsRecord{provider.records[2]}, provider.applied[1].changes.remove)
	assert.Empty(t, provider.applied[1].changes.add)
	assert.Equal(t, []map[string][]string{{"acidburn.example.com": {"A"}}}, saved)
}

func TestExecute_retiredNamesAreKeptWhenAHostFailsToPlan(t *testing.T) {
	f, provider, _ := dnsFixture(t)
	provider.records = append(provider.records, dnsRecord{id: "3", name: "old", rtype: "A", content: "203.0.113.1"})
	f.runner.DNSState = map[string][]string{"old.example.com": {"A"}}
	f.runner.SaveDNSState = func(map[string][]string) error {
		t.Error("saved DNS state")
		return nil
	}

	err := f.runner.Execute(t.Context(), []target{{name: "smarts", err: errors.New("no credentials")}}, true)

	require.ErrorIs(t, err, errFailed)
	assert.Contains(t, f.out.String(), "- A old.example.com  203.0.113.1")
	assert.Empty(t, provider.applied)
}

// dnsFixture is a runner whose DNS account is a fake holding acidburn's
// records, and the account's settings once it's opened.
func dnsFixture(t *testing.T) (*runnerFixture, *fakeDNS, *config.DNSSettings) {
	t.Helper()
	repo, dir, source := testRepo(t)
	user, err := repo.Encrypt("me@example.com")
	require.NoError(t, err)
	key, err := repo.Encrypt("key")
	require.NoError(t, err)
	settings, err := os.ReadFile(filepath.Join(dir, "sensible.yml"))
	require.NoError(t, err)
	writeFile(
		t,
		filepath.Join(dir, "sensible.yml"),
		string(settings)+"dns:\n  provider: mydnshost\n  mydnshost:\n    auth_user: "+indentYAML(indentYAML(user))+
			"\n    auth_key: "+indentYAML(indentYAML(key))+"\n",
	)
	repo, err = config.Open(dir, source)
	require.NoError(t, err)

	f := newRunnerFixture(t, testResources)
	f.runner.DNSSettings = repo.DNS()
	provider := &fakeDNS{
		zones: map[string]bool{"example.com": true},
		records: []dnsRecord{
			{id: "1", name: "acidburn", rtype: "A", content: "203.0.113.1"},
			{id: "2", name: "acidburn", rtype: "AAAA", content: "2001:db8::1"},
		},
	}
	var opened config.DNSSettings
	f.runner.DNS = func(s config.DNSSettings) (dnsProvider, error) {
		opened = s
		return provider, nil
	}
	return f, provider, &opened
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

func TestPaletteDiff(t *testing.T) {
	text := "owner: 0 → 1000\n--- /etc/x\n@@ -1 +1 @@\n-old\n+new\n same\n"

	assert.Equal(
		t,
		[]string{
			"  owner: 0 → 1000",
			"  \x1b[1m--- /etc/x\x1b[0m",
			"  \x1b[36m@@ -1 +1 @@\x1b[0m",
			"  \x1b[31m-old\x1b[0m",
			"  \x1b[32m+new\x1b[0m",
			"   same",
		},
		palette(true).diff(text, "  "),
	)
	assert.Equal(t, indent(text, "  "), palette(false).diff(text, "  "))
}

func TestRendererGroupsConcurrentApplies(t *testing.T) {
	var buf bytes.Buffer
	r := newRenderer(&buf)
	a := &hostRun{name: "acidburn"}
	b := &hostRun{name: "smarts"}
	c := &hostRun{name: "penderghast"}
	changed := func(id string) host.Applied { return host.Applied{ID: id, Status: host.StatusChanged, Handler: true} }

	r.applied(a, changed("file:/a1"))
	r.applied(b, changed("file:/b1"))
	r.applied(c, changed("file:/c1"))
	r.applied(a, changed("file:/a2"))
	r.applied(b, changed("file:/b2"))
	r.applyDone(b)
	r.applyDone(a)
	r.applied(c, changed("file:/c2"))
	r.applyDone(c)

	assert.Equal(
		t,
		"> Applying changes on acidburn\n  ↻ file /a1\n  ↻ file /a2\n"+
			"> Applying changes on smarts\n  ↻ file /b1\n  ↻ file /b2\n"+
			"> Applying changes on penderghast\n  ↻ file /c1\n  ↻ file /c2\n",
		buf.String(),
	)
}

func TestRendererTasksWriteInOrderWithoutATerminal(t *testing.T) {
	var buf bytes.Buffer
	r := newRenderer(&buf)
	a := r.beginSection("Resolving changes on acidburn")
	b := r.beginSection("Resolving changes on smarts")
	assert.Equal(t, "> Resolving changes on acidburn\n", buf.String())

	r.finish(b, "  ✓ 2 unchanged")
	assert.Equal(t, "> Resolving changes on acidburn\n", buf.String())

	r.finish(a, "  ~ file /a")
	assert.Equal(
		t,
		"> Resolving changes on acidburn\n  ~ file /a\n> Resolving changes on smarts\n  ✓ 2 unchanged\n",
		buf.String(),
	)
}

// screen applies the cursor movements a live renderer writes, giving the
// lines left showing.
func screen(t *testing.T, out string) []string {
	t.Helper()
	lines := [][]rune{nil}
	row, col := 0, 0
	for i := 0; i < len(out); {
		if out[i] == '\x1b' {
			end := strings.IndexAny(out[i:], "FJKmhl")
			require.GreaterOrEqual(t, end, 0, "unterminated escape")
			args, code := out[i+2:i+end], out[i+end]
			i += end + 1
			switch code {
			case 'F':
				var n int
				_, err := fmt.Sscanf(args, "%d", &n)
				require.NoError(t, err)
				row, col = row-n, 0
				require.GreaterOrEqual(t, row, 0)
			case 'J':
				lines = append(lines[:row], lines[row][:col])
			case 'K':
				lines[row] = lines[row][:col]
			default:
			}
			continue
		}
		c, size := utf8.DecodeRuneInString(out[i:])
		i += size
		if c == '\n' {
			row, col = row+1, 0
			if row == len(lines) {
				lines = append(lines, nil)
			}
			continue
		}
		if col < len(lines[row]) {
			lines[row][col] = c
		} else {
			lines[row] = append(lines[row], c)
		}
		col++
	}
	text := make([]string, 0, len(lines))
	for _, l := range lines[:len(lines)-1] {
		text = append(text, string(l))
	}
	return text
}

func newLiveRenderer(buf *bytes.Buffer) *renderer {
	r := newRenderer(buf)
	r.live = true
	// Tests draw by hand, so frames don't depend on timing.
	r.ticking = true
	return r
}

func TestRendererDrawsUnfinishedTasks(t *testing.T) {
	var buf bytes.Buffer
	r := newLiveRenderer(&buf)
	r.section("Connecting to agents")
	a := r.beginItem("acidburn")
	b := r.beginItem("smarts")
	assert.Equal(t, []string{"> Connecting to agents", "  ⠋ acidburn", "  ⠋ smarts"}, screen(t, buf.String()))

	r.finish(b, "  ✓ smarts")
	assert.Equal(t, []string{"> Connecting to agents", "  ⠋ acidburn", "    smarts"}, screen(t, buf.String()))

	r.finish(a, "  ✗ acidburn: refused")
	assert.Equal(
		t,
		[]string{"> Connecting to agents", "  ✗ acidburn: refused", "  ✓ smarts"},
		screen(t, buf.String()),
	)
}

func TestRendererWritesSectionsAboveUnfinishedTasks(t *testing.T) {
	var buf bytes.Buffer
	r := newLiveRenderer(&buf)
	a := r.beginSection("Resolving changes on acidburn")
	b := r.beginSection("Resolving changes on smarts")
	assert.Equal(
		t,
		[]string{"⠋ Resolving changes on acidburn", "⠋ Resolving changes on smarts"},
		screen(t, buf.String()),
	)

	r.finish(a, "  ~ file /a", "    - old")
	r.line("interrupting")
	assert.Equal(
		t,
		[]string{
			"> Resolving changes on acidburn",
			"  ~ file /a",
			"    - old",
			"interrupting",
			"⠋ Resolving changes on smarts",
		},
		screen(t, buf.String()),
	)

	r.finish(b)
	assert.Equal(t, "> Resolving changes on smarts", screen(t, buf.String())[4])
}

func TestRendererDrawsWhatEachHostIsApplying(t *testing.T) {
	var buf bytes.Buffer
	r := newLiveRenderer(&buf)
	a := &hostRun{name: "acidburn"}
	b := &hostRun{name: "smarts"}

	r.applying(a, host.Applying{ID: "file:/a1"})
	r.applying(b, host.Applying{ID: "package:vim"})
	assert.Equal(
		t,
		[]string{"> Applying changes on acidburn", "  ⠋ file /a1", "  ⠋ package vim  smarts"},
		screen(t, buf.String()),
	)

	r.applied(a, host.Applied{ID: "file:/a1", Status: host.StatusChanged})
	assert.Equal(
		t,
		[]string{"> Applying changes on acidburn", "  ✓ file /a1", "  ⠋ package vim  smarts"},
		screen(t, buf.String()),
	)

	r.applyDone(a)
	r.applied(b, host.Applied{ID: "package:vim", Status: host.StatusFailed, Error: "boom"})
	r.applyDone(b)
	assert.Equal(
		t,
		[]string{
			"> Applying changes on acidburn",
			"  ✓ file /a1",
			"> Applying changes on smarts",
			"  ✗ package vim: boom",
		},
		screen(t, buf.String()),
	)
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 3))
	assert.Equal(t, "ab\x1b[0m", truncate("abc", 2))
	assert.Equal(t, "\x1b[32mab\x1b[0m", truncate("\x1b[32mabc\x1b[0m", 2))
	assert.Equal(t, "⠋ a\x1b[0m", truncate("⠋ abc", 3))
}

func TestPrintable(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"plain text":       {"export PATH=~/bin:$PATH", "export PATH=~/bin:$PATH"},
		"newlines and tab": {"a\n\tb\n", "a\n\tb\n"},
		"other unicode":    {"⠋ café �", "⠋ café �"},
		"escape sequence":  {"\x1b[2J\x1b]52;c;aGk=\a", `\x1b[2J\x1b]52;c;aGk=\a`},
		"carriage return":  {"real\rfake", `real\rfake`},
		"delete":           {"a\x7fb", `a\x7fb`},
		"c1 control":       {"a\u009b2Jb", `a\u009b2Jb`},
		"invalid utf-8":    {"a\x9b2J\xffb", `a\x9b2J\xffb`},
		"bidi override":    {"a\u202eb\u2066c", `a\u202eb\u2066c`},
		"zero width":       {"a\u200bb\ufeffc", `a\u200bb\ufeffc`},
	}
	for name, tt := range tests {
		t.Run(
			name,
			func(t *testing.T) {
				assert.Equal(t, tt.want, printable(tt.in))
			},
		)
	}
}

func TestConnect_makesAgentTextPrintable(t *testing.T) {
	builds := newFakeBuilds(t)
	fake := &fakeAgent{
		hash:  builds["amd64"].Hash,
		facts: host.Facts{OSFamily: "debian\x1b[2J"},
	}
	a, _, err := connect(t.Context(), pipeTransport{fake}, builds)
	require.NoError(t, err)
	defer a.bye()

	facts, err := a.facts()
	require.NoError(t, err)
	assert.Equal(t, `debian\x1b[2J`, facts.OSFamily)
}

func TestConnect_makesAgentErrorsPrintable(t *testing.T) {
	fake := &fakeAgent{hash: "stale", upgradeError: "disk\rfull"}
	_, _, err := connect(t.Context(), pipeTransport{fake}, newFakeBuilds(t))
	assert.ErrorContains(t, err, `disk\rfull`)
}

type writeRecorder struct{ writes []string }

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

func TestRendererSendsEachUpdateInOneSynchronisedWrite(t *testing.T) {
	w := &writeRecorder{}
	r := newRenderer(w)
	r.live, r.ticking = true, true
	a := r.beginSection("Resolving changes on acidburn")
	r.beginSection("Resolving changes on smarts")
	w.writes = nil

	r.finish(a, "  ~ file /a", "    - old", "    + new")
	require.Len(t, w.writes, 1)
	assert.True(t, strings.HasPrefix(w.writes[0], "\x1b[?2026h"))
	assert.True(t, strings.HasSuffix(w.writes[0], "\x1b[?2026l"))
}

func TestHostPlanLines_showsWarnings(t *testing.T) {
	h := &hostRun{
		resources: host.ResourceList{host.DockerNetwork{Name: "web"}, host.DockerNetwork{Name: "six"}},
		checked: []host.Checked{
			{ID: "docker-network:web", Status: host.StatusInSync, Warning: "IPv6 is on rather than off\n"},
			{ID: "docker-network:six", Status: host.StatusInSync},
		},
	}

	assert.Equal(
		t,
		[]string{"! docker-network web", "  IPv6 is on rather than off", "✓ 2 unchanged"},
		hostPlanLines(h, false),
	)
}

func TestHostPlanLines_indentsMultiLineErrors(t *testing.T) {
	h := &hostRun{
		resources: host.ResourceList{host.DockerNetwork{Name: "web"}},
		checked: []host.Checked{
			{ID: "docker-network:web", Status: host.StatusFailed, Error: "inspecting:\n✓ file /etc/x\n"},
		},
	}

	assert.Equal(t, []string{"✗ docker-network web: inspecting:", "  ✓ file /etc/x"}, hostPlanLines(h, false))
}

func recordID(dir, path string) string {
	return host.WrittenRecordIn(dir, host.File{Path: path}).ID()
}

func TestHostPlanLines_leavesOutRecordsOfChangingFiles(t *testing.T) {
	const files = host.WrittenDir + "/files"
	checked := []host.Checked{
		{ID: "file:/etc/a", Status: host.StatusDrifted, Diff: "create file\n"},
		{ID: recordID(files, "/etc/a"), Status: host.StatusDrifted, Diff: "create file\n"},
		{ID: "file:/etc/docker/daemon.json", Status: host.StatusDeferred},
		{ID: recordID(host.WrittenDir, "/etc/docker/daemon.json"), Status: host.StatusDeferred},
		{ID: "file:/etc/b", Status: host.StatusInSync},
		{ID: recordID(files, "/etc/b"), Status: host.StatusDrifted, Diff: "create file\n"},
		{ID: "file:/etc/c", Status: host.StatusInSync},
		{ID: recordID(files, "/etc/c"), Status: host.StatusDrifted, Diff: "change mode\n"},
		{ID: "file:/etc/d", Status: host.StatusDrifted, Diff: "create file\n"},
		{ID: recordID(files, "/etc/d"), Status: host.StatusFailed, Error: "denied"},
		{ID: "dir:/srv/e", Status: host.StatusDrifted, Diff: "create directory\n"},
		{ID: recordID(host.WrittenDir+"/directories", "/srv/e"), Status: host.StatusDrifted, Diff: "create file\n"},
	}
	h := &hostRun{resources: make(host.ResourceList, len(checked)), checked: checked}

	assert.Equal(
		t,
		[]string{
			"~ file /etc/a",
			"  create file",
			"? file /etc/docker/daemon.json  deferred",
			"~ file /etc/d",
			"  create file",
			"✗ " + displayID(recordID(files, "/etc/d")) + ": denied",
			"~ dir /srv/e",
			"  create directory",
			"~ 2 write records",
			"✓ 2 unchanged",
		},
		hostPlanLines(h, false),
	)
	assert.Equal(t, summary{changes: 5, targets: 1, deferred: 1}, summarise([]*hostRun{h}, nil))
}

func TestRendererLeavesOutRecordsOfChangedFiles(t *testing.T) {
	const files = host.WrittenDir + "/files"
	var buf bytes.Buffer
	r := newRenderer(&buf)
	h := &hostRun{name: "acidburn"}

	r.applied(h, host.Applied{ID: "file:/etc/a", Status: host.StatusChanged})
	r.applied(h, host.Applied{ID: recordID(files, "/etc/a"), Status: host.StatusChanged})
	r.applied(h, host.Applied{ID: "file:/etc/b", Status: host.StatusInSync})
	r.applied(h, host.Applied{ID: recordID(files, "/etc/b"), Status: host.StatusChanged})
	r.applied(h, host.Applied{ID: recordID(host.WrittenDir, "/etc/docker/daemon.json"), Status: host.StatusChanged})
	r.applied(h, host.Applied{ID: recordID(files, "/etc/c"), Status: host.StatusInSync})
	r.applied(h, host.Applied{ID: recordID(files, "/etc/d"), Status: host.StatusFailed, Error: "denied"})
	r.applied(h, host.Applied{ID: "dir:/srv/e", Status: host.StatusChanged})
	r.applied(h, host.Applied{ID: recordID(host.WrittenDir+"/directories", "/srv/e"), Status: host.StatusChanged})
	r.applyDone(h)

	assert.Equal(
		t,
		"> Applying changes on acidburn\n"+
			"  ✓ file /etc/a\n"+
			"  ✗ "+displayID(recordID(files, "/etc/d"))+": denied\n"+
			"  ✓ dir /srv/e\n"+
			"  ✓ 2 write records\n",
		buf.String(),
	)
}

func TestRendererIndentsMultiLineApplyErrors(t *testing.T) {
	var buf bytes.Buffer
	r := newRenderer(&buf)
	h := &hostRun{name: "acidburn"}

	r.applied(h, host.Applied{ID: "command:x", Status: host.StatusFailed, Error: "exit 1\n✓ file /etc/x", Output: "out"})
	r.applyError(h, errors.New("lost\n> Applying changes on smarts"))
	r.applyDone(h)

	assert.Equal(
		t,
		"> Applying changes on acidburn\n"+
			"  ✗ command x: exit 1\n    ✓ file /etc/x\n    out\n"+
			"  ✗ lost\n    > Applying changes on smarts\n",
		buf.String(),
	)
}

func TestPaletteFailureColoursEachLine(t *testing.T) {
	assert.Equal(t, []string{"\x1b[31m✗ a\x1b[0m", "\x1b[31m  b\x1b[0m"}, palette(true).failure("a\nb"))
}

func TestExecute_savesGeneratedValuesBeforeApplying(t *testing.T) {
	tests := []struct {
		name         string
		answer       bool
		saveErr      error
		wantSaved    []string
		wantMessages []string
		wantOut      string
	}{
		{"declined", false, nil, nil, []string{"FactsRequest", "Check", "Bye"}, ""},
		{
			"applied",
			true,
			nil,
			[]string{"acidburn"},
			[]string{"FactsRequest", "Check", "Apply", "Bye"},
			"> Saving generated secrets\n  ✓ acidburn\n> Applying changes on acidburn\n",
		},
		{
			"save fails",
			true,
			errors.New("disk full"),
			[]string{"acidburn"},
			[]string{"FactsRequest", "Check", "Bye"},
			"> Saving generated secrets\n  ✗ acidburn: disk full\n",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				f := newRunnerFixture(t, testResources)
				f.answer = tt.answer
				var saved []string
				changed := &fakeAgent{status: deferDocker}
				f.runner.Compile = func(tg target, _ host.Facts) (compiled, error) {
					return compiled{
						resources: testResources,
						save: func() error {
							assert.NotContains(t, changed.messages(), "Apply")
							saved = append(saved, tg.name)
							return tt.saveErr
						},
					}, nil
				}

				err := f.runner.Execute(t.Context(), []target{f.target("acidburn", changed)}, false)

				if tt.saveErr != nil {
					require.ErrorIs(t, err, errFailed)
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, tt.wantSaved, saved)
				assert.Equal(t, tt.wantMessages, changed.messages())
				if tt.wantOut == "" {
					assert.NotContains(t, f.out.String(), "Saving generated secrets")
				} else {
					assert.Contains(t, f.out.String(), tt.wantOut)
				}
			},
		)
	}
}

func TestCompiler_savesIssuedCertsOnce(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"sensible.yml":       "secrets:\n  recipients: [" + id.Recipient().String() + "]\ncas: [internal]\n",
		"hosts.d/hosts.yml":  "alpha:\n  roles: {web: }\n",
		"roles/web/role.yml": "certs:\n  web: {ca: internal, server: [web.example.com]}\n",
	} {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	open := func() *config.Repo {
		repo, err := config.Open(dir, func() (age.Identity, error) { return id, nil })
		require.NoError(t, err)
		return repo
	}
	facts := host.Facts{OSFamily: "arch"}
	keyContent := func(c compiled) string {
		// As the agent receives them.
		data, err := json.Marshal(c.resources)
		require.NoError(t, err)
		var received host.ResourceList
		require.NoError(t, json.Unmarshal(data, &received))
		i := slices.IndexFunc(received, func(r host.Resource) bool { return r.ID() == "file:/srv/certs/web/tls.key" })
		require.GreaterOrEqual(t, i, 0)
		assert.True(t, slices.ContainsFunc(received, func(r host.Resource) bool { return r.ID() == "cert-record:web" }))
		return received[i].(host.File).Content
	}

	first, err := compiler(open())(target{name: "alpha"}, facts)
	require.NoError(t, err)
	require.NotNil(t, first.save)
	require.NoError(t, first.save())

	second, err := compiler(open())(target{name: "alpha"}, facts)
	require.NoError(t, err)
	assert.Nil(t, second.save, "nothing new to save")
	assert.Equal(t, keyContent(first), keyContent(second))
}

func TestCompiler_findsUnusedSecrets(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"sensible.yml":                 "secrets:\n  recipients: [" + id.Recipient().String() + "]\n",
		"hosts.d/hosts.yml":            "alpha:\n  roles: {app: , data: }\n",
		"roles/app/docker-compose.yml": "services:\n  app:\n    image: nginx\n    environment:\n      DB: !generated db\n",
		"roles/data/role.yml":          "compose:\n  volumes: {blobs: {}}\n",
	} {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	open := func() *config.Repo {
		repo, err := config.Open(dir, func() (age.Identity, error) { return id, nil })
		require.NoError(t, err)
		return repo
	}
	saved := map[string]string{"db": "x", "token": "y"}
	require.NoError(
		t,
		open().SaveGenerated(
			"alpha",
			[]config.Stack{{Name: "app", Generated: saved}, {Name: "data", Generated: saved}, {Name: "old", Generated: saved}},
		),
	)
	facts := host.Facts{OSFamily: "arch"}

	c, err := compiler(open())(target{name: "alpha"}, facts)
	require.NoError(t, err)
	require.Len(t, c.unusedSecrets, 2)
	assert.Equal(t, "app", c.unusedSecrets[0].stack)
	assert.Equal(t, []string{"token"}, c.unusedSecrets[0].names)
	assert.True(t, c.unusedSecrets[0].inUse)
	assert.Equal(t, "old", c.unusedSecrets[1].stack)
	assert.Equal(t, []string{"db", "token"}, c.unusedSecrets[1].names)
	assert.False(t, c.unusedSecrets[1].inUse)

	for _, s := range c.unusedSecrets {
		require.NoError(t, s.drop())
	}
	again, err := compiler(open())(target{name: "alpha"}, facts)
	require.NoError(t, err)
	assert.Empty(t, again.unusedSecrets)
	generated := open().Inventory().Hosts["alpha"].Generated
	assert.ElementsMatch(t, []string{"app", "data"}, slices.Collect(maps.Keys(generated)))
	assert.Equal(t, []string{"db"}, slices.Collect(maps.Keys(generated["app"])))
}

func TestExecute_updatePackagesComesFirstAndWarnsOnceApplied(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	f.runner.UpdatePackages = true
	agent := &fakeAgent{
		status: func(r host.Resource) host.Status {
			if _, ok := r.(host.PackageUpdate); ok {
				return host.StatusDrifted
			}
			return host.StatusInSync
		},
		applyWarnings: map[string]string{"package-update": "the host needs a reboot\n"},
	}

	require.NoError(t, f.runner.Execute(t.Context(), []target{f.target("acidburn", agent)}, false))

	require.Len(t, agent.checks, 1)
	assert.Equal(t, append(host.ResourceList{host.PackageUpdate{}}, testResources...), agent.checks[0])
	assert.Contains(t, f.out.String(), "  ~ package-update\n")
	assert.Equal(t, []string{"Apply 1 change on 1 target? [y/N] "}, f.confirmed)
	assert.Contains(t, f.out.String(), "✓ package-update\n  ! package-update\n    the host needs a reboot\n")
}

func TestExecute_packagesAreOnlyUpdatedOnRequest(t *testing.T) {
	f := newRunnerFixture(t, testResources)
	agent := &fakeAgent{}

	require.NoError(t, f.runner.Execute(t.Context(), []target{f.target("acidburn", agent)}, false))

	require.Len(t, agent.checks, 1)
	assert.Equal(t, testResources, agent.checks[0])
}

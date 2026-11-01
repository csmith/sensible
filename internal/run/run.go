package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/features"
	"chameth.com/sensible/internal/host"
)

// Options select the hosts for Run and what to do with them.
type Options struct {
	ConfigDir string
	// Hosts limits the run to these inventory names. Empty means all hosts.
	Hosts []string
	// Addrs overrides inventory addresses, keyed by host name.
	Addrs map[string]string
	Apply bool
	// Yes applies without asking for confirmation.
	Yes bool
}

// Run plans the selected hosts and, with Options.Apply, applies the plan.
func Run(ctx context.Context, opts Options) error {
	out := os.Stdout
	repo, err := openRepo(opts.ConfigDir, out)
	if err != nil {
		return err
	}
	names, err := selectHosts(repo.Inventory(), opts.Hosts, opts.Addrs)
	if err != nil {
		return err
	}
	builder := NewEmbeddedBuilds()
	targets := make([]target, len(names))
	for i, name := range names {
		targets[i] = newTarget(repo, name, opts.Addrs[name], builder)
	}

	r := &Runner{
		Out:     out,
		Confirm: confirmOnTerminal,
		Builds:  builder,
		Compile: func(t target, facts host.Facts) (host.ResourceList, error) {
			cfg, err := repo.HostConfig(t.name, facts.OSFamily)
			if err != nil {
				return nil, err
			}
			return features.Resources(
				features.Host{
					Name:        t.name,
					Local:       t.local,
					Config:      cfg,
					Facts:       facts,
					SensibleKey: t.sensibleKey,
				},
			)
		},
		DNS:            newDNSClient,
		DNSCredentials: repo.DNS(),
	}
	return r.Execute(ctx, targets, opts.Apply, opts.Yes)
}

func openRepo(dir string, out io.Writer) (*config.Repo, error) {
	var repo *config.Repo
	repo, err := config.Open(
		dir,
		func() (age.Identity, error) {
			r := newRenderer(out)
			id, err := repo.CommandIdentity()()
			if err != nil {
				r.section("Resolving secrets", []string{r.p.fail("✗ age identity")})
				return nil, err
			}
			r.section("Resolving secrets", []string{r.p.ok("✓") + " age identity"})
			return id, nil
		},
	)
	return repo, err
}

// unknownHost explains that name isn't in the inventory, pointing at the
// right name when it's a host's address.
func unknownHost(inv config.Inventory, name string) error {
	for _, n := range slices.Sorted(maps.Keys(inv.Hosts)) {
		if inv.Hosts[n].Address == name {
			return fmt.Errorf("%s is the address of %s; use its name from hosts.d", name, n)
		}
	}
	return fmt.Errorf(
		"unknown host %q; hosts.d has %s",
		name,
		strings.Join(slices.Sorted(maps.Keys(inv.Hosts)), ", "),
	)
}

func selectHosts(inv config.Inventory, requested []string, addrs map[string]string) ([]string, error) {
	for name := range addrs {
		if !slices.Contains(requested, name) && len(requested) > 0 {
			return nil, fmt.Errorf("--addr given for %s, which isn't selected", name)
		}
		if _, ok := inv.Hosts[name]; !ok {
			return nil, unknownHost(inv, name)
		}
	}
	if len(requested) == 0 {
		names := make([]string, 0, len(inv.Hosts))
		for name := range inv.Hosts {
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}
	var names []string
	for _, name := range requested {
		if _, ok := inv.Hosts[name]; !ok {
			return nil, unknownHost(inv, name)
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names, nil
}

// target is a host to connect to. err is set when the host can't be
// reached at all, e.g. because it has no credentials.
type target struct {
	name        string
	dnsName     string
	local       bool
	sensibleKey string
	transport   Transport
	err         error
}

func newTarget(repo *config.Repo, name, addr string, builds Builds) target {
	entry := repo.Inventory().Hosts[name]
	t := target{name: name, dnsName: entry.DNSName}
	if isLocal(name) {
		t.local = true
		t.transport = &Local{Builds: builds}
		return t
	}
	if addr == "" {
		addr = entry.Address
	}
	if addr == "" {
		t.err = errors.New("no address")
		return t
	}
	if entry.SSHKey.IsZero() {
		t.err = fmt.Errorf("no credentials; run `sensible bootstrap %s`", name)
		return t
	}
	signer, password, err := revealCredentials(entry)
	if err != nil {
		t.err = err
		return t
	}
	t.sensibleKey = authorizedKey(signer.PublicKey(), name)
	t.transport = &OpenSSH{
		Name:              name,
		Address:           addr,
		Signer:            signer,
		Password:          password,
		HostKey:           checkHostKey(name, entry.HostKeys),
		HostKeyAlgorithms: hostKeyAlgorithms(entry.HostKeys),
	}
	return t
}

func revealCredentials(creds config.HostEntry) (ssh.Signer, string, error) {
	key, err := creds.SSHKey.Reveal()
	if err != nil {
		return nil, "", fmt.Errorf("ssh_key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil, "", fmt.Errorf("ssh_key: %w", err)
	}
	password, err := creds.SudoPassword.Reveal()
	if err != nil {
		return nil, "", fmt.Errorf("sudo_password: %w", err)
	}
	return signer, password, nil
}

func isLocal(name string) bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	short, _, _ := strings.Cut(hostname, ".")
	return hostname == name || short == name
}

// Runner plans and applies a set of targets. Its fields are the parts that
// vary between real runs and tests.
type Runner struct {
	Out            io.Writer
	Confirm        func(prompt string) (bool, error)
	Builds         Builds
	Compile        func(t target, facts host.Facts) (host.ResourceList, error)
	DNS            func(user, key string) dnsClient
	DNSCredentials config.DNSCredentials
}

// hostRun is one target's progress through a run.
type hostRun struct {
	target
	agent     *agent
	upgraded  bool
	facts     host.Facts
	resources host.ResourceList
	checked   []host.Checked
	failed    bool
}

var errFailed = errors.New("one or more targets failed")

// Execute connects to the targets, shows the combined plan and, if apply is
// set and confirmed, applies it.
func (r *Runner) Execute(ctx context.Context, targets []target, apply, yes bool) error {
	out := newRenderer(r.Out)
	runs := r.connect(ctx, targets)
	defer func() {
		for _, h := range runs {
			if h.agent != nil {
				h.agent.bye()
			}
		}
	}()
	out.agents(runs)

	r.checkAll(runs)
	dns := r.planDNS(ctx, runs)
	out.plan(runs, dns)

	s := summarise(runs, dns.changes)
	failed := len(dns.errs) > 0 || anyFailed(runs)
	out.line("")
	if s.empty() {
		out.line(out.p.bold("No changes"))
		return failedErr(failed)
	}
	if !apply || yes {
		out.line(out.p.bold(s.String()))
	}
	if !apply {
		return failedErr(failed)
	}
	if !yes {
		ok, err := r.Confirm("Apply " + s.String() + "? [y/N] ")
		if err != nil || !ok {
			return errors.Join(err, failedErr(failed))
		}
	}

	r.applyAll(runs, out)
	if len(dns.changes) > 0 {
		out.section("Applying DNS changes", nil)
	}
	for _, c := range dns.changes {
		err := c.apply(ctx)
		failed = failed || err != nil
		out.dnsResult(c, err)
	}
	return failedErr(failed || anyFailed(runs))
}

func anyFailed(runs []*hostRun) bool {
	return slices.ContainsFunc(
		runs,
		func(h *hostRun) bool { return h.err != nil || h.failed },
	)
}

func failedErr(failed bool) error {
	if failed {
		return errFailed
	}
	return nil
}

func (r *Runner) connect(ctx context.Context, targets []target) []*hostRun {
	runs := make([]*hostRun, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		h := &hostRun{target: t}
		runs[i] = h
		if h.err == nil {
			wg.Go(func() { h.connect(ctx, r.Builds) })
		}
	}
	wg.Wait()
	return runs
}

func (h *hostRun) connect(ctx context.Context, builds Builds) {
	a, upgraded, err := connect(ctx, h.transport, builds)
	if err != nil {
		h.err = err
		return
	}
	h.agent, h.upgraded = a, upgraded
	if h.facts, err = a.facts(); err != nil {
		h.err = err
	}
}

func (r *Runner) checkAll(runs []*hostRun) {
	var wg sync.WaitGroup
	for _, h := range runs {
		if h.agent == nil || h.err != nil {
			continue
		}
		var err error
		h.resources, err = r.Compile(h.target, h.facts)
		if err != nil {
			h.err = err
			continue
		}
		wg.Go(h.check)
	}
	wg.Wait()
}

func (h *hostRun) check() {
	checked, err := h.agent.check(h.resources)
	if err != nil {
		h.err = err
		return
	}
	h.checked = checked
	for _, c := range checked {
		if c.Status == host.StatusFailed {
			h.failed = true
		}
	}
}

func (r *Runner) applyAll(runs []*hostRun, out *renderer) {
	var wg sync.WaitGroup
	for _, h := range runs {
		if h.agent != nil && h.pending() {
			wg.Go(func() { h.apply(out) })
		}
	}
	wg.Wait()
}

func (h *hostRun) apply(out *renderer) {
	done, err := h.agent.apply(func(a host.Applied) { out.applied(h, a) })
	if err != nil {
		h.err = err
		out.applyError(h, err)
	}
	if done.Failed {
		h.failed = true
	}
	out.applyDone(h)
}

func (h *hostRun) pending() bool {
	return h.err == nil && slices.ContainsFunc(
		h.checked,
		func(c host.Checked) bool { return c.Status == host.StatusDrifted || c.Status == host.StatusDeferred },
	)
}

type summary struct {
	changes, targets, deferred int
}

func summarise(runs []*hostRun, dns []*dnsChange) summary {
	var s summary
	for _, h := range runs {
		if !h.pending() {
			continue
		}
		s.targets++
		for _, c := range h.checked {
			switch c.Status {
			case host.StatusDrifted:
				s.changes++
			case host.StatusDeferred:
				s.deferred++
			default:
			}
		}
	}
	if len(dns) > 0 {
		s.targets++
		s.changes += len(dns)
	}
	return s
}

func (s summary) String() string {
	text := fmt.Sprintf("%s on %s", plural(s.changes, "change"), plural(s.targets, "target"))
	if s.deferred > 0 {
		text += fmt.Sprintf("; %d more will be checked during apply", s.deferred)
	}
	return text
}

func (s summary) empty() bool {
	return s.changes == 0 && s.deferred == 0
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Transport starts an agent somewhere and returns its streams.
type Transport interface {
	Start(ctx context.Context) (*AgentPipe, error)
}

// AgentPipe is a started agent.
type AgentPipe struct {
	Reader io.Reader
	Writer io.Writer
	Close  func() error
	// EarlyExit is reported when the agent's output ends before its Hello.
	EarlyExit error
}

// Builds provides agent binaries for a GOARCH.
type Builds interface {
	Build(ctx context.Context, goarch string) (Build, error)
}

// connect starts an agent and upgrades it if it isn't the current build.
func connect(ctx context.Context, t Transport, builds Builds) (*agent, bool, error) {
	pipe, err := t.Start(ctx)
	if err != nil {
		return nil, false, err
	}
	a := &agent{conn: host.NewConn(pipe.Reader, pipe.Writer), close: pipe.Close}
	hello, err := a.hello(pipe.EarlyExit)
	if err != nil {
		_ = a.close()
		return nil, false, err
	}
	if !slices.Contains(agentArchs, hello.Arch) {
		_ = a.close()
		return nil, false, fmt.Errorf("unsupported architecture %q", hello.Arch)
	}
	b, err := builds.Build(ctx, hello.Arch)
	if err != nil {
		_ = a.close()
		return nil, false, err
	}
	if b.Hash == hello.Hash {
		return a, false, nil
	}

	if err := a.upgrade(b, pipe.EarlyExit); err != nil {
		_ = a.close()
		return nil, false, fmt.Errorf("upgrading agent: %w", err)
	}
	return a, true, nil
}

// agent is a connected agent that has said Hello.
type agent struct {
	conn  *host.Conn
	close func() error
}

func (a *agent) hello(earlyExit error) (host.Hello, error) {
	msg, err := a.receive()
	if err != nil {
		if earlyExit != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return host.Hello{}, earlyExit
		}
		if errors.As(err, new(agentError)) {
			return host.Hello{}, err
		}
		return host.Hello{}, fmt.Errorf("waiting for agent: %w", err)
	}
	hello, ok := msg.(host.Hello)
	if !ok {
		return host.Hello{}, fmt.Errorf("agent sent %T before Hello", msg)
	}
	return hello, nil
}

// upgrade replaces the agent with the given build.
func (a *agent) upgrade(b Build, earlyExit error) error {
	if err := a.conn.Send(host.Upgrade{Binary: b.Binary}); err != nil {
		return err
	}
	hello, err := a.hello(earlyExit)
	if err != nil {
		return err
	}
	if hello.Hash != b.Hash {
		return fmt.Errorf("agent still reports build %.12s after upgrade", hello.Hash)
	}
	return nil
}

func goarch(machine string) (string, error) {
	switch machine {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q", machine)
	}
}

func (a *agent) facts() (host.Facts, error) {
	if err := a.conn.Send(host.FactsRequest{}); err != nil {
		return host.Facts{}, err
	}
	reply, err := receive[host.FactsReply](a)
	return reply.Facts, err
}

func (a *agent) check(resources host.ResourceList) ([]host.Checked, error) {
	if err := a.conn.Send(host.Check{Resources: resources}); err != nil {
		return nil, err
	}
	var checked []host.Checked
	for {
		msg, err := a.receive()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case host.Checked:
			checked = append(checked, m)
		case host.Done:
			if len(checked) != len(resources) {
				return nil, fmt.Errorf("agent checked %d of %d resources", len(checked), len(resources))
			}
			return checked, nil
		default:
			return nil, fmt.Errorf("unexpected %T while checking", msg)
		}
	}
}

func (a *agent) apply(each func(host.Applied)) (host.Done, error) {
	if err := a.conn.Send(host.Apply{}); err != nil {
		return host.Done{}, err
	}
	for {
		msg, err := a.receive()
		if err != nil {
			return host.Done{Failed: true}, err
		}
		switch m := msg.(type) {
		case host.Applied:
			each(m)
		case host.Done:
			return m, nil
		default:
			return host.Done{Failed: true}, fmt.Errorf("unexpected %T while applying", msg)
		}
	}
}

func (a *agent) bye() {
	_ = a.conn.Send(host.Bye{})
	_ = a.close()
}

// receive reads the next message, turning an Error from the agent into an
// error.
func (a *agent) receive() (any, error) {
	msg, err := a.conn.Receive()
	if err != nil {
		return nil, err
	}
	if e, ok := msg.(host.Error); ok {
		return nil, agentError(e.Message)
	}
	return msg, nil
}

type agentError string

func (e agentError) Error() string {
	return "agent: " + string(e)
}

func receive[T any](a *agent) (T, error) {
	var zero T
	msg, err := a.receive()
	if err != nil {
		return zero, err
	}
	v, ok := msg.(T)
	if !ok {
		return zero, fmt.Errorf("expected %T from agent, got %T", zero, msg)
	}
	return v, nil
}

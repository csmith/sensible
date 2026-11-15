package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

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
	// Yes applies without asking for confirmation.
	Yes bool
	// UpdatePackages brings each host's packages up to date before anything
	// else.
	UpdatePackages bool
}

// Run plans the selected hosts and applies the plan once confirmed.
func Run(ctx context.Context, opts Options) error {
	out := os.Stdout
	repo, err := openRepo(opts.ConfigDir, out)
	if err != nil {
		return err
	}
	names, err := selectHosts(repo.Inventory(), opts.Hosts)
	if err != nil {
		return err
	}
	builder := NewEmbeddedBuilds()
	targets := make([]target, len(names))
	for i, name := range names {
		targets[i] = newTarget(repo, name)
	}

	r := &Runner{
		Out:         out,
		Confirm:     confirmOnTerminal,
		Builds:      builder,
		Compile:     compiler(repo),
		DNS:         newDNSProvider,
		DNSSettings: repo.DNS(),
		Vhosts:      repo.Vhosts(),
		DNSNames:    dnsNames(repo.Inventory()),

		DNSState:     repo.DNSState(),
		SaveDNSState: repo.SaveDNSState,

		OIDC:          newOIDCProvider,
		OIDCSettings:  repo.OIDC(),
		OIDCOwners:    oidcOwners(repo.Inventory()),
		OIDCAPIOwners: oidcAPIOwners(repo.Inventory()),

		UpdatePackages: opts.UpdatePackages,
	}
	return r.Execute(ctx, targets, opts.Yes)
}

// compiler builds a host's resources from the repo, as apply makes them.
func compiler(repo *config.Repo) func(target, host.Facts) (compiled, error) {
	return func(t target, facts host.Facts) (compiled, error) {
		cfg, err := repo.HostConfig(t.name, facts.OSFamily)
		if err != nil {
			return compiled{}, err
		}
		resources, err := features.Resources(
			features.Host{
				Name:        t.name,
				Config:      cfg,
				Facts:       facts,
				SensibleKey: t.sensibleKey,
			},
		)
		if err != nil {
			return compiled{}, err
		}
		c := compiled{resources: resources}
		generated := slices.ContainsFunc(cfg.Stacks, func(s config.Stack) bool { return len(s.Generated) > 0 })
		if generated || slices.ContainsFunc(cfg.IssuedCerts, config.Cert.Unsaved) {
			c.save = func() error {
				if err := repo.SaveCerts(t.name, cfg.IssuedCerts); err != nil {
					return err
				}
				return repo.SaveGenerated(t.name, cfg.Stacks)
			}
		}
		c.unusedSecrets = unusedSecrets(repo, t.name, cfg)
		c.ignored = repo.Inventory().Hosts[t.name].Ignored
		c.ignore = func(id, item string) error { return repo.IgnoreLeftover(t.name, id, item) }
		c.oidcClients, c.oidcAPIs = cfg.OIDCClients, cfg.OIDCAPIs
		c.oidc = oidcRecords{
			clients: repo.Inventory().Hosts[t.name].OIDCClients,
			save: func(id string, saved config.SavedOIDCClient) error {
				return repo.SaveOIDCClient(t.name, id, saved)
			},
			drop:    func(id string) error { return repo.DropOIDCClient(t.name, id) },
			apis:    repo.Inventory().Hosts[t.name].OIDCAPIs,
			saveAPI: func(identifier string) error { return repo.SaveOIDCAPI(t.name, identifier) },
			dropAPI: func(identifier string) error { return repo.DropOIDCAPI(t.name, identifier) },
		}
		return c, nil
	}
}

// unusedSecrets are the host's saved generated values for stacks it no
// longer has, and those its stacks no longer use. A removed stack whose
// volume directory is still declared keeps its values, as the volumes may
// hold data that uses them.
func unusedSecrets(repo *config.Repo, name string, cfg config.Config) []savedSecrets {
	saved := repo.Inventory().Hosts[name].Generated
	var unused []savedSecrets
	for _, stack := range slices.Sorted(maps.Keys(saved)) {
		names := slices.Sorted(maps.Keys(saved[stack]))
		inUse := false
		if i := slices.IndexFunc(cfg.Stacks, func(s config.Stack) bool { return s.Name == stack }); i >= 0 {
			names, inUse = cfg.Stacks[i].Unused, true
		} else {
			dir := filepath.Join(config.VolumesDir, stack)
			if slices.ContainsFunc(cfg.Volumes, func(v config.Volume) bool { return filepath.Dir(v.Path) == dir }) {
				continue
			}
		}
		if len(names) == 0 {
			continue
		}
		unused = append(
			unused,
			savedSecrets{
				stack: stack,
				names: names,
				inUse: inUse,
				drop:  func() error { return repo.DropGenerated(name, stack, names) },
			},
		)
	}
	return unused
}

func openRepo(dir string, out io.Writer) (*config.Repo, error) {
	var repo *config.Repo
	repo, err := config.Open(
		dir,
		func() (age.Identity, error) {
			r := newRenderer(out)
			r.section("Resolving secrets")
			t := r.beginItem("age identity")
			id, err := repo.CommandIdentity()()
			if err != nil {
				r.finish(t, itemIndent+r.p.fail("✗ age identity"))
				return nil, err
			}
			r.finish(t, itemIndent+r.p.ok("✓")+" age identity")
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

func selectHosts(inv config.Inventory, requested []string) ([]string, error) {
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
	sensibleKey string
	transport   Transport
	err         error
}

func newTarget(repo *config.Repo, name string) target {
	entry := repo.Inventory().Hosts[name]
	t := target{name: name, dnsName: entry.DNSName}
	address := hostAddress(name, entry)
	if address == "" {
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
		Address:           address,
		Signer:            signer,
		Password:          password,
		HostKey:           checkHostKey(name, entry.HostKeys),
		HostKeyAlgorithms: hostKeyAlgorithms(entry.HostKeys),
	}
	return t
}

func dnsNames(inv config.Inventory) map[string]string {
	names := map[string]string{}
	for name, e := range inv.Hosts {
		if e.DNSName != "" {
			names[name] = e.DNSName
		}
	}
	return names
}

func revealCredentials(creds config.HostEntry) (ssh.Signer, string, error) {
	key, err := creds.SSHKey.Reveal()
	if err != nil {
		return nil, "", fmt.Errorf("ssh_key: %w", err)
	}
	if key == creds.SSHKey.Placeholder() {
		return nil, "", errors.New("ssh_key can't be decrypted to connect; use --facts")
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

// hostAddress is where to reach a host. The machine this runs on is reached
// over loopback, as its configured address may not be reachable from itself.
func hostAddress(name string, entry config.HostEntry) string {
	if !isLocal(name) {
		return entry.Address
	}
	if _, port, err := net.SplitHostPort(entry.Address); err == nil {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return "127.0.0.1"
}

func isLocal(name string) bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	short, _, _ := strings.Cut(hostname, ".")
	return hostname == name || short == name
}

// compiled is what a host should have.
type compiled struct {
	resources host.ResourceList
	// save keeps values generated for the resources, so later runs use the
	// same ones. It's nil if nothing was generated.
	save func() error
	// unusedSecrets are what prune offers to drop from the host's state.
	unusedSecrets []savedSecrets
	// ignored are the leftovers that are meant to stay, as items by the ID
	// of the resource that lists them, and ignore records another.
	ignored map[string][]string
	ignore  func(id, item string) error
	// oidcClients and oidcAPIs are the OIDC clients and APIs the host
	// declares, and oidc those sensible manages for it.
	oidcClients map[string]config.OIDCClientConfig
	oidcAPIs    map[string]config.OIDCAPIConfig
	oidc        oidcRecords
}

// savedSecrets are the generated values saved for one of a host's stacks.
type savedSecrets struct {
	stack string
	names []string
	// inUse is set when the host still has the stack, which no longer
	// uses these values.
	inUse bool
	drop  func() error
}

// Runner plans and applies a set of targets. Its fields are the parts that
// vary between real runs and tests.
type Runner struct {
	Out     io.Writer
	Confirm func(prompt string) (bool, error)
	// Ask returns the answer to a prompt, trimmed and in lower case.
	Ask         func(prompt string) (string, error)
	Builds      Builds
	Compile     func(t target, facts host.Facts) (compiled, error)
	DNS         func(settings config.DNSSettings) (dnsProvider, error)
	DNSSettings config.DNSSettings
	// Vhosts maps each vhost to the hosts serving it, and DNSNames each
	// host to its dns_name, for all hosts, not just those in the run.
	Vhosts   map[string][]string
	DNSNames map[string]string
	// DNSState maps each name sensible has set records for to the types it
	// manages there, and SaveDNSState replaces it. With no SaveDNSState,
	// names aren't recorded.
	DNSState     map[string][]string
	SaveDNSState func(map[string][]string) error
	OIDC         func(settings config.OIDCSettings) (oidcProvider, error)
	OIDCSettings config.OIDCSettings
	// OIDCOwners maps each OIDC client sensible manages to the hosts it's
	// for, and OIDCAPIOwners each API to its host, for all hosts.
	OIDCOwners    map[string][]string
	OIDCAPIOwners map[string]string
	// UpdatePackages puts a PackageUpdate before each host's resources.
	UpdatePackages bool
}

// hostRun is one target's progress through a run.
type hostRun struct {
	target
	agent     *agent
	upgraded  bool
	facts     host.Facts
	resources host.ResourceList
	save      func() error
	// unusedSecrets, ignored and ignore are kept from compiling for prune.
	unusedSecrets []savedSecrets
	ignored       map[string][]string
	ignore        func(id, item string) error
	oidcClients   map[string]config.OIDCClientConfig
	oidcAPIs      map[string]config.OIDCAPIConfig
	oidc          oidcRecords
	// oidcChanged is set when the OIDC changes register a secret generated
	// for the host, and saveFailed when its generated values couldn't be
	// saved.
	oidcChanged bool
	saveFailed  bool
	checked     []host.Checked
	failed      bool
	// leftovers are what prune offers to remove, and unlisted the
	// resources whose leftovers couldn't be listed.
	leftovers []*leftover
	unlisted  []host.Leftovers
	// done is closed when the host's current step, connecting or checking,
	// has finished.
	done chan struct{}
}

var errFailed = errors.New("one or more targets failed")

// Execute connects to the targets, shows the combined plan and, once
// confirmed, applies it.
func (r *Runner) Execute(ctx context.Context, targets []target, yes bool) error {
	out := newRenderer(r.Out)
	runs := r.connect(ctx, targets)
	defer byeAll(runs)
	out.agents(runs)

	r.checkAll(runs)
	out.plan(runs)
	var dns dnsPlan
	if names, warnings := r.managedNames(runs); len(names) > 0 || len(warnings) > 0 {
		t := out.beginSection("Resolving DNS changes")
		dns = r.planDNS(ctx, names, warnings)
		out.finish(t, out.dnsLines(dns)...)
	}

	var oidc oidcPlan
	if slices.ContainsFunc(runs, func(h *hostRun) bool { return len(h.oidcClients) > 0 || len(h.oidcAPIs) > 0 }) {
		t := out.beginSection("Resolving OIDC changes")
		oidc = r.planOIDC(ctx, runs)
		out.finish(t, out.crossHostLines(oidc.lines(), nil, oidc.errs, oidc.unchanged)...)
	}

	failed := len(dns.errs) > 0 || len(oidc.errs) > 0 || anyFailed(runs)
	steps := slices.DeleteFunc(
		[]crossHostStep{r.dnsStep(dns), oidc.step()},
		func(s crossHostStep) bool { return s.changes == 0 },
	)
	if anyFailed(runs) && len(steps) > 0 {
		out.line("")
		for _, st := range steps {
			out.line(out.p.change(fmt.Sprintf("! %s won't be applied, as not every host could be planned", st.name)))
		}
		steps = nil
	}

	s := summarise(runs, steps)
	if s.empty() {
		// With failures, there may be changes that couldn't be planned.
		if !failed {
			out.line("")
			out.line(out.p.bold("No changes"))
		}
		return failedErr(failed)
	}
	out.line("")
	if yes {
		out.line(out.p.bold(s.String()))
	} else {
		ok, err := r.Confirm("Apply " + s.String() + "? [y/N] ")
		if err != nil || !ok {
			return errors.Join(err, failedErr(failed))
		}
	}

	saveGenerated(runs, out)
	r.applyAll(runs, out)
	for _, st := range steps {
		if !st.apply(ctx, out) {
			failed = true
		}
	}
	return failedErr(failed || anyFailed(runs))
}

// crossHostStep is a change worked out from the configuration of every
// host, such as DNS records. It's only applied when every host in the run
// planned, as a host that didn't may have changed what it should be.
type crossHostStep struct {
	// name is plural, e.g. "DNS changes".
	name    string
	changes int
	// apply reports whether every change succeeded.
	apply func(ctx context.Context, out *renderer) bool
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

// connect starts connecting to each target, closing its done when finished.
func (r *Runner) connect(ctx context.Context, targets []target) []*hostRun {
	runs := make([]*hostRun, len(targets))
	for i, t := range targets {
		h := &hostRun{target: t, done: make(chan struct{})}
		runs[i] = h
		if h.err != nil {
			close(h.done)
			continue
		}
		go func() {
			defer close(h.done)
			h.connect(ctx, r.Builds)
		}()
	}
	return runs
}

func byeAll(runs []*hostRun) {
	for _, h := range runs {
		if h.agent != nil {
			h.agent.bye()
		}
	}
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

// checkAll starts checking each connected host, closing its done when
// finished.
func (r *Runner) checkAll(runs []*hostRun) {
	for _, h := range runs {
		h.done = make(chan struct{})
		if h.agent == nil || h.err != nil {
			close(h.done)
			continue
		}
		c, err := r.Compile(h.target, h.facts)
		if err != nil {
			h.err = err
			close(h.done)
			continue
		}
		if r.UpdatePackages {
			c.resources = append(host.ResourceList{host.PackageUpdate{}}, c.resources...)
		}
		h.resources, h.save, h.unusedSecrets = c.resources, c.save, c.unusedSecrets
		h.ignored, h.ignore = c.ignored, c.ignore
		h.oidcClients, h.oidcAPIs, h.oidc = c.oidcClients, c.oidcAPIs, c.oidc
		go func() {
			defer close(h.done)
			h.check()
		}()
	}
}

func (h *hostRun) check() {
	checked, err := h.agent.check(host.Check{Resources: h.resources, Ignored: h.ignored})
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

// saveGenerated saves the values generated for each host about to be
// applied, or whose OIDC clients' secrets are about to be registered, so
// they're used from then on. A host whose values can't be saved isn't
// applied.
func saveGenerated(runs []*hostRun, out *renderer) {
	var saving []*hostRun
	for _, h := range runs {
		if h.agent != nil && (h.pending() || h.oidcChanged) && h.save != nil {
			saving = append(saving, h)
		}
	}
	if len(saving) == 0 {
		return
	}
	out.section("Saving generated secrets")
	for _, h := range saving {
		if err := h.save(); err != nil {
			h.err, h.saveFailed = err, true
			out.item(out.p.failure(h.name + ": " + err.Error())...)
			continue
		}
		out.item(out.p.ok("✓") + " " + h.name)
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
	done, err := h.agent.apply(
		func(a host.Applying) { out.applying(h, a) },
		func(a host.Applied) { out.applied(h, a) },
	)
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

func summarise(runs []*hostRun, steps []crossHostStep) summary {
	var s summary
	for _, h := range runs {
		if !h.pending() {
			continue
		}
		s.targets++
		quiet := quietRecords(h.checked)
		for _, c := range h.checked {
			if quiet[c.ID] {
				continue
			}
			switch c.Status {
			case host.StatusDrifted:
				s.changes++
			case host.StatusDeferred:
				s.deferred++
			default:
			}
		}
	}
	for _, st := range steps {
		s.targets++
		s.changes += st.changes
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
	upgraded := b.Hash != hello.Hash
	if upgraded {
		if hello, err = a.upgrade(b, pipe.EarlyExit); err != nil {
			_ = a.close()
			return nil, false, fmt.Errorf("upgrading agent: %w", err)
		}
	}
	if hello.Proto < host.ProtocolVersion {
		_ = a.close()
		return nil, false, fmt.Errorf(
			"agent speaks protocol %d, but this controller needs %d (run go generate before building)",
			hello.Proto,
			host.ProtocolVersion,
		)
	}
	// Only now is the agent known to understand Ping.
	a.keepAlive(pingInterval)
	return a, upgraded, nil
}

// agent is a connected agent that has said Hello.
type agent struct {
	conn  *host.Conn
	close func() error
	// stopPings, if set, stops keepAlive.
	stopPings func()
}

// pingInterval is well inside the 30 minutes sensible-config gives sshd's
// ChannelTimeout.
var pingInterval = 5 * time.Minute

// keepAlive pings the agent until bye, so the session isn't closed for being
// idle while the controller waits at a prompt or the agent is busy with a
// long step. The agent only reads pings between requests, but sending them
// is enough for sshd to see traffic.
func (a *agent) keepAlive(every time.Duration) {
	stop := make(chan struct{})
	a.stopPings = sync.OnceFunc(func() { close(stop) })
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if a.conn.Send(host.Ping{}) != nil {
					return
				}
			}
		}
	}()
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
func (a *agent) upgrade(b Build, earlyExit error) (host.Hello, error) {
	if err := a.conn.Send(host.Upgrade{Binary: b.Binary}); err != nil {
		return host.Hello{}, err
	}
	hello, err := a.hello(earlyExit)
	if err != nil {
		return host.Hello{}, err
	}
	if hello.Hash != b.Hash {
		return host.Hello{}, fmt.Errorf("agent still reports build %.12s after upgrade", hello.Hash)
	}
	return hello, nil
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

func (a *agent) check(msg host.Check) ([]host.Checked, error) {
	resources := msg.Resources
	if err := a.conn.Send(msg); err != nil {
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

func (a *agent) apply(starting func(host.Applying), each func(host.Applied)) (host.Done, error) {
	if err := a.conn.Send(host.Apply{}); err != nil {
		return host.Done{}, err
	}
	for {
		msg, err := a.receive()
		if err != nil {
			return host.Done{Failed: true}, err
		}
		switch m := msg.(type) {
		case host.Applying:
			starting(m)
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
	if a.stopPings != nil {
		a.stopPings()
	}
	_ = a.conn.Send(host.Bye{})
	_ = a.close()
}

// receive reads the next message, turning an Error from the agent into an
// error. Every string in it has its control characters made visible, as
// they can carry anything from the host, such as a file's content in a diff.
func (a *agent) receive() (any, error) {
	msg, err := a.conn.Receive()
	if err != nil {
		return nil, err
	}
	msg = printableStrings(msg)
	if e, ok := msg.(host.Error); ok {
		return nil, agentError(e.Message)
	}
	return msg, nil
}

func printableStrings(msg any) any {
	v := reflect.New(reflect.TypeOf(msg)).Elem()
	v.Set(reflect.ValueOf(msg))
	makePrintable(v)
	return v.Interface()
}

func makePrintable(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(printable(v.String()))
		}
	case reflect.Struct:
		for _, field := range v.Fields() {
			makePrintable(field)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			makePrintable(v.Index(i))
		}
	default:
	}
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

// providerClient is the HTTP client for DNS and OIDC providers' APIs. It
// refuses redirects, as Go would send their API keys on to wherever a
// redirect points.
func providerClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("refusing to follow a redirect to %s", req.URL.Redacted())
		},
	}
}

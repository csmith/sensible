package run

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"chameth.com/sensible/internal/config"
)

// oidcProvider is an admin account with an OIDC provider.
type oidcProvider interface {
	oidcClientAdmin
	oidcAPIAdmin
}

// oidcClientAdmin manages a provider's clients.
type oidcClientAdmin interface {
	// Client returns nil if there's no client with the ID.
	Client(ctx context.Context, id string) (*oidcClient, error)
	Secrets(ctx context.Context, id string) ([]oidcSecret, error)
	// Groups maps each user group's name to its ID.
	Groups(ctx context.Context) (map[string]string, error)
	Create(ctx context.Context, c oidcClient) error
	// Update sets the client's settings to c's, leaving those sensible
	// doesn't manage as they are.
	Update(ctx context.Context, c oidcClient) error
	SetGroups(ctx context.Context, id string, groups []string) error
	// SetLogo sets the client's logo for the light or dark theme, taking
	// its type from name's extension.
	SetLogo(ctx context.Context, id string, dark bool, name string, data []byte) error
	// AddSecret registers secret for the client, returning its ID.
	AddSecret(ctx context.Context, id, secret string) (string, error)
	DeleteSecret(ctx context.Context, id, secretID string) error
	// Delete succeeds if the client is already gone.
	Delete(ctx context.Context, id string) error
}

// oidcAPIAdmin manages a provider's APIs and which clients may call them.
type oidcAPIAdmin interface {
	// APIs are the provider's APIs, by identifier.
	APIs(ctx context.Context) (map[string]*oidcAPI, error)
	// CreateAPI returns the new API's ID, which the other API methods take.
	CreateAPI(ctx context.Context, identifier, name string) (string, error)
	RenameAPI(ctx context.Context, id, name string) error
	// SetPermissions replaces the API's permissions, returning each one's ID
	// by key.
	SetPermissions(ctx context.Context, id string, permissions []oidcPermission) (map[string]string, error)
	// Grants are the clients that may call the API, by client ID.
	Grants(ctx context.Context, id string) (map[string]oidcGrant, error)
	// Grant replaces the client's access with g, whose permissions
	// are IDs.
	Grant(ctx context.Context, id, clientID string, g oidcGrant) error
	Revoke(ctx context.Context, id, clientID string) error
	// DeleteAPI succeeds if the API is already gone.
	DeleteAPI(ctx context.Context, id string) error
}

// oidcClient is a client's settings that sensible manages.
type oidcClient struct {
	id                               string
	name                             string
	callbackURLs, logoutCallbackURLs []string
	public, pkce, skipConsent        bool
	// restricted limits the client to the user groups with the IDs in
	// groups, which are in order.
	restricted bool
	groups     []string
	// launchURL is left as it is if it's empty in the client sensible
	// wants.
	launchURL            string
	hasLogo, hasDarkLogo bool
}

// oidcSecret is one of a client's secrets. Its prefix is the start of its
// value, or empty if that isn't known.
type oidcSecret struct {
	id     string
	prefix string
	active bool
}

func newOIDCProvider(s config.OIDCSettings) (oidcProvider, error) {
	switch s.Provider {
	case "pocketid":
		return newPocketID(s.PocketID)
	case "":
		return nil, errors.New("sensible.yml: oidc.provider isn't set")
	default:
		return nil, fmt.Errorf("sensible.yml: oidc.provider: unknown provider %q", s.Provider)
	}
}

// oidcRecords are the OIDC clients sensible manages for a host, each with
// what it registered, and the APIs, by identifier, with the means to change
// them.
type oidcRecords struct {
	clients map[string]config.SavedOIDCClient
	save    func(id string, saved config.SavedOIDCClient) error
	drop    func(id string) error

	apis    []string
	saveAPI func(identifier string) error
	dropAPI func(identifier string) error
}

// oidcPlan is the OIDC client and API changes for a run, with how many
// clients and APIs are already as they should be.
type oidcPlan struct {
	changes    []*oidcChange
	apiChanges []*oidcAPIChange
	unchanged  int
	errs       []error
}

// planOIDC works out the changes the clients and APIs the running hosts
// declare need. A client is only planned if every host sensible manages it
// for is in the run, and an API only moves from another host if that host is
// in the run and no longer declares it.
func (r *Runner) planOIDC(ctx context.Context, runs []*hostRun) oidcPlan {
	var p oidcPlan
	byName := map[string]*hostRun{}
	for _, h := range runs {
		byName[h.name] = h
	}
	clients := p.declaredClients(runs)
	apis := p.declared(runs, "api", func(h *hostRun) []string { return slices.Collect(maps.Keys(h.oidcAPIs)) })
	if len(clients) == 0 && len(apis) == 0 {
		return p
	}
	provider, err := r.OIDC(r.OIDCSettings)
	if err != nil {
		p.errs = append(p.errs, err)
		return p
	}
	planned, ok := p.planClients(ctx, provider, clients, byName, r.OIDCOwners)
	if ok && len(apis) > 0 {
		p.planAPIs(ctx, provider, apis, byName, r.OIDCAPIOwners, planned)
	}
	return p
}

// declared maps each ID that a running host declares to that host, noting
// those that more than one declares as errors.
func (p *oidcPlan) declared(runs []*hostRun, kind string, ids func(h *hostRun) []string) map[string]*hostRun {
	declared := map[string]*hostRun{}
	conflicted := map[string]bool{}
	for _, h := range runs {
		if h.agent == nil || h.err != nil {
			continue
		}
		for _, id := range slices.Sorted(slices.Values(ids(h))) {
			if other, ok := declared[id]; ok {
				if !conflicted[id] {
					p.errs = append(
						p.errs,
						fmt.Errorf("%s %s: both %s and %s declare it", kind, id, other.name, h.name),
					)
				}
				conflicted[id] = true
				continue
			}
			declared[id] = h
		}
	}
	for id := range conflicted {
		delete(declared, id)
	}
	return declared
}

// declaredClient is a client as the running hosts that declare it want it:
// with each host's callback URLs, and its other settings the same on each.
type declaredClient struct {
	cfg config.OIDCClientConfig
	// hosts are those that declare it, by name.
	hosts []*hostRun
}

// declaredClients merges the clients that the running hosts declare, by
// ID, noting those the hosts disagree about as errors.
func (p *oidcPlan) declaredClients(runs []*hostRun) map[string]*declaredClient {
	declared := map[string]*declaredClient{}
	conflicted := map[string]bool{}
	byHostName := func(a, b *hostRun) int { return strings.Compare(a.name, b.name) }
	for _, h := range slices.SortedFunc(slices.Values(runs), byHostName) {
		if h.agent == nil || h.err != nil {
			continue
		}
		for _, id := range slices.Sorted(maps.Keys(h.oidcClients)) {
			cfg := h.oidcClients[id]
			d, ok := declared[id]
			switch {
			case !ok:
				declared[id] = &declaredClient{
					cfg:   cfg,
					hosts: []*hostRun{h},
				}
				continue
			case conflicted[id]:
				continue
			}
			if field := clientDifference(d.cfg, cfg); field != "" {
				p.errs = append(
					p.errs,
					fmt.Errorf("client %s: %s and %s set different %s", id, d.hosts[0].name, h.name, field),
				)
				conflicted[id] = true
				continue
			}
			d.cfg.CallbackURLs = union(d.cfg.CallbackURLs, cfg.CallbackURLs)
			d.cfg.LogoutCallbackURLs = union(d.cfg.LogoutCallbackURLs, cfg.LogoutCallbackURLs)
			d.hosts = append(d.hosts, h)
		}
	}
	for id := range conflicted {
		delete(declared, id)
	}
	return declared
}

// clientDifference is a setting, besides the callback URLs, that a and b
// don't agree on, or is empty if they agree.
func clientDifference(a, b config.OIDCClientConfig) string {
	for _, f := range []struct {
		name string
		same bool
	}{
		{"name", a.Name == b.Name},
		{"public", a.Public == b.Public},
		{"pkce", a.PKCE == b.PKCE},
		{"skip_consent", a.SkipConsent == b.SkipConsent},
		{"groups", slices.Equal(sortedSet(a.Groups), sortedSet(b.Groups))},
		{"secret", a.SecretValue == b.SecretValue},
		{"launch_url", a.LaunchURL == b.LaunchURL},
		{"logo", sameLogo(a.Logo, b.Logo, a.LogoData, b.LogoData)},
		{"dark_logo", sameLogo(a.DarkLogo, b.DarkLogo, a.DarkLogoData, b.DarkLogoData)},
	} {
		if !f.same {
			return f.name
		}
	}
	return ""
}

func sortedSet(s config.Set) []string { return slices.Sorted(slices.Values(s)) }

// sameLogo is whether two logos would be uploaded the same.
func sameLogo(pathA, pathB string, dataA, dataB []byte) bool {
	return filepath.Base(pathA) == filepath.Base(pathB) && bytes.Equal(dataA, dataB)
}

// union is a followed by the items of b it doesn't have.
func union(a, b config.Set) config.Set {
	out := slices.Clone(a)
	for _, item := range b {
		if !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	return out
}

// planClients plans the declared clients, returning whether each that could
// be planned is public, by ID, and whether the provider could be read.
func (p *oidcPlan) planClients(
	ctx context.Context,
	provider oidcProvider,
	declared map[string]*declaredClient,
	byName map[string]*hostRun,
	owners map[string][]string,
) (map[string]bool, bool) {
	planned := map[string]bool{}
	if len(declared) == 0 {
		return planned, true
	}
	groups, err := provider.Groups(ctx)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("listing user groups: %w", err))
		return nil, false
	}

	for _, id := range slices.Sorted(maps.Keys(declared)) {
		d := declared[id]
		from, err := previousHosts(owners[id], d.hosts, byName)
		if err != nil {
			p.errs = append(p.errs, fmt.Errorf("client %s: %w", id, err))
			continue
		}
		c, err := planClient(ctx, provider, groups, id, d, from)
		switch {
		case err != nil:
			p.errs = append(p.errs, fmt.Errorf("client %s: %w", id, err))
			continue
		case c == nil:
			p.unchanged++
		default:
			p.changes = append(p.changes, c)
			if c.addSecret {
				for _, h := range d.hosts {
					h.oidcChanged = true
				}
			}
		}
		planned[id] = d.cfg.Public
	}
	return planned, true
}

// previousHosts are the hosts in the run that sensible managed a client for
// until now, given its owners, that don't declare it. They and hosts, which
// do, must be all its owners, as applying some of them would drop the
// others' callback URLs.
func previousHosts(owners []string, hosts []*hostRun, byName map[string]*hostRun) ([]*hostRun, error) {
	var from []*hostRun
	var missing []string
	for _, owner := range owners {
		switch {
		case slices.ContainsFunc(hosts, func(h *hostRun) bool { return h.name == owner }):
		case byName[owner] != nil:
			from = append(from, byName[owner])
		default:
			missing = append(missing, owner)
		}
	}
	if len(missing) == 0 {
		return from, nil
	}
	all := slices.Clone(missing)
	for _, h := range hosts {
		all = append(all, h.name)
	}
	slices.Sort(all)
	return nil, fmt.Errorf(
		"sensible manages it for %s; apply %s together, as every host that declares it must be",
		joinAnd(missing),
		joinAnd(all),
	)
}

// joinAnd lists names as "a, b and c".
func joinAnd(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// hostNames lists the hosts' names, or "none".
func hostNames(hosts []*hostRun) string {
	if len(hosts) == 0 {
		return "none"
	}
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.name
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// previousHost is the host in the run that sensible managed something h
// declares for until now, given its owner, or nil if that's h or no host.
func previousHost(owner string, h *hostRun, byName map[string]*hostRun) (*hostRun, error) {
	if owner == "" || owner == h.name {
		return nil, nil
	}
	if from := byName[owner]; from != nil {
		return from, nil
	}
	return nil, fmt.Errorf("sensible manages it for %s; apply %s and %s together to move it", owner, owner, h.name)
}

// oidcChange is a planned change to one client.
type oidcChange struct {
	provider oidcProvider
	// hosts are those that declare the client, and from those sensible
	// managed it for until now that no longer do.
	hosts  []*hostRun
	from   []*hostRun
	want   oidcClient
	secret string
	// secretID is the secret sensible registered that's kept.
	secretID string
	// logos are those to upload, and saved what's recorded for the client
	// once it's changed, besides its secret.
	logos []oidcLogo
	saved config.SavedOIDCClient
	lines []string

	create, update, setGroups, addSecret bool
	// pruneSecrets is set if the client may have secrets other than
	// sensible's.
	pruneSecrets bool
	record       bool
}

// planClient compares the client that the hosts declare with the
// provider's, returning nil if it needs no change.
func planClient(
	ctx context.Context,
	provider oidcProvider,
	groups map[string]string,
	id string,
	d *declaredClient,
	from []*hostRun,
) (*oidcChange, error) {
	cfg := d.cfg
	want := oidcClient{
		id:                 id,
		name:               cfg.Name,
		callbackURLs:       slices.Clone(cfg.CallbackURLs),
		logoutCallbackURLs: slices.Clone(cfg.LogoutCallbackURLs),
		public:             cfg.Public,
		// The provider may insist on it for public clients anyway.
		pkce:        cfg.Public || cfg.PKCE,
		skipConsent: cfg.SkipConsent,
		restricted:  len(cfg.Groups) > 0,
		launchURL:   cfg.LaunchURL,
	}
	for _, g := range cfg.Groups {
		gid, ok := groups[g]
		if !ok {
			return nil, fmt.Errorf("no user group named %q", g)
		}
		want.groups = append(want.groups, gid)
	}
	slices.Sort(want.groups)

	c := &oidcChange{provider: provider, hosts: d.hosts, from: from, want: want, secret: cfg.SecretValue}
	// It's managed if it's recorded for the hosts that declare it and no
	// others.
	managed := len(from) == 0
	var recorded config.SavedOIDCClient
	var recordedFor []*hostRun
	for _, h := range append(slices.Clone(d.hosts), from...) {
		r, ok := h.oidc.clients[id]
		if !ok {
			managed = false
			continue
		}
		if len(recordedFor) == 0 {
			recorded = r
		}
		recordedFor = append(recordedFor, h)
	}
	existing, err := provider.Client(ctx, id)
	if err != nil {
		return nil, err
	}
	c.planLogos(cfg, recorded, existing)
	if existing == nil {
		c.create, c.setGroups, c.addSecret, c.pruneSecrets, c.record = true, want.restricted, !want.public, true, true
		c.lines = []string{"+ client " + id}
		return c, nil
	}

	label := "~ client " + id + "  "
	for _, l := range c.logos {
		c.lines = append(c.lines, label+l.setting())
	}
	c.planSettings(existing, label)
	existingGroups := slices.Sorted(slices.Values(existing.groups))
	if existing.restricted != want.restricted || (want.restricted && !slices.Equal(existingGroups, want.groups)) {
		c.update = c.update || existing.restricted != want.restricted
		c.setGroups = want.restricted
		c.lines = append(c.lines, label+"groups: "+groupNames(existing, groups)+" → "+groupNames(&want, groups))
	}

	secrets, err := provider.Secrets(ctx, id)
	if err != nil {
		return nil, err
	}
	if !want.public && managed {
		i := slices.IndexFunc(
			secrets,
			func(s oidcSecret) bool {
				return s.id == recorded.SecretID && s.active && s.prefix != "" && strings.HasPrefix(c.secret, s.prefix)
			},
		)
		if i >= 0 {
			c.secretID = recorded.SecretID
		}
	}
	if !want.public && c.secretID == "" {
		c.addSecret = true
		c.lines = append(c.lines, label+"secret")
	}
	others := len(secrets)
	if c.secretID != "" {
		others--
	}
	if others > 0 {
		c.pruneSecrets = true
		c.lines = append(c.lines, "- client "+id+"  "+plural(others, "other secret"))
	}
	if !managed {
		c.record = true
		c.lines = append(c.lines, label+"hosts: "+hostNames(recordedFor)+" → "+hostNames(d.hosts))
	}
	if len(c.lines) == 0 {
		return nil, nil
	}
	c.record = c.record || c.addSecret || len(c.logos) > 0
	return c, nil
}

// planSettings notes the settings, besides groups, in which existing isn't
// the client c wants.
func (c *oidcChange) planSettings(existing *oidcClient, label string) {
	want := c.want
	fields := []struct {
		name          string
		before, after string
	}{
		{"name", existing.name, want.name},
		{"callback_urls", urlList(existing.callbackURLs), urlList(want.callbackURLs)},
		{"logout_callback_urls", urlList(existing.logoutCallbackURLs), urlList(want.logoutCallbackURLs)},
		{"public", strconv.FormatBool(existing.public), strconv.FormatBool(want.public)},
		{"pkce", strconv.FormatBool(existing.pkce), strconv.FormatBool(want.pkce)},
		{"skip_consent", strconv.FormatBool(existing.skipConsent), strconv.FormatBool(want.skipConsent)},
	}
	if want.launchURL != "" {
		fields = append(fields, struct{ name, before, after string }{"launch_url", existing.launchURL, want.launchURL})
	}
	for _, f := range fields {
		if f.before != f.after {
			c.update = true
			c.lines = append(c.lines, label+f.name+": "+f.before+" → "+f.after)
		}
	}
}

func urlList(urls []string) string { return cmp.Or(strings.Join(urls, ", "), "none") }

// oidcLogo is a client logo to upload, with the hash that's recorded for it.
type oidcLogo struct {
	dark bool
	name string
	data []byte
	hash string
}

func (l oidcLogo) setting() string {
	if l.dark {
		return "dark_logo"
	}
	return "logo"
}

// planLogos sets the logos to upload: those the client declares that aren't
// the ones sensible last uploaded, or that existing has lost. Those it
// doesn't declare are left as they are.
func (c *oidcChange) planLogos(cfg config.OIDCClientConfig, recorded config.SavedOIDCClient, existing *oidcClient) {
	c.saved = config.SavedOIDCClient{Logo: recorded.Logo, DarkLogo: recorded.DarkLogo}
	for _, l := range []struct {
		dark     bool
		path     string
		data     []byte
		recorded string
		has      bool
	}{
		{false, cfg.Logo, cfg.LogoData, recorded.Logo, existing != nil && existing.hasLogo},
		{true, cfg.DarkLogo, cfg.DarkLogoData, recorded.DarkLogo, existing != nil && existing.hasDarkLogo},
	} {
		if l.path == "" {
			continue
		}
		sum := sha256.Sum256(l.data)
		hash := hex.EncodeToString(sum[:])
		if l.has && hash == l.recorded {
			continue
		}
		c.logos = append(c.logos, oidcLogo{dark: l.dark, name: filepath.Base(l.path), data: l.data, hash: hash})
	}
}

// groupNames describes who may use the client.
func groupNames(c *oidcClient, groups map[string]string) string {
	if !c.restricted {
		return "everyone"
	}
	if len(c.groups) == 0 {
		return "no one"
	}
	names := map[string]string{}
	for name, id := range groups {
		names[id] = name
	}
	out := make([]string, len(c.groups))
	for i, id := range c.groups {
		out[i] = cmp.Or(names[id], id)
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

// apply makes the change. The secret sensible registers is recorded before
// any other is removed, so it's never lost track of.
func (c *oidcChange) apply(ctx context.Context) error {
	p, id := c.provider, c.want.id
	switch {
	case c.create:
		if err := p.Create(ctx, c.want); err != nil {
			return err
		}
	case c.update:
		if err := p.Update(ctx, c.want); err != nil {
			return err
		}
	}
	if c.setGroups {
		if err := p.SetGroups(ctx, id, c.want.groups); err != nil {
			return err
		}
	}
	if err := c.uploadLogos(ctx); err != nil {
		return err
	}
	if c.addSecret {
		if err := c.registerSecret(ctx); err != nil {
			return err
		}
	}
	if err := c.updateRecords(); err != nil {
		return err
	}
	if !c.pruneSecrets {
		return nil
	}
	secrets, err := p.Secrets(ctx, id)
	if err != nil {
		return err
	}
	for _, s := range secrets {
		if s.id == c.secretID {
			continue
		}
		if err := p.DeleteSecret(ctx, id, s.id); err != nil {
			return err
		}
	}
	return nil
}

// registerSecret adds the client's secret to the provider, unless a host
// that declares it couldn't save the secrets generated for it.
func (c *oidcChange) registerSecret(ctx context.Context) error {
	for _, h := range c.hosts {
		if h.saveFailed {
			return fmt.Errorf("%s's generated secrets weren't saved", h.name)
		}
	}
	secretID, err := c.provider.AddSecret(ctx, c.want.id, c.secret)
	c.secretID = secretID
	return err
}

// updateRecords drops the client from the hosts that no longer declare it,
// and records it for those that do if it changed.
func (c *oidcChange) updateRecords() error {
	for _, h := range c.from {
		if err := h.oidc.drop(c.want.id); err != nil {
			return err
		}
	}
	if !c.record {
		return nil
	}
	c.saved.SecretID = c.secretID
	for _, h := range c.hosts {
		if err := h.oidc.save(c.want.id, c.saved); err != nil {
			return err
		}
	}
	return nil
}

// uploadLogos uploads the logos that changed, noting their hashes to record.
func (c *oidcChange) uploadLogos(ctx context.Context) error {
	for _, l := range c.logos {
		if err := c.provider.SetLogo(ctx, c.want.id, l.dark, l.name, l.data); err != nil {
			return fmt.Errorf("%s: %w", l.setting(), err)
		}
		if l.dark {
			c.saved.DarkLogo = l.hash
		} else {
			c.saved.Logo = l.hash
		}
	}
	return nil
}

func (p *oidcPlan) lines() []string {
	var lines []string
	for _, c := range p.changes {
		lines = append(lines, c.lines...)
	}
	for _, c := range p.apiChanges {
		lines = append(lines, c.lines...)
	}
	return lines
}

func (p *oidcPlan) step() crossHostStep {
	return crossHostStep{
		name:    "OIDC changes",
		changes: len(p.lines()),
		apply: func(ctx context.Context, out *renderer) bool {
			out.section("Applying OIDC changes")
			ok := true
			for _, c := range p.changes {
				err := out.applyItem("client "+c.want.id, func() error { return c.apply(ctx) })
				ok = ok && err == nil
			}
			// After the clients, so those they're granted to exist.
			for _, c := range p.apiChanges {
				err := out.applyItem("api "+c.identifier, func() error { return c.apply(ctx) })
				ok = ok && err == nil
			}
			return ok
		},
	}
}

// findUnusedOIDCClients offers the clients sensible manages for the host
// that no host it manages them for declares. Those it manages for other
// hosts too are only offered by the first, and only if the others are in
// the run, as otherwise they may still declare them. The provider is only
// opened to remove one.
func (h *hostRun) findUnusedOIDCClients(
	ctx context.Context,
	open func() (oidcProvider, error),
	owners map[string][]string,
	byName map[string]*hostRun,
) {
	for _, id := range slices.Sorted(maps.Keys(h.oidc.clients)) {
		hosts, ok := unusedClientHosts(id, h, owners[id], byName)
		if !ok {
			continue
		}
		h.leftovers = append(
			h.leftovers,
			&leftover{
				h:     h,
				label: "OIDC client " + id,
				remove: func() error {
					p, err := open()
					if err != nil {
						return err
					}
					if err := p.Delete(ctx, id); err != nil {
						return err
					}
					for _, o := range hosts {
						if err := o.oidc.drop(id); err != nil {
							return err
						}
					}
					return nil
				},
			},
		)
	}
}

// unusedClientHosts are the hosts sensible manages the client for, which
// are h and its other owners, if none of them declares it and h is the first
// of them.
func unusedClientHosts(id string, h *hostRun, owners []string, byName map[string]*hostRun) ([]*hostRun, bool) {
	if _, ok := h.oidcClients[id]; ok {
		return nil, false
	}
	hosts := []*hostRun{h}
	for _, owner := range owners {
		if owner == h.name {
			continue
		}
		if owner < h.name {
			return nil, false
		}
		o := byName[owner]
		if o == nil {
			return nil, false
		}
		<-o.done
		if o.agent == nil || o.err != nil {
			return nil, false
		}
		if _, ok := o.oidcClients[id]; ok {
			return nil, false
		}
		hosts = append(hosts, o)
	}
	return hosts, true
}

// openOIDCOnce opens the OIDC provider the first time it's needed.
func (r *Runner) openOIDCOnce() func() (oidcProvider, error) {
	return sync.OnceValues(func() (oidcProvider, error) { return r.OIDC(r.OIDCSettings) })
}

// oidcOwners maps each OIDC client sensible manages to the hosts it's
// for, by name.
func oidcOwners(inv config.Inventory) map[string][]string {
	owners := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(inv.Hosts)) {
		for id := range inv.Hosts[name].OIDCClients {
			owners[id] = append(owners[id], name)
		}
	}
	return owners
}

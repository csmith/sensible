package run

import (
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
// what it registered, and the means to change them.
type oidcRecords struct {
	clients map[string]config.SavedOIDCClient
	save    func(id string, saved config.SavedOIDCClient) error
	drop    func(id string) error
}

// oidcPlan is the OIDC client changes for a run, with how many clients are
// already as they should be.
type oidcPlan struct {
	changes   []*oidcChange
	unchanged int
	errs      []error
}

// planOIDC works out the changes the clients the running hosts declare
// need. A client sensible manages for another host can only move to this
// one if that host is in the run and no longer declares it.
func (r *Runner) planOIDC(ctx context.Context, runs []*hostRun) oidcPlan {
	var p oidcPlan
	declared := map[string]*hostRun{}
	conflicted := map[string]bool{}
	byName := map[string]*hostRun{}
	for _, h := range runs {
		byName[h.name] = h
		if h.agent == nil || h.err != nil {
			continue
		}
		for _, id := range slices.Sorted(maps.Keys(h.oidcClients)) {
			if other, ok := declared[id]; ok {
				p.errs = append(p.errs, fmt.Errorf("client %s: both %s and %s declare it", id, other.name, h.name))
				conflicted[id] = true
				continue
			}
			declared[id] = h
		}
	}
	if len(declared) == 0 {
		return p
	}
	provider, err := r.OIDC(r.OIDCSettings)
	if err != nil {
		p.errs = append(p.errs, err)
		return p
	}
	groups, err := provider.Groups(ctx)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("listing user groups: %w", err))
		return p
	}

	for _, id := range slices.Sorted(maps.Keys(declared)) {
		if conflicted[id] {
			continue
		}
		h := declared[id]
		var from *hostRun
		if owner := r.OIDCOwners[id]; owner != "" && owner != h.name {
			if from = byName[owner]; from == nil {
				p.errs = append(
					p.errs,
					fmt.Errorf("client %s: sensible manages it for %s; apply %s and %s together to move it", id, owner, owner, h.name),
				)
				continue
			}
		}
		c, err := planClient(ctx, provider, groups, id, h, from)
		switch {
		case err != nil:
			p.errs = append(p.errs, fmt.Errorf("client %s: %w", id, err))
		case c == nil:
			p.unchanged++
		default:
			p.changes = append(p.changes, c)
			if c.addSecret {
				h.oidcChanged = true
			}
		}
	}
	return p
}

// oidcChange is a planned change to one client.
type oidcChange struct {
	provider oidcProvider
	host     *hostRun
	// from is the host sensible managed the client for until now, if it's
	// another.
	from   *hostRun
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

// planClient compares the client that h declares with the provider's,
// returning nil if it needs no change.
func planClient(
	ctx context.Context,
	provider oidcProvider,
	groups map[string]string,
	id string,
	h, from *hostRun,
) (*oidcChange, error) {
	cfg := h.oidcClients[id]
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

	c := &oidcChange{provider: provider, host: h, from: from, want: want, secret: cfg.SecretValue}
	recorded, managed := h.oidc.clients[id]
	if from != nil {
		managed = false
		recorded = from.oidc.clients[id]
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
		c.lines = append(
			c.lines,
			label+"groups: "+groupNames(existing, groups)+" → "+groupNames(&want, groups),
		)
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
		before := "none"
		if from != nil {
			before = from.name
		}
		c.lines = append(c.lines, label+"host: "+before+" → "+h.name)
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
		{"callback_urls", strings.Join(existing.callbackURLs, ", "), strings.Join(want.callbackURLs, ", ")},
		{
			"logout_callback_urls",
			strings.Join(existing.logoutCallbackURLs, ", "),
			strings.Join(want.logoutCallbackURLs, ", "),
		},
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
		if c.host.saveFailed {
			return fmt.Errorf("%s's generated secrets weren't saved", c.host.name)
		}
		secretID, err := p.AddSecret(ctx, id, c.secret)
		if err != nil {
			return err
		}
		c.secretID = secretID
	}
	if c.from != nil {
		if err := c.from.oidc.drop(id); err != nil {
			return err
		}
	}
	if c.record {
		c.saved.SecretID = c.secretID
		if err := c.host.oidc.save(id, c.saved); err != nil {
			return err
		}
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

func (p oidcPlan) lines() []string {
	var lines []string
	for _, c := range p.changes {
		lines = append(lines, c.lines...)
	}
	return lines
}

func (p oidcPlan) step() crossHostStep {
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
			return ok
		},
	}
}

// findUnusedOIDCClients offers the clients sensible manages for the host
// that it no longer declares. The provider is only opened to remove one.
func (h *hostRun) findUnusedOIDCClients(ctx context.Context, open func() (oidcProvider, error)) {
	for _, id := range slices.Sorted(maps.Keys(h.oidc.clients)) {
		if _, ok := h.oidcClients[id]; ok {
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
					return h.oidc.drop(id)
				},
			},
		)
	}
}

// openOIDCOnce opens the OIDC provider the first time it's needed.
func (r *Runner) openOIDCOnce() func() (oidcProvider, error) {
	return sync.OnceValues(func() (oidcProvider, error) { return r.OIDC(r.OIDCSettings) })
}

func oidcOwners(inv config.Inventory) map[string]string {
	owners := map[string]string{}
	for name, e := range inv.Hosts {
		for id := range e.OIDCClients {
			owners[id] = name
		}
	}
	return owners
}

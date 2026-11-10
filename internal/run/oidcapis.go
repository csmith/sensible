package run

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"chameth.com/sensible/internal/config"
)

// oidcAPI is an API's settings that sensible manages, with the provider's ID
// for it.
type oidcAPI struct {
	id, name string
	// permissions are in key order.
	permissions []oidcPermission
}

// oidcPermission is one of an API's permissions. Its id is the provider's,
// and empty in one sensible wants.
type oidcPermission struct {
	id, key, name, description string
}

// oidcGrant is what a client may do with an API: as itself, with client
// credentials, and on behalf of its users, each with permissions.
type oidcGrant struct {
	client, user                       bool
	clientPermissions, userPermissions []string
}

func (g oidcGrant) equal(o oidcGrant) bool {
	return g.client == o.client && g.user == o.user &&
		slices.Equal(g.clientPermissions, o.clientPermissions) &&
		slices.Equal(g.userPermissions, o.userPermissions)
}

// description describes the grant, whose permissions are keys.
func (g oidcGrant) description() string {
	var parts []string
	if g.client {
		parts = append(parts, cmp.Or(strings.Join(g.clientPermissions, ", "), "no permissions"))
	}
	if g.user {
		parts = append(parts, "for users: "+cmp.Or(strings.Join(g.userPermissions, ", "), "no permissions"))
	}
	return cmp.Or(strings.Join(parts, "; "), "none")
}

// planAPIs plans the declared APIs. A client may be granted access if it's
// one of planned, which are about to be made if they're missing, or if the
// provider already has it. planned notes whether each is public.
func (p *oidcPlan) planAPIs(
	ctx context.Context,
	provider oidcProvider,
	declared map[string]*hostRun,
	byName map[string]*hostRun,
	owners map[string]string,
	planned map[string]bool,
) {
	existing, err := provider.APIs(ctx)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("listing APIs: %w", err))
		return
	}
	for _, identifier := range slices.Sorted(maps.Keys(declared)) {
		h := declared[identifier]
		from, err := previousHost(owners[identifier], h, byName)
		if err != nil {
			p.errs = append(p.errs, fmt.Errorf("api %s: %w", identifier, err))
			continue
		}
		c, err := planAPI(ctx, provider, identifier, h, from, existing[identifier], planned)
		switch {
		case err != nil:
			p.errs = append(p.errs, fmt.Errorf("api %s: %w", identifier, err))
		case c == nil:
			p.unchanged++
		default:
			p.apiChanges = append(p.apiChanges, c)
		}
	}
}

// oidcAPIChange is a planned change to one API.
type oidcAPIChange struct {
	provider oidcProvider
	host     *hostRun
	// from is the host sensible managed the API for until now, if it's
	// another.
	from       *hostRun
	identifier string
	want       oidcAPI
	// grants are what each client should have, with permission keys in
	// order, by client ID. Those in grant are granted it, and those in
	// revoke lose access.
	grants        map[string]oidcGrant
	grant, revoke []string
	// permissionIDs are the existing permissions' IDs, by key.
	permissionIDs map[string]string
	lines         []string

	create, rename, setPermissions, record bool
}

// planAPI compares the API that h declares with the provider's, existing,
// returning nil if it needs no change.
func planAPI(
	ctx context.Context,
	provider oidcProvider,
	identifier string,
	h, from *hostRun,
	existing *oidcAPI,
	planned map[string]bool,
) (*oidcAPIChange, error) {
	cfg := h.oidcAPIs[identifier]
	c := &oidcAPIChange{
		provider:   provider,
		host:       h,
		from:       from,
		identifier: identifier,
		want:       oidcAPI{name: cfg.Name},
		grants:     map[string]oidcGrant{},
	}
	for _, key := range slices.Sorted(maps.Keys(cfg.Permissions)) {
		perm := cfg.Permissions[key]
		c.want.permissions = append(
			c.want.permissions,
			oidcPermission{key: key, name: perm.Name, description: perm.Description},
		)
	}
	for _, client := range slices.Sorted(maps.Keys(cfg.Clients)) {
		c.grants[client] = oidcGrant{client: true, clientPermissions: sortedSet(cfg.Clients[client])}
	}
	for _, client := range slices.Sorted(maps.Keys(cfg.Users)) {
		g := c.grants[client]
		g.user, g.userPermissions = true, sortedSet(cfg.Users[client])
		c.grants[client] = g
	}
	for _, client := range slices.Sorted(maps.Keys(c.grants)) {
		public, ok := planned[client]
		if !ok {
			found, err := provider.Client(ctx, client)
			if err != nil {
				return nil, err
			}
			if found == nil {
				return nil, fmt.Errorf("no OIDC client %s to grant access to", client)
			}
			public = found.public
		}
		if public && c.grants[client].client {
			return nil, fmt.Errorf("client %s is public, so it can't use client credentials", client)
		}
	}

	if existing == nil {
		c.create, c.setPermissions, c.record = true, len(c.want.permissions) > 0, true
		c.grant = slices.Sorted(maps.Keys(c.grants))
		c.lines = []string{"+ api " + identifier}
		return c, nil
	}

	c.want.id = existing.id
	if existing.name != c.want.name {
		c.rename = true
		c.lines = append(c.lines, "~ api "+identifier+"  name: "+existing.name+" → "+c.want.name)
	}
	c.planPermissions(existing)
	grants, err := provider.Grants(ctx, existing.id)
	if err != nil {
		return nil, err
	}
	c.planGrants(existing, grants)
	if from != nil || !slices.Contains(h.oidc.apis, identifier) {
		c.record = true
		before := "none"
		if from != nil {
			before = from.name
		}
		c.lines = append(c.lines, "~ api "+identifier+"  host: "+before+" → "+h.name)
	}
	if len(c.lines) == 0 {
		return nil, nil
	}
	return c, nil
}

// planPermissions notes the permissions that existing is missing, has but
// shouldn't, or has with another name or description. Any of them means
// they're all replaced.
func (c *oidcAPIChange) planPermissions(existing *oidcAPI) {
	have := map[string]oidcPermission{}
	c.permissionIDs = map[string]string{}
	for _, perm := range existing.permissions {
		have[perm.key] = perm
		c.permissionIDs[perm.key] = perm.id
	}
	label := " api " + c.identifier + "  permission "
	wanted := map[string]bool{}
	for _, want := range c.want.permissions {
		wanted[want.key] = true
		perm, ok := have[want.key]
		switch {
		case !ok:
			c.lines = append(c.lines, "+"+label+want.key)
		case perm.name != want.name || perm.description != want.description:
			c.lines = append(c.lines, "~"+label+want.key)
		default:
			continue
		}
		c.setPermissions = true
	}
	for _, perm := range existing.permissions {
		if !wanted[perm.key] {
			c.setPermissions = true
			c.lines = append(c.lines, "-"+label+perm.key)
		}
	}
}

// planGrants notes the clients whose access to the API isn't exactly
// what's declared.
func (c *oidcAPIChange) planGrants(existing *oidcAPI, grants map[string]oidcGrant) {
	keys := map[string]string{}
	for _, perm := range existing.permissions {
		keys[perm.id] = perm.key
	}
	toKeys := func(ids []string) []string {
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = cmp.Or(keys[id], id)
		}
		slices.Sort(out)
		return out
	}
	for _, client := range slices.Sorted(maps.Keys(c.grants)) {
		want := c.grants[client]
		label := " api " + c.identifier + "  client " + client
		g, ok := grants[client]
		if !ok {
			c.grant = append(c.grant, client)
			if want.user || len(want.clientPermissions) > 0 {
				label += ": " + want.description()
			}
			c.lines = append(c.lines, "+"+label)
			continue
		}
		g.clientPermissions, g.userPermissions = toKeys(g.clientPermissions), toKeys(g.userPermissions)
		if g.equal(want) {
			continue
		}
		c.grant = append(c.grant, client)
		c.lines = append(c.lines, "~"+label+": "+g.description()+" → "+want.description())
	}
	for _, client := range slices.Sorted(maps.Keys(grants)) {
		if _, ok := c.grants[client]; !ok {
			c.revoke = append(c.revoke, client)
			c.lines = append(c.lines, "- api "+c.identifier+"  client "+client)
		}
	}
}

func (c *oidcAPIChange) apply(ctx context.Context) error {
	p, id := c.provider, c.want.id
	switch {
	case c.create:
		var err error
		if id, err = p.CreateAPI(ctx, c.identifier, c.want.name); err != nil {
			return err
		}
	case c.rename:
		if err := p.RenameAPI(ctx, id, c.want.name); err != nil {
			return err
		}
	}
	permissionIDs := c.permissionIDs
	if c.setPermissions {
		var err error
		if permissionIDs, err = p.SetPermissions(ctx, id, c.want.permissions); err != nil {
			return fmt.Errorf("permissions: %w", err)
		}
	}
	for _, client := range c.grant {
		g := c.grants[client]
		var err error
		if g.clientPermissions, err = permissionIDList(permissionIDs, g.clientPermissions); err == nil {
			g.userPermissions, err = permissionIDList(permissionIDs, g.userPermissions)
		}
		if err == nil {
			err = p.Grant(ctx, id, client, g)
		}
		if err != nil {
			return fmt.Errorf("client %s: %w", client, err)
		}
	}
	for _, client := range c.revoke {
		if err := p.Revoke(ctx, id, client); err != nil {
			return fmt.Errorf("client %s: %w", client, err)
		}
	}
	if c.from != nil {
		if err := c.from.oidc.dropAPI(c.identifier); err != nil {
			return err
		}
	}
	if c.record {
		return c.host.oidc.saveAPI(c.identifier)
	}
	return nil
}

// permissionIDList is the IDs of the permissions with the keys.
func permissionIDList(ids map[string]string, keys []string) ([]string, error) {
	var out []string
	for _, key := range keys {
		id, ok := ids[key]
		if !ok {
			return nil, fmt.Errorf("the provider has no permission %s", key)
		}
		out = append(out, id)
	}
	return out, nil
}

// findUnusedOIDCAPIs offers the APIs sensible manages for the host that it
// no longer declares. The provider is only opened to remove one.
func (h *hostRun) findUnusedOIDCAPIs(ctx context.Context, open func() (oidcProvider, error)) {
	for _, identifier := range slices.Sorted(slices.Values(h.oidc.apis)) {
		if _, ok := h.oidcAPIs[identifier]; ok {
			continue
		}
		h.leftovers = append(
			h.leftovers,
			&leftover{
				h:     h,
				label: "OIDC API " + identifier,
				remove: func() error {
					p, err := open()
					if err != nil {
						return err
					}
					apis, err := p.APIs(ctx)
					if err != nil {
						return err
					}
					if api := apis[identifier]; api != nil {
						if err := p.DeleteAPI(ctx, api.id); err != nil {
							return err
						}
					}
					return h.oidc.dropAPI(identifier)
				},
			},
		)
	}
}

func oidcAPIOwners(inv config.Inventory) map[string]string {
	owners := map[string]string{}
	for name, e := range inv.Hosts {
		for _, identifier := range e.OIDCAPIs {
			owners[identifier] = name
		}
	}
	return owners
}

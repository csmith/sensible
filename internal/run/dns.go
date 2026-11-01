package run

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	api "github.com/mydnshost/mydnshost-go-api"
)

type dnsClient interface {
	Domains(ctx context.Context) (map[string]api.AccessLevel, error)
	Records(ctx context.Context, domain string) (*api.RecordsResponse, error)
	ModifyRecords(ctx context.Context, domain string, ops ...api.RecordOperation) (*api.ModifyRecordsResponse, error)
}

func newDNSClient(user, key string) dnsClient {
	return &api.Client{Authenticator: &api.ApiKeyAuthenticator{User: user, Key: key}}
}

// dnsPlan is the DNS changes for a run, with how many records are already
// as they should be.
type dnsPlan struct {
	changes   []*dnsChange
	unchanged int
	warnings  []string
	errs      []error
}

// planDNS works out the A and AAAA records for every host with a DNS name
// whose facts came back. Addresses from facts are only used if they're
// valid, as a compromised host could report anything.
func (r *Runner) planDNS(ctx context.Context, runs []*hostRun) dnsPlan {
	var p dnsPlan
	var z *dnsZones
	for _, h := range runs {
		if h.agent == nil || h.dnsName == "" {
			continue
		}
		if z == nil {
			client, err := r.dnsClient()
			if err != nil {
				p.errs = append(p.errs, err)
				return p
			}
			z = &dnsZones{client: client, records: map[string][]api.ExistingRecord{}}
		}

		for _, want := range []struct{ rtype, fact string }{
			{"A", h.facts.DefaultIPv4},
			{"AAAA", h.facts.DefaultIPv6},
		} {
			addr, ok := dnsAddress(want.rtype, want.fact)
			if !ok {
				if want.fact != "" {
					p.warnings = append(
						p.warnings,
						fmt.Sprintf("ignoring invalid %s address %q from %s", want.rtype, want.fact, h.name),
					)
				}
				continue
			}
			change, err := z.plan(ctx, h.dnsName, want.rtype, []string{addr})
			if err != nil {
				p.errs = append(p.errs, fmt.Errorf("%s %s: %w", want.rtype, h.dnsName, err))
				continue
			}
			if change != nil {
				p.changes = append(p.changes, change)
			} else {
				p.unchanged++
			}
		}
	}
	return p
}

func (r *Runner) dnsClient() (dnsClient, error) {
	user, err := r.DNSCredentials.AuthUser.Reveal()
	if err != nil {
		return nil, fmt.Errorf("sensible.yml: dns.auth_user: %w", err)
	}
	key, err := r.DNSCredentials.AuthKey.Reveal()
	if err != nil {
		return nil, fmt.Errorf("sensible.yml: dns.auth_key: %w", err)
	}
	return r.DNS(user, key), nil
}

func dnsAddress(rtype, fact string) (string, bool) {
	addr, err := netip.ParseAddr(fact)
	if err != nil || addr.Zone() != "" || addr.Is4In6() || !addr.IsGlobalUnicast() {
		return "", false
	}
	if addr.Is4() != (rtype == "A") {
		return "", false
	}
	return addr.String(), true
}

// dnsZones caches one account's domains and their records.
type dnsZones struct {
	client  dnsClient
	domains []string
	records map[string][]api.ExistingRecord
}

// dnsChange is a planned change to one name and type.
type dnsChange struct {
	client dnsClient
	domain string
	fqdn   string
	rtype  string
	before []string
	after  []string
	ops    []api.RecordOperation
}

// plan makes the records for fqdn and rtype exactly values, leaving TTLs
// alone.
func (z *dnsZones) plan(ctx context.Context, fqdn, rtype string, values []string) (*dnsChange, error) {
	if z.domains == nil {
		domains, err := z.client.Domains(ctx)
		if err != nil {
			return nil, err
		}
		z.domains = make([]string, 0, len(domains))
		for d := range domains {
			z.domains = append(z.domains, d)
		}
	}
	domain := findDomain(z.domains, fqdn)
	if domain == "" {
		return nil, fmt.Errorf("no domain on this account contains %s", fqdn)
	}
	name, err := relativeName(fqdn, domain)
	if err != nil {
		return nil, err
	}

	records, ok := z.records[domain]
	if !ok {
		res, err := z.client.Records(ctx, domain)
		if err != nil {
			return nil, err
		}
		records = res.Records
		z.records[domain] = records
	}
	var existing []api.ExistingRecord
	for _, rec := range records {
		if n, err := relativeName(rec.Name, domain); err == nil && n == name && strings.EqualFold(rec.Type, rtype) {
			existing = append(existing, rec)
		}
	}

	p := planRecords(rtype, existing, values, nil, true)
	if p.empty() {
		return nil, nil
	}
	return &dnsChange{
		client: z.client,
		domain: domain,
		fqdn:   normaliseDomain(fqdn),
		rtype:  rtype,
		before: contents(existing),
		after:  p.predict(existing),
		ops:    p.operations(name, rtype, nil),
	}, nil
}

func (c *dnsChange) String() string {
	before, after := strings.Join(c.before, ", "), strings.Join(c.after, ", ")
	switch {
	case before == "":
		return fmt.Sprintf("+ %s %s  %s", c.rtype, c.fqdn, after)
	case after == "":
		return fmt.Sprintf("- %s %s  %s", c.rtype, c.fqdn, before)
	default:
		return fmt.Sprintf("~ %s %s  %s → %s", c.rtype, c.fqdn, before, after)
	}
}

func (c *dnsChange) apply(ctx context.Context) error {
	_, err := c.client.ModifyRecords(ctx, c.domain, c.ops...)
	return err
}

// recordPlan is what has to change for one name and type: values to add,
// existing records whose TTL needs changing, and records to remove.
type recordPlan struct {
	add    []string
	update []api.ExistingRecord
	remove []api.ExistingRecord
}

// planRecords compares existing records with the wanted values. A nil ttl
// leaves existing TTLs alone and gives new records the domain's default.
// With exclusive, every record not matching a value is removed, as are
// duplicates.
func planRecords(rtype string, existing []api.ExistingRecord, values []string, ttl *int, exclusive bool) recordPlan {
	wanted := map[string]bool{}
	var desired []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if k := normaliseContent(rtype, v); !wanted[k] {
			wanted[k] = true
			desired = append(desired, v)
		}
	}

	byKey := map[string][]api.ExistingRecord{}
	var order []string
	for _, rec := range existing {
		k := normaliseContent(rtype, rec.Content)
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], rec)
	}

	var p recordPlan
	for _, v := range desired {
		recs := byKey[normaliseContent(rtype, v)]
		if len(recs) == 0 {
			p.add = append(p.add, v)
			continue
		}
		if ttl != nil && recs[0].TTL != *ttl {
			p.update = append(p.update, recs[0])
		}
		if exclusive {
			p.remove = append(p.remove, recs[1:]...)
		}
	}
	if exclusive {
		for _, k := range order {
			if !wanted[k] {
				p.remove = append(p.remove, byKey[k]...)
			}
		}
	}
	return p
}

func (p recordPlan) empty() bool {
	return len(p.add) == 0 && len(p.update) == 0 && len(p.remove) == 0
}

func (p recordPlan) operations(name, rtype string, ttl *int) []api.RecordOperation {
	ops := make([]api.RecordOperation, 0, len(p.remove)+len(p.update)+len(p.add))
	for _, rec := range p.remove {
		ops = append(ops, api.DeleteRecord(rec.Id))
	}
	for _, rec := range p.update {
		ops = append(ops, api.ModifyRecord(rec.Id, api.Record{TTL: *ttl}))
	}
	for _, v := range p.add {
		rec := api.Record{Name: name, Type: rtype, Content: v}
		if ttl != nil {
			rec.TTL = *ttl
		}
		ops = append(ops, api.CreateRecord(rec))
	}
	return ops
}

func (p recordPlan) predict(existing []api.ExistingRecord) []string {
	removed := map[int]bool{}
	for _, rec := range p.remove {
		removed[rec.Id] = true
	}
	var result []string
	for _, rec := range existing {
		if !removed[rec.Id] {
			result = append(result, rec.Content)
		}
	}
	return append(result, p.add...)
}

func contents(records []api.ExistingRecord) []string {
	out := make([]string, len(records))
	for i, rec := range records {
		out[i] = rec.Content
	}
	return out
}

func normaliseContent(rtype, content string) string {
	content = strings.TrimSpace(content)
	if rtype == "A" || rtype == "AAAA" {
		if addr, err := netip.ParseAddr(content); err == nil {
			return addr.String()
		}
	}
	return content
}

func normaliseDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// findDomain returns the most specific domain containing fqdn, matching on
// label boundaries, or "" if none does.
func findDomain(domains []string, fqdn string) string {
	name := "." + normaliseDomain(fqdn)
	best := ""
	for _, d := range domains {
		d = normaliseDomain(d)
		if strings.HasSuffix(name, "."+d) && len(d) > len(best) {
			best = d
		}
	}
	return best
}

// relativeName returns name relative to domain, "" for the apex. Names
// ending in a dot are fully qualified and must be inside the domain.
func relativeName(name, domain string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "@" || name == "." {
		return "", nil
	}
	qualified := strings.HasSuffix(name, ".")
	name = strings.TrimSuffix(name, ".")
	switch {
	case name == domain:
		return "", nil
	case strings.HasSuffix(name, "."+domain):
		return strings.TrimSuffix(name, "."+domain), nil
	case qualified:
		return "", fmt.Errorf("%s. isn't inside domain %s", name, domain)
	default:
		return name, nil
	}
}

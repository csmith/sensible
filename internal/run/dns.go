package run

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"chameth.com/sensible/internal/config"
)

// dnsProvider is an account with a DNS provider.
type dnsProvider interface {
	// Zones maps each zone on the account to whether the account can change
	// its records.
	Zones(ctx context.Context) (map[string]bool, error)
	Records(ctx context.Context, zone string) ([]dnsRecord, error)
	// Apply makes the changes to a zone's records, removals first so a CNAME
	// can replace other records.
	Apply(ctx context.Context, zone string, changes dnsRecordChanges) error
}

// dnsRecord is a record in a zone. Its name is relative to the zone, "" for
// the apex, though providers may also give "@" or a fully qualified name
// ending in a dot. Its id is whatever the provider identifies it by.
type dnsRecord struct {
	id      string
	name    string
	rtype   string
	content string
	ttl     int
}

// dnsRecordChanges are changes to a zone's records. Updates are existing
// records with a new TTL. Adds have no id, and a zero TTL gives them the
// zone's default.
type dnsRecordChanges struct {
	remove []dnsRecord
	update []dnsRecord
	add    []dnsRecord
}

func newDNSProvider(s config.DNSSettings) (dnsProvider, error) {
	switch s.Provider {
	case "mydnshost":
		return newMyDNSHost(s.MyDNSHost)
	case "":
		return nil, errors.New("sensible.yml: dns.provider isn't set")
	default:
		return nil, fmt.Errorf("sensible.yml: dns.provider: unknown provider %q", s.Provider)
	}
}

// dnsPlan is the DNS changes for a run, with how many sets of records are
// already as they should be.
type dnsPlan struct {
	changes   []*dnsChange
	unchanged int
	warnings  []string
	errs      []error
}

// managedName is a name whose records of the given types sensible sets. A type
// with no values has its records removed.
type managedName struct {
	fqdn  string
	types map[string][]string
	// vhost names are left alone, with a warning, if the account can't
	// change their domain.
	vhost bool
}

// vhostTypes are the types a vhost's records replace, besides those the
// records have.
var vhostTypes = []string{"A", "AAAA", "CNAME"}

// managedNames are the names to manage for the hosts whose facts came back:
// each host's own name with its A and AAAA records, and the vhosts it
// serves, with the records for every host serving them. Addresses from facts
// are only used if they're valid, as a compromised host could report
// anything.
func (r *Runner) managedNames(runs []*hostRun) ([]managedName, []string) {
	var names []managedName
	var warnings []string
	running := map[string]bool{}
	for _, h := range runs {
		if h.agent == nil {
			continue
		}
		running[h.name] = true
		if h.dnsName == "" {
			continue
		}
		types := map[string][]string{}
		for _, want := range []struct{ rtype, fact string }{
			{"A", h.facts.DefaultIPv4},
			{"AAAA", h.facts.DefaultIPv6},
		} {
			addr, ok := dnsAddress(want.rtype, want.fact)
			if ok {
				types[want.rtype] = []string{addr}
			} else if want.fact != "" {
				warnings = append(
					warnings,
					fmt.Sprintf("ignoring invalid %s address %q from %s", want.rtype, want.fact, h.name),
				)
			}
		}
		if len(types) > 0 {
			names = append(names, managedName{fqdn: h.dnsName, types: types})
		}
	}

	vhosts, vhostWarnings := r.vhostNames(running)
	return append(names, vhosts...), append(warnings, vhostWarnings...)
}

// vhostNames are the vhosts the running hosts serve, each with the records
// for every host serving it.
func (r *Runner) vhostNames(running map[string]bool) ([]managedName, []string) {
	if len(r.DNSSettings.Vhosts) == 0 {
		return nil, nil
	}
	var names []managedName
	var warnings []string
	unnamed := map[string]bool{}
	for _, vhost := range slices.Sorted(maps.Keys(r.Vhosts)) {
		hosts := r.Vhosts[vhost]
		if !slices.ContainsFunc(hosts, func(h string) bool { return running[h] }) {
			continue
		}
		types := map[string][]string{}
		for _, t := range vhostTypes {
			types[t] = nil
		}
		wanted := false
		for _, h := range hosts {
			target := r.DNSNames[h]
			if target == "" {
				if !unnamed[h] {
					unnamed[h] = true
					warnings = append(warnings, h+" serves vhosts but has no dns_name")
				}
				continue
			}
			for _, rec := range r.DNSSettings.Vhosts {
				types[rec.Type] = append(types[rec.Type], strings.ReplaceAll(rec.Content, "{host}", target))
				wanted = true
			}
		}
		if wanted {
			names = append(names, managedName{fqdn: vhost, types: types, vhost: true})
		}
	}
	return names, warnings
}

// planDNS works out the changes the names need.
func (r *Runner) planDNS(ctx context.Context, names []managedName, warnings []string) dnsPlan {
	p := dnsPlan{warnings: warnings}
	if len(names) == 0 {
		return p
	}
	provider, err := r.DNS(r.DNSSettings)
	if err != nil {
		p.errs = append(p.errs, err)
		return p
	}
	z := &dnsZones{provider: provider, records: map[string][]dnsRecord{}}
	z.planNames(ctx, names, &p)
	return p
}

func (z *dnsZones) planNames(ctx context.Context, names []managedName, p *dnsPlan) {
	for _, n := range names {
		change, unchanged, err := z.plan(ctx, n.fqdn, n.types)
		p.unchanged += unchanged
		switch {
		case (errors.Is(err, errNoDomain) || errors.Is(err, errReadOnly)) && n.vhost:
			p.warnings = append(p.warnings, fmt.Sprintf("leaving vhost %s alone: %v", n.fqdn, err))
		case err != nil:
			p.errs = append(p.errs, fmt.Errorf("%s: %w", n.fqdn, err))
		case change != nil:
			p.changes = append(p.changes, change)
		default:
		}
	}
}

func (p dnsPlan) step() crossHostStep {
	changes := 0
	for _, c := range p.changes {
		changes += len(c.diffs)
	}
	return crossHostStep{
		name:    "DNS changes",
		changes: changes,
		apply: func(ctx context.Context, out *renderer) bool {
			out.section("Applying DNS changes")
			ok := true
			for _, c := range p.changes {
				err := out.dnsApply(c, func() error { return c.apply(ctx) })
				ok = ok && err == nil
			}
			return ok
		},
	}
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

// dnsZones caches an account's zones, with whether it can change each, and
// their records.
type dnsZones struct {
	provider dnsProvider
	writable map[string]bool
	records  map[string][]dnsRecord
}

var (
	errNoDomain = errors.New("no domain on this account contains it")
	errReadOnly = errors.New("this account can't change its domain")
)

// dnsChange is a planned change to one name's records.
type dnsChange struct {
	provider dnsProvider
	zone     string
	fqdn     string
	diffs    []dnsDiff
	records  dnsRecordChanges
}

// dnsDiff is a change to the records of one type.
type dnsDiff struct {
	rtype  string
	before []string
	after  []string
}

// plan makes fqdn's records of each type in types exactly its values,
// leaving TTLs alone. It also returns how many types with values need no
// change.
func (z *dnsZones) plan(ctx context.Context, fqdn string, types map[string][]string) (*dnsChange, int, error) {
	if z.writable == nil {
		zones, err := z.provider.Zones(ctx)
		if err != nil {
			return nil, 0, err
		}
		z.writable = map[string]bool{}
		for zone, writable := range zones {
			z.writable[normaliseDomain(zone)] = writable
		}
	}
	// The most specific zone is the one the name is served from, even if the
	// account can't change it.
	zone := findDomain(slices.Collect(maps.Keys(z.writable)), fqdn)
	if zone == "" {
		return nil, 0, errNoDomain
	}
	if !z.writable[zone] {
		return nil, 0, fmt.Errorf("%w %s", errReadOnly, zone)
	}
	name, err := relativeName(fqdn, zone)
	if err != nil {
		return nil, 0, err
	}

	records, ok := z.records[zone]
	if !ok {
		records, err = z.provider.Records(ctx, zone)
		if err != nil {
			return nil, 0, err
		}
		z.records[zone] = records
	}

	c := &dnsChange{provider: z.provider, zone: zone, fqdn: normaliseDomain(fqdn)}
	unchanged := 0
	for _, rtype := range slices.Sorted(maps.Keys(types)) {
		var existing []dnsRecord
		for _, rec := range records {
			if n, err := relativeName(rec.name, zone); err == nil && n == name && strings.EqualFold(rec.rtype, rtype) {
				existing = append(existing, rec)
			}
		}
		p := planRecords(rtype, existing, types[rtype], nil, true)
		if p.empty() {
			if len(types[rtype]) > 0 {
				unchanged++
			}
			continue
		}
		c.diffs = append(c.diffs, dnsDiff{rtype: rtype, before: contents(existing), after: p.predict(existing)})
		changes := p.changes(name, rtype, nil)
		c.records.remove = append(c.records.remove, changes.remove...)
		c.records.update = append(c.records.update, changes.update...)
		c.records.add = append(c.records.add, changes.add...)
	}
	if len(c.diffs) == 0 {
		return nil, unchanged, nil
	}
	return c, unchanged, nil
}

func (c *dnsChange) lines() []string {
	lines := make([]string, len(c.diffs))
	for i, d := range c.diffs {
		before, after := strings.Join(d.before, ", "), strings.Join(d.after, ", ")
		switch {
		case before == "":
			lines[i] = fmt.Sprintf("+ %s %s  %s", d.rtype, c.fqdn, after)
		case after == "":
			lines[i] = fmt.Sprintf("- %s %s  %s", d.rtype, c.fqdn, before)
		default:
			lines[i] = fmt.Sprintf("~ %s %s  %s → %s", d.rtype, c.fqdn, before, after)
		}
	}
	return lines
}

// types names the record types the change touches, e.g. "A, AAAA".
func (c *dnsChange) types() string {
	types := make([]string, len(c.diffs))
	for i, d := range c.diffs {
		types[i] = d.rtype
	}
	return strings.Join(types, ", ")
}

func (c *dnsChange) apply(ctx context.Context) error {
	return c.provider.Apply(ctx, c.zone, c.records)
}

// recordPlan is what has to change for one name and type: values to add,
// existing records whose TTL needs changing, and records to remove.
type recordPlan struct {
	add    []string
	update []dnsRecord
	remove []dnsRecord
}

// planRecords compares existing records with the wanted values. A nil ttl
// leaves existing TTLs alone and gives new records the domain's default.
// With exclusive, every record not matching a value is removed, as are
// duplicates.
func planRecords(rtype string, existing []dnsRecord, values []string, ttl *int, exclusive bool) recordPlan {
	wanted := map[string]bool{}
	var desired []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if k := normaliseContent(rtype, v); !wanted[k] {
			wanted[k] = true
			desired = append(desired, v)
		}
	}

	byKey := map[string][]dnsRecord{}
	var order []string
	for _, rec := range existing {
		k := normaliseContent(rtype, rec.content)
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
		if ttl != nil && recs[0].ttl != *ttl {
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

func (p recordPlan) changes(name, rtype string, ttl *int) dnsRecordChanges {
	c := dnsRecordChanges{remove: p.remove}
	for _, rec := range p.update {
		rec.ttl = *ttl
		c.update = append(c.update, rec)
	}
	for _, v := range p.add {
		rec := dnsRecord{name: name, rtype: rtype, content: v}
		if ttl != nil {
			rec.ttl = *ttl
		}
		c.add = append(c.add, rec)
	}
	return c
}

func (p recordPlan) predict(existing []dnsRecord) []string {
	removed := map[string]bool{}
	for _, rec := range p.remove {
		removed[rec.id] = true
	}
	var result []string
	for _, rec := range existing {
		if !removed[rec.id] {
			result = append(result, rec.content)
		}
	}
	return append(result, p.add...)
}

func contents(records []dnsRecord) []string {
	out := make([]string, len(records))
	for i, rec := range records {
		out[i] = rec.content
	}
	return out
}

func normaliseContent(rtype, content string) string {
	content = strings.TrimSpace(content)
	switch strings.ToUpper(rtype) {
	case "A", "AAAA":
		if addr, err := netip.ParseAddr(content); err == nil {
			return addr.String()
		}
	case "CNAME", "RRCLONE":
		return strings.TrimSuffix(strings.ToLower(strings.Join(strings.Fields(content), " ")), ".")
	default:
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

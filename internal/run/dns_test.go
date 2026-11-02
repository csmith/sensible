package run

import (
	"context"
	"encoding/json"
	"testing"

	"chameth.com/sensible/internal/config"

	api "github.com/mydnshost/mydnshost-go-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type modification struct {
	domain string
	ops    []map[string]any
}

type fakeDNS struct {
	domains  []string
	records  []api.ExistingRecord
	modified []modification
}

func (f *fakeDNS) Domains(context.Context) (map[string]api.AccessLevel, error) {
	m := map[string]api.AccessLevel{}
	for _, d := range f.domains {
		m[d] = api.LevelOwner
	}
	return m, nil
}

func (f *fakeDNS) Records(context.Context, string) (*api.RecordsResponse, error) {
	return &api.RecordsResponse{Records: f.records}, nil
}

func (f *fakeDNS) ModifyRecords(
	_ context.Context,
	domain string,
	ops ...api.RecordOperation,
) (*api.ModifyRecordsResponse, error) {
	m := modification{domain: domain}
	for _, op := range ops {
		var v map[string]any
		if err := json.Unmarshal(op, &v); err != nil {
			return nil, err
		}
		m.ops = append(m.ops, v)
	}
	f.modified = append(f.modified, m)
	return &api.ModifyRecordsResponse{}, nil
}

func record(id int, content string, ttl int) api.ExistingRecord {
	return api.ExistingRecord{Id: id, Name: "www", Type: "A", Content: content, TTL: ttl}
}

func ids(records []api.ExistingRecord) []int {
	out := make([]int, len(records))
	for i, r := range records {
		out[i] = r.Id
	}
	return out
}

func TestPlanRecords_exclusiveRemovesOthersAndDuplicates(t *testing.T) {
	existing := []api.ExistingRecord{record(1, "192.0.2.1", 60), record(2, "192.0.2.2", 60), record(3, "192.0.2.1", 60)}

	p := planRecords("A", existing, []string{"192.0.2.1", "192.0.2.9"}, nil, true)

	assert.Equal(t, []string{"192.0.2.9"}, p.add)
	assert.Empty(t, p.update)
	assert.Equal(t, []int{3, 2}, ids(p.remove))
	assert.Equal(t, []string{"192.0.2.1", "192.0.2.9"}, p.predict(existing))
}

func TestPlanRecords_inclusiveKeepsOthers(t *testing.T) {
	p := planRecords(
		"A",
		[]api.ExistingRecord{record(1, "192.0.2.1", 60), record(2, "192.0.2.2", 60)},
		[]string{"192.0.2.1"},
		nil,
		false,
	)

	assert.True(t, p.empty())
}

func TestPlanRecords_ttl(t *testing.T) {
	existing := []api.ExistingRecord{record(1, "192.0.2.1", 60), record(2, "192.0.2.2", 300)}
	ttl := 300

	p := planRecords("A", existing, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, &ttl, true)

	assert.Equal(t, []int{1}, ids(p.update))
	ops := p.operations("www", "A", &ttl)
	require.Len(t, ops, 2)
	assert.JSONEq(t, `{"id":1,"ttl":300}`, string(ops[0]))
	assert.JSONEq(t, `{"name":"www","type":"A","content":"192.0.2.3","ttl":300}`, string(ops[1]))
}

func TestPlanRecords_nilTTLLeavesTTLsAlone(t *testing.T) {
	p := planRecords("A", []api.ExistingRecord{record(1, "192.0.2.1", 60)}, []string{"192.0.2.1", "192.0.2.3"}, nil, false)

	assert.Empty(t, p.update)
	ops := p.operations("www", "A", nil)
	require.Len(t, ops, 1)
	assert.JSONEq(t, `{"name":"www","type":"A","content":"192.0.2.3"}`, string(ops[0]))
}

func TestPlanRecords_comparesAddressesCanonically(t *testing.T) {
	existing := []api.ExistingRecord{{Id: 1, Type: "AAAA", Content: "2001:0db8:0000::0001"}}

	assert.True(t, planRecords("AAAA", existing, []string{"2001:db8::1"}, nil, true).empty())
}

func TestFindDomain(t *testing.T) {
	domains := []string{"example.com", "bar.example.com", "r.example.com"}

	assert.Equal(t, "bar.example.com", findDomain(domains, "foo.bar.example.com"))
	assert.Equal(t, "example.com", findDomain(domains, "foobar.example.com."))
	assert.Equal(t, "example.com", findDomain(domains, "Example.COM"))
	assert.Empty(t, findDomain(domains, "example.org"))
}

func TestRelativeName(t *testing.T) {
	tests := []struct {
		name, want string
		wantErr    bool
	}{
		{name: "@", want: ""},
		{name: "example.com", want: ""},
		{name: "www.example.com.", want: "www"},
		{name: "WWW", want: "www"},
		{name: "www.example.org.", wantErr: true},
	}
	for _, tt := range tests {
		got, err := relativeName(tt.name, "example.com")
		if tt.wantErr {
			require.Error(t, err, tt.name)
			continue
		}
		require.NoError(t, err, tt.name)
		assert.Equal(t, tt.want, got, tt.name)
	}
}

func TestDNSAddress(t *testing.T) {
	tests := []struct {
		rtype, fact, want string
		ok                bool
	}{
		{"A", "203.0.113.5", "203.0.113.5", true},
		{"A", "192.168.87.170", "192.168.87.170", true},
		{"AAAA", "2001:0db8::0001", "2001:db8::1", true},
		{"A", "2001:db8::1", "", false},
		{"AAAA", "203.0.113.5", "", false},
		{"AAAA", "::ffff:203.0.113.5", "", false},
		{"A", "127.0.0.1", "", false},
		{"A", "0.0.0.0", "", false},
		{"AAAA", "fe80::1", "", false},
		{"AAAA", "fe80::1%eth0", "", false},
		{"A", "", "", false},
		{"A", "evil.example.com", "", false},
	}
	for _, tt := range tests {
		got, ok := dnsAddress(tt.rtype, tt.fact)
		assert.Equal(t, tt.ok, ok, "%s %s", tt.rtype, tt.fact)
		assert.Equal(t, tt.want, got, "%s %s", tt.rtype, tt.fact)
	}
}

func TestZonesPlan(t *testing.T) {
	client := &fakeDNS{
		domains: []string{"example.com", "other.org"},
		records: []api.ExistingRecord{
			{Id: 7, Name: "host", Type: "A", Content: "192.0.2.1"},
			{Id: 8, Name: "host", Type: "AAAA", Content: "2001:db8::1"},
			{Id: 9, Name: "elsewhere", Type: "A", Content: "192.0.2.1"},
		},
	}
	z := &dnsZones{client: client, records: map[string][]api.ExistingRecord{}}

	change, unchanged, err := z.plan(
		t.Context(),
		"host.example.com",
		map[string][]string{"A": {"192.0.2.2"}, "AAAA": {"2001:db8::1"}},
	)
	require.NoError(t, err)
	assert.Equal(t, 1, unchanged)
	require.NotNil(t, change)
	assert.Equal(t, []string{"~ A host.example.com  192.0.2.1 → 192.0.2.2"}, change.lines())
	require.NoError(t, change.apply(t.Context()))
	assert.Equal(
		t,
		[]modification{{
			domain: "example.com",
			ops: []map[string]any{
				{"id": float64(7), "delete": true},
				{"name": "host", "type": "A", "content": "192.0.2.2"},
			},
		}},
		client.modified,
	)

	none, _, err := z.plan(t.Context(), "host.example.com", map[string][]string{"AAAA": {"2001:db8::1"}})
	require.NoError(t, err)
	assert.Nil(t, none)

	added, _, err := z.plan(t.Context(), "new.example.com", map[string][]string{"A": {"192.0.2.3"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"+ A new.example.com  192.0.2.3"}, added.lines())

	_, _, err = z.plan(t.Context(), "host.example.net", map[string][]string{"A": {"192.0.2.3"}})
	assert.ErrorIs(t, err, errNoDomain)
}

func TestZonesPlan_replacesOtherTypesInOneChange(t *testing.T) {
	client := &fakeDNS{
		domains: []string{"example.com"},
		records: []api.ExistingRecord{
			{Id: 1, Name: "", Type: "A", Content: "192.0.2.1"},
			{Id: 2, Name: "", Type: "MX", Content: "mail.example.com"},
			{Id: 3, Name: "", Type: "RRCLONE", Content: "(A,AAAA)  Old.example.net."},
		},
	}
	z := &dnsZones{client: client, records: map[string][]api.ExistingRecord{}}

	change, _, err := z.plan(
		t.Context(),
		"example.com",
		map[string][]string{"A": nil, "CNAME": nil, "RRCLONE": {"(A,AAAA) new.example.net", "(A,AAAA) old.example.net"}},
	)
	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{
			"- A example.com  192.0.2.1",
			"~ RRCLONE example.com  (A,AAAA)  Old.example.net. → (A,AAAA)  Old.example.net., (A,AAAA) new.example.net",
		},
		change.lines(),
	)
	assert.Equal(t, "A, RRCLONE", change.types())
	require.NoError(t, change.apply(t.Context()))
	assert.Equal(
		t,
		[]map[string]any{
			{"id": float64(1), "delete": true},
			{"name": "@", "type": "RRCLONE", "content": "(A,AAAA) new.example.net"},
		},
		client.modified[0].ops,
	)
}

func TestZonesPlan_onlyWritableDomains(t *testing.T) {
	client := &levelDNS{
		levels: map[string]api.AccessLevel{"example.com": api.LevelRead, "sub.example.com": api.LevelWrite},
	}
	z := &dnsZones{client: client, records: map[string][]api.ExistingRecord{}}

	_, _, err := z.plan(t.Context(), "www.example.com", map[string][]string{"A": {"192.0.2.1"}})
	require.ErrorIs(t, err, errReadOnly)
	change, _, err := z.plan(t.Context(), "www.sub.example.com", map[string][]string{"A": {"192.0.2.1"}})
	require.NoError(t, err)
	assert.Equal(t, "sub.example.com", change.domain)

	// A writable parent doesn't stand in for a read-only zone within it.
	client.levels = map[string]api.AccessLevel{"example.com": api.LevelWrite, "sub.example.com": api.LevelRead}
	z = &dnsZones{client: client, records: map[string][]api.ExistingRecord{}}
	_, _, err = z.plan(t.Context(), "www.sub.example.com", map[string][]string{"A": {"192.0.2.1"}})
	assert.ErrorIs(t, err, errReadOnly)
}

type levelDNS struct {
	fakeDNS
	levels map[string]api.AccessLevel
}

func (l *levelDNS) Domains(context.Context) (map[string]api.AccessLevel, error) {
	return l.levels, nil
}

func TestManagedNames_vhosts(t *testing.T) {
	r := &Runner{
		DNSSettings: config.DNSSettings{Vhosts: []config.VhostRecord{{Type: "RRCLONE", Content: "(A,AAAA) {host}"}}},
		Vhosts: map[string][]string{
			"shared.example.com":  {"acidburn", "hetzner1", "smarts"},
			"mine.example.com":    {"acidburn"},
			"theirs.example.com":  {"hetzner1"},
			"unnamed.example.com": {"smarts"},
		},
		DNSNames: map[string]string{"acidburn": "acidburn.example.net", "hetzner1": "hetzner1.example.net"},
	}
	runs := []*hostRun{
		{name: "acidburn", agent: &agent{}},
		{name: "smarts", agent: &agent{}},
		{name: "unreachable"},
	}

	names, warnings := r.managedNames(runs)

	owned := func(rrclone ...string) map[string][]string {
		return map[string][]string{"A": nil, "AAAA": nil, "CNAME": nil, "RRCLONE": rrclone}
	}
	assert.Equal(
		t,
		[]managedName{
			{fqdn: "mine.example.com", types: owned("(A,AAAA) acidburn.example.net"), vhost: true},
			{
				fqdn:  "shared.example.com",
				types: owned("(A,AAAA) acidburn.example.net", "(A,AAAA) hetzner1.example.net"),
				vhost: true,
			},
		},
		names,
	)
	assert.Equal(t, []string{"smarts serves vhosts but has no dns_name"}, warnings)

	r.DNSSettings.Vhosts = nil
	names, warnings = r.managedNames(runs)
	assert.Empty(t, names)
	assert.Empty(t, warnings)
}

func TestPlanNames_vhostOutsideAccountWarns(t *testing.T) {
	z := &dnsZones{client: &fakeDNS{domains: []string{"example.com"}}, records: map[string][]api.ExistingRecord{}}
	var p dnsPlan

	z.planNames(
		t.Context(),
		[]managedName{
			{fqdn: "www.example.org", types: map[string][]string{"CNAME": {"x.example.com"}}, vhost: true},
			{fqdn: "host.example.org", types: map[string][]string{"A": {"192.0.2.1"}}},
		},
		&p,
	)

	assert.Equal(
		t,
		[]string{"leaving vhost www.example.org alone: no domain on this account contains it"},
		p.warnings,
	)
	require.Len(t, p.errs, 1)
	assert.ErrorIs(t, p.errs[0], errNoDomain)
}

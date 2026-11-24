package run

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"chameth.com/sensible/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type appliedChanges struct {
	zone    string
	changes dnsRecordChanges
}

type fakeDNS struct {
	zones   map[string]bool
	records []dnsRecord
	applied []appliedChanges
}

func (f *fakeDNS) Zones(context.Context) (map[string]bool, error) {
	return f.zones, nil
}

func (f *fakeDNS) Records(context.Context, string) ([]dnsRecord, error) {
	return f.records, nil
}

func (f *fakeDNS) Apply(_ context.Context, zone string, changes dnsRecordChanges) error {
	f.applied = append(f.applied, appliedChanges{zone: zone, changes: changes})
	return nil
}

func record(id, content string, ttl int) dnsRecord {
	return dnsRecord{id: id, name: "www", rtype: "A", content: content, ttl: ttl}
}

func ids(records []dnsRecord) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.id
	}
	return out
}

func TestPlanRecords_exclusiveRemovesOthersAndDuplicates(t *testing.T) {
	existing := []dnsRecord{record("1", "192.0.2.1", 60), record("2", "192.0.2.2", 60), record("3", "192.0.2.1", 60)}

	p := planRecords("A", existing, []string{"192.0.2.1", "192.0.2.9"}, nil, true)

	assert.Equal(t, []string{"192.0.2.9"}, p.add)
	assert.Empty(t, p.update)
	assert.Equal(t, []string{"3", "2"}, ids(p.remove))
	assert.Equal(t, []string{"192.0.2.1", "192.0.2.9"}, p.predict(existing))
}

func TestPlanRecords_inclusiveKeepsOthers(t *testing.T) {
	p := planRecords(
		"A",
		[]dnsRecord{record("1", "192.0.2.1", 60), record("2", "192.0.2.2", 60)},
		[]string{"192.0.2.1"},
		nil,
		false,
	)

	assert.True(t, p.empty())
}

func TestPlanRecords_ttl(t *testing.T) {
	existing := []dnsRecord{record("1", "192.0.2.1", 60), record("2", "192.0.2.2", 300)}
	ttl := 300

	p := planRecords("A", existing, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, &ttl, true)

	assert.Equal(t, []string{"1"}, ids(p.update))
	assert.Equal(
		t,
		dnsRecordChanges{
			update: []dnsRecord{record("1", "192.0.2.1", 300)},
			add:    []dnsRecord{{name: "www", rtype: "A", content: "192.0.2.3", ttl: 300}},
		},
		p.changes("www", "A", &ttl),
	)
}

func TestPlanRecords_nilTTLLeavesTTLsAlone(t *testing.T) {
	p := planRecords("A", []dnsRecord{record("1", "192.0.2.1", 60)}, []string{"192.0.2.1", "192.0.2.3"}, nil, false)

	assert.Empty(t, p.update)
	assert.Equal(
		t,
		dnsRecordChanges{add: []dnsRecord{{name: "www", rtype: "A", content: "192.0.2.3"}}},
		p.changes("www", "A", nil),
	)
}

func TestPlanRecords_comparesAddressesCanonically(t *testing.T) {
	existing := []dnsRecord{{id: "1", rtype: "AAAA", content: "2001:0db8:0000::0001"}}

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
	provider := &fakeDNS{
		zones: map[string]bool{"Example.com.": true, "other.org": true},
		records: []dnsRecord{
			{id: "7", name: "host", rtype: "A", content: "192.0.2.1"},
			{id: "8", name: "host.example.com.", rtype: "AAAA", content: "2001:db8::1"},
			{id: "9", name: "elsewhere", rtype: "A", content: "192.0.2.1"},
		},
	}
	z := &dnsZones{provider: provider, records: map[string][]dnsRecord{}}

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
		[]appliedChanges{{
			zone: "example.com",
			changes: dnsRecordChanges{
				remove: []dnsRecord{provider.records[0]},
				add:    []dnsRecord{{name: "host", rtype: "A", content: "192.0.2.2"}},
			},
		}},
		provider.applied,
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
	provider := &fakeDNS{
		zones: map[string]bool{"example.com": true},
		records: []dnsRecord{
			{id: "1", name: "", rtype: "A", content: "192.0.2.1"},
			{id: "2", name: "", rtype: "MX", content: "mail.example.com"},
			{id: "3", name: "@", rtype: "RRCLONE", content: "(A,AAAA)  Old.example.net."},
		},
	}
	z := &dnsZones{provider: provider, records: map[string][]dnsRecord{}}

	change, _, err := z.plan(
		t.Context(),
		"example.com",
		map[string][]string{
			"A":       nil,
			"CNAME":   nil,
			"RRCLONE": {"(A,AAAA) new.example.net", "(A,AAAA) old.example.net"},
		},
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
		dnsRecordChanges{
			remove: []dnsRecord{provider.records[0]},
			add:    []dnsRecord{{name: "", rtype: "RRCLONE", content: "(A,AAAA) new.example.net"}},
		},
		provider.applied[0].changes,
	)
}

func TestZonesPlan_onlyWritableZones(t *testing.T) {
	provider := &fakeDNS{zones: map[string]bool{"example.com": false, "sub.example.com": true}}
	z := &dnsZones{provider: provider, records: map[string][]dnsRecord{}}

	_, _, err := z.plan(t.Context(), "www.example.com", map[string][]string{"A": {"192.0.2.1"}})
	require.ErrorIs(t, err, errReadOnly)
	change, _, err := z.plan(t.Context(), "www.sub.example.com", map[string][]string{"A": {"192.0.2.1"}})
	require.NoError(t, err)
	assert.Equal(t, "sub.example.com", change.zone)

	// A writable parent doesn't stand in for a read-only zone within it.
	provider.zones = map[string]bool{"example.com": true, "sub.example.com": false}
	z = &dnsZones{provider: provider, records: map[string][]dnsRecord{}}
	_, _, err = z.plan(t.Context(), "www.sub.example.com", map[string][]string{"A": {"192.0.2.1"}})
	assert.ErrorIs(t, err, errReadOnly)
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

func TestManagedNames_retiresNamesNothingDeclares(t *testing.T) {
	r := &Runner{
		DNSSettings: config.DNSSettings{Provider: "mydnshost"},
		Vhosts:      map[string][]string{"moved.example.com": {"hetzner1"}},
		DNSNames:    map[string]string{"hetzner1": "Hetzner1.example.net"},
		DNSState: map[string][]string{
			"gone.example.com":     {"A", "AAAA", "CNAME", "RRCLONE"},
			"moved.example.com":    {"A", "AAAA", "CNAME"},
			"hetzner1.example.net": {"A"},
			"web1.example.net":     {"A", "AAAA"},
		},
	}

	names, _ := r.managedNames([]*hostRun{{name: "acidburn", agent: &agent{}}})

	assert.Equal(
		t,
		[]managedName{
			{
				fqdn:    "gone.example.com",
				types:   map[string][]string{"A": nil, "AAAA": nil, "CNAME": nil, "RRCLONE": nil},
				retired: true,
			},
			{fqdn: "web1.example.net", types: map[string][]string{"A": nil, "AAAA": nil}, retired: true},
		},
		names,
	)

	r.DNSSettings.Provider = ""
	names, _ = r.managedNames(nil)
	assert.Empty(t, names)
}

func TestPlanDNS_recordsNamesAlreadyAsTheyShouldBe(t *testing.T) {
	provider := &fakeDNS{
		zones:   map[string]bool{"example.com": true, "readonly.com": false},
		records: []dnsRecord{{id: "1", name: "web1", rtype: "A", content: "192.0.2.1"}},
	}
	var saved map[string][]string
	r := &Runner{
		DNS:          func(config.DNSSettings) (dnsProvider, error) { return provider, nil },
		DNSState:     map[string][]string{"empty.example.com": {"A"}, "old.readonly.com": {"A"}},
		SaveDNSState: func(s map[string][]string) error { saved = s; return nil },
	}

	p := r.planDNS(
		t.Context(),
		[]managedName{
			{fqdn: "Web1.example.com", types: map[string][]string{"A": {"192.0.2.1"}}},
			{fqdn: "new.example.com", types: map[string][]string{"A": {"192.0.2.2"}}},
			{fqdn: "empty.example.com", types: map[string][]string{"A": nil}, retired: true},
			{fqdn: "old.readonly.com", types: map[string][]string{"A": nil}, retired: true},
		},
		nil,
	)

	assert.Empty(t, p.errs)
	assert.Equal(
		t,
		[]string{"leaving retired name old.readonly.com alone: this account can't change its domain readonly.com"},
		p.warnings,
	)
	assert.Equal(t, map[string][]string{"web1.example.com": {"A"}, "old.readonly.com": {"A"}}, saved)
	assert.Equal(t, saved, r.DNSState)
}

func TestRecordDNS_keepsTypesAndOnlySavesChanges(t *testing.T) {
	saves := 0
	r := &Runner{
		DNSState:     map[string][]string{"app.example.com": {"A", "RRCLONE"}},
		SaveDNSState: func(map[string][]string) error { saves++; return nil },
	}

	require.NoError(t, r.recordDNS(dnsStateChange{remember: map[string][]string{"app.example.com": {"cname", "A"}}}))
	assert.Equal(t, map[string][]string{"app.example.com": {"A", "CNAME", "RRCLONE"}}, r.DNSState)
	require.NoError(t, r.recordDNS(dnsStateChange{remember: map[string][]string{"app.example.com": {"A"}}}))
	assert.Equal(t, 1, saves)
}

func TestPlanNames_vhostOutsideAccountWarns(t *testing.T) {
	z := &dnsZones{provider: &fakeDNS{zones: map[string]bool{"example.com": true}}, records: map[string][]dnsRecord{}}
	var p dnsPlan

	z.planNames(
		t.Context(),
		[]managedName{
			{fqdn: "www.example.org", types: map[string][]string{"CNAME": {"x.example.com"}}, vhost: true},
			{fqdn: "host.example.org", types: map[string][]string{"A": {"192.0.2.1"}}},
		},
		&p,
	)

	assert.Equal(t, []string{"leaving vhost www.example.org alone: no domain on this account contains it"}, p.warnings)
	require.Len(t, p.errs, 1)
	assert.ErrorIs(t, p.errs[0], errNoDomain)
}

func TestNewDNSProvider_needsAKnownProvider(t *testing.T) {
	_, err := newDNSProvider(config.DNSSettings{})
	require.ErrorContains(t, err, "dns.provider isn't set")

	_, err = newDNSProvider(config.DNSSettings{Provider: "nope"})
	require.ErrorContains(t, err, `unknown provider "nope"`)

	_, err = newDNSProvider(config.DNSSettings{Provider: "mydnshost"})
	assert.ErrorContains(t, err, "dns.mydnshost.auth_user")
}

// fakeMyDNSHost serves the MyDNSHost API for user "alice" with key "key".
type fakeMyDNSHost struct {
	levels   map[string]string
	records  []map[string]any
	modified []map[string]any
}

func newFakeMyDNSHost(t *testing.T, f *fakeMyDNSHost) *myDNSHost {
	t.Helper()
	reply := func(w http.ResponseWriter, response any) {
		writeJSON(w, http.StatusOK, map[string]any{"respid": "1", "method": "x", "response": response})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /1.0/domains", func(w http.ResponseWriter, _ *http.Request) { reply(w, f.levels) })
	mux.HandleFunc(
		"GET /1.0/domains/example.com/records",
		func(w http.ResponseWriter, _ *http.Request) { reply(w, map[string]any{"records": f.records}) },
	)
	mux.HandleFunc(
		"POST /1.0/domains/example.com/records",
		func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Data struct {
					Records []map[string]any `json:"records"`
				} `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.modified = append(f.modified, body.Data.Records...)
			reply(w, map[string]any{"serial": 1, "changed": []any{}})
		},
	)
	srv := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Api-User") != "alice" || r.Header.Get("X-Api-Key") != "key" {
					writeJSON(w, http.StatusOK, map[string]any{"error": "Invalid API key"})
					return
				}
				mux.ServeHTTP(w, r)
			},
		),
	)
	t.Cleanup(srv.Close)
	return &myDNSHost{url: srv.URL + "/1.0", user: "alice", key: "key", client: providerClient()}
}

func TestMyDNSHost_zonesAreWritableWithWriteAccess(t *testing.T) {
	zones, err := newFakeMyDNSHost(
		t,
		&fakeMyDNSHost{
			levels: map[string]string{
				"owned.com": "owner",
				"admin.com": "admin",
				"write.com": "write",
				"read.com":  "read",
			},
		},
	).Zones(t.Context())

	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"owned.com": true, "admin.com": true, "write.com": true, "read.com": false}, zones)
}

func TestMyDNSHost_records(t *testing.T) {
	records, err := newFakeMyDNSHost(
		t,
		&fakeMyDNSHost{
			records: []map[string]any{
				{"id": 7, "name": "www", "type": "A", "content": "192.0.2.1", "ttl": 60, "changed_at": 1},
			},
		},
	).Records(t.Context(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, []dnsRecord{{id: "7", name: "www", rtype: "A", content: "192.0.2.1", ttl: 60}}, records)
}

func TestMyDNSHost_apply(t *testing.T) {
	fake := &fakeMyDNSHost{}

	err := newFakeMyDNSHost(t, fake).Apply(
		t.Context(),
		"example.com",
		dnsRecordChanges{
			remove: []dnsRecord{{id: "1"}},
			update: []dnsRecord{{id: "2", ttl: 300}},
			add: []dnsRecord{
				{name: "", rtype: "RRCLONE", content: "(A,AAAA) host.example.net"},
				{name: "www", rtype: "A", content: "192.0.2.3", ttl: 60},
			},
		},
	)

	require.NoError(t, err)
	assert.Equal(
		t,
		[]map[string]any{
			{"id": float64(1), "delete": true},
			{"id": float64(2), "ttl": float64(300)},
			{"name": "@", "type": "RRCLONE", "content": "(A,AAAA) host.example.net"},
			{"name": "www", "type": "A", "content": "192.0.2.3", "ttl": float64(60)},
		},
		fake.modified,
	)
}

func TestMyDNSHost_reportsAPIErrors(t *testing.T) {
	m := newFakeMyDNSHost(t, &fakeMyDNSHost{})
	m.key = "wrong"

	_, err := m.Zones(t.Context())

	require.ErrorContains(t, err, "GET /domains: Invalid API key")
}

func TestMyDNSHost_reportsHTTPErrors(t *testing.T) {
	_, err := newFakeMyDNSHost(t, &fakeMyDNSHost{}).Records(t.Context(), "missing.com")

	require.ErrorContains(t, err, "GET /domains/missing.com/records: 404 Not Found")
}

func TestMyDNSHost_refusesRedirects(t *testing.T) {
	var leaked []string
	elsewhere := httptest.NewServer(
		http.HandlerFunc(
			func(_ http.ResponseWriter, r *http.Request) { leaked = append(leaked, r.Header.Get("X-Api-Key")) },
		),
	)
	t.Cleanup(elsewhere.Close)
	redirect := httptest.NewServer(http.RedirectHandler(elsewhere.URL, http.StatusFound))
	t.Cleanup(redirect.Close)
	m := &myDNSHost{url: redirect.URL, user: "alice", key: "key", client: providerClient()}

	_, err := m.Zones(t.Context())

	require.ErrorContains(t, err, "refusing to follow a redirect to "+elsewhere.URL)
	assert.Empty(t, leaked)
}

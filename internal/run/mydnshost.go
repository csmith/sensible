package run

import (
	"context"
	"fmt"
	"strconv"

	api "github.com/mydnshost/mydnshost-go-api"

	"chameth.com/sensible/internal/config"
)

// myDNSHost is a MyDNSHost account.
type myDNSHost struct {
	client myDNSHostClient
}

type myDNSHostClient interface {
	Domains(ctx context.Context) (map[string]api.AccessLevel, error)
	Records(ctx context.Context, domain string) (*api.RecordsResponse, error)
	ModifyRecords(ctx context.Context, domain string, ops ...api.RecordOperation) (*api.ModifyRecordsResponse, error)
}

func newMyDNSHost(s config.MyDNSHostSettings) (*myDNSHost, error) {
	user, err := s.AuthUser.Reveal()
	if err != nil {
		return nil, fmt.Errorf("sensible.yml: dns.mydnshost.auth_user: %w", err)
	}
	key, err := s.AuthKey.Reveal()
	if err != nil {
		return nil, fmt.Errorf("sensible.yml: dns.mydnshost.auth_key: %w", err)
	}
	return &myDNSHost{client: &api.Client{Authenticator: &api.ApiKeyAuthenticator{User: user, Key: key}}}, nil
}

func (m *myDNSHost) Zones(ctx context.Context) (map[string]bool, error) {
	domains, err := m.client.Domains(ctx)
	if err != nil {
		return nil, err
	}
	zones := make(map[string]bool, len(domains))
	for d, level := range domains {
		zones[d] = level == api.LevelOwner || level == api.LevelAdmin || level == api.LevelWrite
	}
	return zones, nil
}

func (m *myDNSHost) Records(ctx context.Context, zone string) ([]dnsRecord, error) {
	res, err := m.client.Records(ctx, zone)
	if err != nil {
		return nil, err
	}
	records := make([]dnsRecord, len(res.Records))
	for i, rec := range res.Records {
		records[i] = dnsRecord{
			id:      strconv.Itoa(rec.Id),
			name:    rec.Name,
			rtype:   rec.Type,
			content: rec.Content,
			ttl:     rec.TTL,
		}
	}
	return records, nil
}

func (m *myDNSHost) Apply(ctx context.Context, zone string, changes dnsRecordChanges) error {
	ops := make([]api.RecordOperation, 0, len(changes.remove)+len(changes.update)+len(changes.add))
	for _, rec := range changes.remove {
		id, err := strconv.Atoi(rec.id)
		if err != nil {
			return fmt.Errorf("invalid record id %q", rec.id)
		}
		ops = append(ops, api.DeleteRecord(id))
	}
	for _, rec := range changes.update {
		id, err := strconv.Atoi(rec.id)
		if err != nil {
			return fmt.Errorf("invalid record id %q", rec.id)
		}
		ops = append(ops, api.ModifyRecord(id, api.Record{TTL: rec.ttl}))
	}
	for _, rec := range changes.add {
		name := rec.name
		if name == "" {
			// An empty name would be left out, and the API reads "@" as the
			// apex.
			name = "@"
		}
		ops = append(ops, api.CreateRecord(api.Record{Name: name, Type: rec.rtype, Content: rec.content, TTL: rec.ttl}))
	}
	_, err := m.client.ModifyRecords(ctx, zone, ops...)
	return err
}

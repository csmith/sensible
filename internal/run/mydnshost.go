package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"chameth.com/sensible/internal/config"
)

// myDNSHost is a MyDNSHost account.
type myDNSHost struct {
	url    string
	user   string
	key    string
	client *http.Client
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
	return &myDNSHost{url: "https://api.mydnshost.co.uk/1.0", user: user, key: key, client: providerClient()}, nil
}

func (m *myDNSHost) Zones(ctx context.Context) (map[string]bool, error) {
	var domains map[string]string
	if err := m.do(ctx, http.MethodGet, "/domains", nil, &domains); err != nil {
		return nil, err
	}
	zones := make(map[string]bool, len(domains))
	for d, level := range domains {
		zones[d] = level == "owner" || level == "admin" || level == "write"
	}
	return zones, nil
}

func (m *myDNSHost) Records(ctx context.Context, zone string) ([]dnsRecord, error) {
	var res struct {
		Records []struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
			TTL     int    `json:"ttl"`
		} `json:"records"`
	}
	if err := m.do(ctx, http.MethodGet, recordsPath(zone), nil, &res); err != nil {
		return nil, err
	}
	records := make([]dnsRecord, len(res.Records))
	for i, rec := range res.Records {
		records[i] = dnsRecord{
			id:      strconv.Itoa(rec.ID),
			name:    rec.Name,
			rtype:   rec.Type,
			content: rec.Content,
			ttl:     rec.TTL,
		}
	}
	return records, nil
}

func (m *myDNSHost) Apply(ctx context.Context, zone string, changes dnsRecordChanges) error {
	type op struct {
		ID      int    `json:"id,omitempty"`
		Delete  bool   `json:"delete,omitempty"`
		Name    string `json:"name,omitempty"`
		Type    string `json:"type,omitempty"`
		Content string `json:"content,omitempty"`
		TTL     int    `json:"ttl,omitempty"`
	}
	ops := make([]op, 0, len(changes.remove)+len(changes.update)+len(changes.add))
	for _, rec := range changes.remove {
		id, err := strconv.Atoi(rec.id)
		if err != nil {
			return fmt.Errorf("invalid record id %q", rec.id)
		}
		ops = append(ops, op{ID: id, Delete: true})
	}
	for _, rec := range changes.update {
		id, err := strconv.Atoi(rec.id)
		if err != nil {
			return fmt.Errorf("invalid record id %q", rec.id)
		}
		ops = append(ops, op{ID: id, TTL: rec.ttl})
	}
	for _, rec := range changes.add {
		name := rec.name
		if name == "" {
			// An empty name would be left out, and the API reads "@" as the
			// apex.
			name = "@"
		}
		ops = append(ops, op{Name: name, Type: rec.rtype, Content: rec.content, TTL: rec.ttl})
	}
	body := map[string]any{"data": map[string]any{"records": ops}}
	return m.do(ctx, http.MethodPost, recordsPath(zone), body, nil)
}

// do sends a request to the API with body, if it's not nil, as JSON,
// decoding the response's data into out if it's not nil.
func (m *myDNSHost) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.url+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-User", m.user)
	req.Header.Set("X-Api-Key", m.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	var envelope struct {
		Error    *string         `json:"error"`
		Response json.RawMessage `json:"response"`
	}
	decodeErr := json.NewDecoder(res.Body).Decode(&envelope)
	switch {
	case decodeErr == nil && envelope.Error != nil:
		return fmt.Errorf("%s %s: %s", method, path, *envelope.Error)
	case res.StatusCode < 200 || res.StatusCode > 299:
		return fmt.Errorf("%s %s: %s", method, path, res.Status)
	case decodeErr != nil:
		return fmt.Errorf("%s %s: %w", method, path, decodeErr)
	case out == nil:
		return nil
	}
	if err := json.Unmarshal(envelope.Response, out); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	return nil
}

func recordsPath(zone string) string {
	return "/domains/" + url.PathEscape(zone) + "/records"
}

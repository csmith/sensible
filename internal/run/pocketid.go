package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"chameth.com/sensible/internal/config"
)

// pocketID is a Pocket ID instance, used with an admin's API key.
type pocketID struct {
	url    string
	key    string
	client *http.Client
}

func newPocketID(s config.PocketIDSettings) (*pocketID, error) {
	key, err := s.APIKey.Reveal()
	if err != nil {
		return nil, fmt.Errorf("sensible.yml: oidc.pocketid.api_key: %w", err)
	}
	return &pocketID{url: s.URL, key: key, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (p *pocketID) Client(ctx context.Context, id string) (*oidcClient, error) {
	var res struct {
		ID                 string   `json:"id"`
		Name               string   `json:"name"`
		CallbackURLs       []string `json:"callbackURLs"`
		LogoutCallbackURLs []string `json:"logoutCallbackURLs"`
		IsPublic           bool     `json:"isPublic"`
		PkceEnabled        bool     `json:"pkceEnabled"`
		IsGroupRestricted  bool     `json:"isGroupRestricted"`
		AllowedUserGroups  []struct {
			ID string `json:"id"`
		} `json:"allowedUserGroups"`
	}
	err := p.do(ctx, http.MethodGet, clientPath(id), nil, &res)
	if errors.Is(err, errPocketIDNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c := &oidcClient{
		id:                 res.ID,
		name:               res.Name,
		callbackURLs:       res.CallbackURLs,
		logoutCallbackURLs: res.LogoutCallbackURLs,
		public:             res.IsPublic,
		pkce:               res.PkceEnabled,
		restricted:         res.IsGroupRestricted,
	}
	for _, g := range res.AllowedUserGroups {
		c.groups = append(c.groups, g.ID)
	}
	return c, nil
}

func (p *pocketID) Secrets(ctx context.Context, id string) ([]oidcSecret, error) {
	var res []struct {
		ID       string `json:"id"`
		Prefix   string `json:"prefix"`
		IsActive bool   `json:"isActive"`
	}
	if err := p.do(ctx, http.MethodGet, clientPath(id)+"/secrets", nil, &res); err != nil {
		return nil, err
	}
	secrets := make([]oidcSecret, len(res))
	for i, s := range res {
		secrets[i] = oidcSecret{id: s.ID, prefix: s.Prefix, active: s.IsActive}
	}
	return secrets, nil
}

func (p *pocketID) Groups(ctx context.Context) (map[string]string, error) {
	groups := map[string]string{}
	for page := 1; ; page++ {
		var res struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		q := url.Values{"pagination[page]": {strconv.Itoa(page)}, "pagination[limit]": {"100"}}
		if err := p.do(ctx, http.MethodGet, "/api/user-groups?"+q.Encode(), nil, &res); err != nil {
			return nil, err
		}
		for _, g := range res.Data {
			groups[g.Name] = g.ID
		}
		if page >= res.Pagination.TotalPages {
			return groups, nil
		}
	}
}

func (p *pocketID) Create(ctx context.Context, c oidcClient) error {
	body := clientSettings(c)
	body["id"] = c.id
	return p.do(ctx, http.MethodPost, "/api/oidc/clients", body, nil)
}

// Update sends the client's current settings back with sensible's changed,
// as Pocket ID resets any that are left out.
func (p *pocketID) Update(ctx context.Context, c oidcClient) error {
	var current map[string]any
	if err := p.do(ctx, http.MethodGet, clientPath(c.id), nil, &current); err != nil {
		return err
	}
	maps.Copy(current, clientSettings(c))
	return p.do(ctx, http.MethodPut, clientPath(c.id), current, nil)
}

func clientSettings(c oidcClient) map[string]any {
	return map[string]any{
		"name":               c.name,
		"callbackURLs":       nonNil(c.callbackURLs),
		"logoutCallbackURLs": nonNil(c.logoutCallbackURLs),
		"isPublic":           c.public,
		"pkceEnabled":        c.pkce,
		"isGroupRestricted":  c.restricted,
	}
}

func (p *pocketID) SetGroups(ctx context.Context, id string, groups []string) error {
	body := map[string][]string{"userGroupIds": nonNil(groups)}
	return p.do(ctx, http.MethodPut, clientPath(id)+"/allowed-user-groups", body, nil)
}

func (p *pocketID) AddSecret(ctx context.Context, id, secret string) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	err := p.do(ctx, http.MethodPost, clientPath(id)+"/secrets", map[string]string{"secret": secret}, &res)
	if err == nil && res.ID == "" {
		err = errors.New("pocket ID didn't give the new secret's ID")
	}
	return res.ID, err
}

func (p *pocketID) DeleteSecret(ctx context.Context, id, secretID string) error {
	return p.do(ctx, http.MethodDelete, clientPath(id)+"/secrets/"+url.PathEscape(secretID), nil, nil)
}

func (p *pocketID) Delete(ctx context.Context, id string) error {
	err := p.do(ctx, http.MethodDelete, clientPath(id), nil, nil)
	if errors.Is(err, errPocketIDNotFound) {
		return nil
	}
	return err
}

var errPocketIDNotFound = errors.New("not found")

// do sends a request to the API, decoding the response into out if it's not
// nil.
func (p *pocketID) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.url+path, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", p.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s %s: %w", method, path, errPocketIDNotFound)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		if e.Error == "" {
			e.Error = res.Status
		}
		return fmt.Errorf("%s %s: %s", method, path, e.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	return nil
}

func clientPath(id string) string {
	return "/api/oidc/clients/" + url.PathEscape(id)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

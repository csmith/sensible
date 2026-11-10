package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
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
		SkipConsent        bool     `json:"skipConsent"`
		IsGroupRestricted  bool     `json:"isGroupRestricted"`
		LaunchURL          *string  `json:"launchURL"`
		HasLogo            bool     `json:"hasLogo"`
		HasDarkLogo        bool     `json:"hasDarkLogo"`
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
		skipConsent:        res.SkipConsent,
		restricted:         res.IsGroupRestricted,
		hasLogo:            res.HasLogo,
		hasDarkLogo:        res.HasDarkLogo,
	}
	if res.LaunchURL != nil {
		c.launchURL = *res.LaunchURL
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
	type group struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	groups := map[string]string{}
	err := eachPage(
		ctx,
		p,
		"/api/user-groups",
		func(g group) {
			groups[g.Name] = g.ID
		},
	)
	return groups, err
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
	settings := map[string]any{
		"name":               c.name,
		"callbackURLs":       nonNil(c.callbackURLs),
		"logoutCallbackURLs": nonNil(c.logoutCallbackURLs),
		"isPublic":           c.public,
		"pkceEnabled":        c.pkce,
		"skipConsent":        c.skipConsent,
		"isGroupRestricted":  c.restricted,
	}
	if c.launchURL != "" {
		settings["launchURL"] = c.launchURL
	}
	return settings
}

// SetLogo uploads a logo, taking its type from name's extension.
func (p *pocketID) SetLogo(ctx context.Context, id string, dark bool, name string, data []byte) error {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", name)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return p.send(
		ctx,
		http.MethodPost,
		clientPath(id)+"/logo?"+url.Values{"light": {strconv.FormatBool(!dark)}}.Encode(),
		w.FormDataContentType(),
		&body,
		nil,
	)
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

// pocketIDAPI is an API as Pocket ID gives it.
type pocketIDAPI struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Permissions []struct {
		ID          string `json:"id"`
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"permissions"`
}

func (a pocketIDAPI) api() *oidcAPI {
	api := &oidcAPI{id: a.ID, name: a.Name}
	for _, perm := range a.Permissions {
		api.permissions = append(
			api.permissions,
			oidcPermission{id: perm.ID, key: perm.Key, name: perm.Name, description: perm.Description},
		)
	}
	slices.SortFunc(api.permissions, func(a, b oidcPermission) int { return strings.Compare(a.key, b.key) })
	return api
}

func (p *pocketID) APIs(ctx context.Context) (map[string]*oidcAPI, error) {
	apis := map[string]*oidcAPI{}
	err := eachPage(ctx, p, "/api/apis", func(a pocketIDAPI) { apis[a.Resource] = a.api() })
	return apis, err
}

func (p *pocketID) CreateAPI(ctx context.Context, identifier, name string) (string, error) {
	var res pocketIDAPI
	err := p.do(ctx, http.MethodPost, "/api/apis", map[string]string{"name": name, "resource": identifier}, &res)
	if err == nil && res.ID == "" {
		err = errors.New("pocket ID didn't give the new API's ID")
	}
	return res.ID, err
}

func (p *pocketID) RenameAPI(ctx context.Context, id, name string) error {
	return p.do(ctx, http.MethodPut, apiPath(id), map[string]string{"name": name}, nil)
}

func (p *pocketID) SetPermissions(
	ctx context.Context,
	id string,
	permissions []oidcPermission,
) (map[string]string, error) {
	type permission struct {
		Key         string  `json:"key"`
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	body := struct {
		Permissions []permission `json:"permissions"`
	}{Permissions: []permission{}}
	for _, perm := range permissions {
		var description *string
		if perm.description != "" {
			description = &perm.description
		}
		body.Permissions = append(body.Permissions, permission{Key: perm.key, Name: perm.name, Description: description})
	}
	var res pocketIDAPI
	if err := p.do(ctx, http.MethodPut, apiPath(id)+"/permissions", body, &res); err != nil {
		return nil, err
	}
	ids := map[string]string{}
	for _, perm := range res.Permissions {
		ids[perm.Key] = perm.ID
	}
	return ids, nil
}

// Grants leaves out clients that can only call the API through Pocket ID's
// access for clients registered with a metadata document, which sensible
// doesn't manage.
func (p *pocketID) Grants(ctx context.Context, id string) (map[string]oidcGrant, error) {
	type access struct {
		Client struct {
			ID string `json:"id"`
		} `json:"client"`
		UserDelegatedAccess        bool     `json:"userDelegatedAccess"`
		ClientAccess               bool     `json:"clientAccess"`
		UserDelegatedPermissionIDs []string `json:"userDelegatedPermissionIds"`
		ClientPermissionIDs        []string `json:"clientPermissionIds"`
	}
	grants := map[string]oidcGrant{}
	err := eachPage(
		ctx,
		p,
		apiPath(id)+"/clients",
		func(a access) {
			g := oidcGrant{
				client:            a.ClientAccess || len(a.ClientPermissionIDs) > 0,
				user:              a.UserDelegatedAccess || len(a.UserDelegatedPermissionIDs) > 0,
				clientPermissions: a.ClientPermissionIDs,
				userPermissions:   a.UserDelegatedPermissionIDs,
			}
			if g.user || g.client {
				grants[a.Client.ID] = g
			}
		},
	)
	return grants, err
}

func (p *pocketID) Grant(ctx context.Context, id, clientID string, g oidcGrant) error {
	body := map[string]any{
		"userDelegatedAccess":        g.user,
		"clientAccess":               g.client,
		"userDelegatedPermissionIds": nonNil(g.userPermissions),
		"clientPermissionIds":        nonNil(g.clientPermissions),
	}
	return p.do(ctx, http.MethodPut, apiPath(id)+"/clients/"+url.PathEscape(clientID), body, nil)
}

func (p *pocketID) Revoke(ctx context.Context, id, clientID string) error {
	return p.do(ctx, http.MethodDelete, apiPath(id)+"/clients/"+url.PathEscape(clientID), nil, nil)
}

func (p *pocketID) DeleteAPI(ctx context.Context, id string) error {
	err := p.do(ctx, http.MethodDelete, apiPath(id), nil, nil)
	if errors.Is(err, errPocketIDNotFound) {
		return nil
	}
	return err
}

var errPocketIDNotFound = errors.New("not found")

// do sends a request to the API with body, if it's not nil, as JSON,
// decoding the response into out if it's not nil.
func (p *pocketID) do(ctx context.Context, method, path string, body, out any) error {
	if body == nil {
		return p.send(ctx, method, path, "", nil, out)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return p.send(ctx, method, path, "application/json", bytes.NewReader(b), out)
}

// send sends a request to the API, decoding the response into out if it's
// not nil.
func (p *pocketID) send(ctx context.Context, method, path, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, p.url+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", p.key)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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

// eachPage gets every page of a paginated list, passing each item to add.
func eachPage[T any](ctx context.Context, p *pocketID, path string, add func(T)) error {
	for page := 1; ; page++ {
		var res struct {
			Data       []T `json:"data"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		q := url.Values{"pagination[page]": {strconv.Itoa(page)}, "pagination[limit]": {"100"}}
		if err := p.do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &res); err != nil {
			return err
		}
		for _, item := range res.Data {
			add(item)
		}
		if page >= res.Pagination.TotalPages {
			return nil
		}
	}
}

func clientPath(id string) string {
	return "/api/oidc/clients/" + url.PathEscape(id)
}

func apiPath(id string) string {
	return "/api/apis/" + url.PathEscape(id)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

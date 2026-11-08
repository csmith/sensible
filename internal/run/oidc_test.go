package run

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

type fakeSecret struct {
	ID       string `json:"id"`
	Prefix   string `json:"prefix"`
	IsActive bool   `json:"isActive"`
}

type fakeGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// fakePocketID is enough of Pocket ID's admin API for sensible, serving one
// user group per page. Like Pocket ID by default, it gives each new
// confidential client a secret of its own.
type fakePocketID struct {
	groups []fakeGroup

	mu       sync.Mutex
	clients  map[string]map[string]any
	secrets  map[string][]fakeSecret
	requests []string
	nextID   int
}

func newFakePocketID(t *testing.T) (*fakePocketID, *httptest.Server) {
	t.Helper()
	f := &fakePocketID{
		groups:  []fakeGroup{{ID: "g1", Name: "admins"}, {ID: "g2", Name: "family"}},
		clients: map[string]map[string]any{},
		secrets: map[string][]fakeSecret{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/user-groups", f.listGroups)
	mux.HandleFunc("POST /api/oidc/clients", f.create)
	mux.HandleFunc("GET /api/oidc/clients/{id}", f.client(f.get))
	mux.HandleFunc("PUT /api/oidc/clients/{id}", f.client(f.update))
	mux.HandleFunc("DELETE /api/oidc/clients/{id}", f.client(f.delete))
	mux.HandleFunc("PUT /api/oidc/clients/{id}/allowed-user-groups", f.client(f.setGroups))
	mux.HandleFunc("GET /api/oidc/clients/{id}/secrets", f.client(f.listSecrets))
	mux.HandleFunc("POST /api/oidc/clients/{id}/secrets", f.client(f.addSecret))
	mux.HandleFunc("DELETE /api/oidc/clients/{id}/secrets/{secret}", f.client(f.deleteSecret))
	srv := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Api-Key") != "key" {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":"Invalid API key"}`))
					return
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				f.requests = append(f.requests, r.Method+" "+r.URL.Path)
				mux.ServeHTTP(w, r)
			},
		),
	)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakePocketID) listGroups(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("pagination[page]"))
	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"data":       f.groups[page-1 : page],
			"pagination": map[string]int{"currentPage": page, "totalPages": len(f.groups)},
		},
	)
}

func (f *fakePocketID) create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	id := body["id"].(string)
	body["allowedUserGroups"] = []any{}
	f.clients[id] = body
	if body["isPublic"] != true {
		f.secrets[id] = append(f.secrets[id], fakeSecret{ID: "auto", Prefix: "AUTO", IsActive: true})
	}
	writeJSON(w, http.StatusCreated, body)
}

// client serves a request about an existing client.
func (f *fakePocketID) client(handle func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, ok := f.clients[id]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Record not found"})
			return
		}
		handle(w, r, id)
	}
}

func (f *fakePocketID) get(w http.ResponseWriter, _ *http.Request, id string) {
	writeJSON(w, http.StatusOK, f.clients[id])
}

func (f *fakePocketID) update(w http.ResponseWriter, r *http.Request, id string) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.clients[id] = body
	writeJSON(w, http.StatusOK, body)
}

func (f *fakePocketID) delete(w http.ResponseWriter, _ *http.Request, id string) {
	delete(f.clients, id)
	delete(f.secrets, id)
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakePocketID) setGroups(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		UserGroupIDs []string `json:"userGroupIds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	groups := make([]any, 0, len(body.UserGroupIDs))
	for _, g := range body.UserGroupIDs {
		groups = append(groups, map[string]string{"id": g})
	}
	f.clients[id]["allowedUserGroups"] = groups
	writeJSON(w, http.StatusOK, f.clients[id])
}

func (f *fakePocketID) listSecrets(w http.ResponseWriter, _ *http.Request, id string) {
	writeJSON(w, http.StatusOK, append([]fakeSecret{}, f.secrets[id]...))
}

func (f *fakePocketID) addSecret(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Secret string `json:"secret"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.nextID++
	s := fakeSecret{ID: "s" + strconv.Itoa(f.nextID), Prefix: body.Secret[:4], IsActive: true}
	f.secrets[id] = append(f.secrets[id], s)
	writeJSON(w, http.StatusCreated, s)
}

func (f *fakePocketID) deleteSecret(w http.ResponseWriter, r *http.Request, id string) {
	f.secrets[id] = slices.DeleteFunc(f.secrets[id], func(s fakeSecret) bool { return s.ID == r.PathValue("secret") })
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// appSecretIDs are the IDs of the secrets of the client app.
func (f *fakePocketID) appSecretIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.secrets["app"]))
	for _, s := range f.secrets["app"] {
		ids = append(ids, s.ID)
	}
	return ids
}

const testSecret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// oidcFixture is a runner whose hosts declare the clients given for them,
// with sensible managing those in records, using a fake Pocket ID.
type oidcFixture struct {
	*runnerFixture
	pocketID *fakePocketID
	declared map[string]map[string]config.OIDCClientConfig
	records  map[string]map[string]string
	saved    []string
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	pid, srv := newFakePocketID(t)
	f := &oidcFixture{
		runnerFixture: newRunnerFixture(t, testResources),
		pocketID:      pid,
		declared:      map[string]map[string]config.OIDCClientConfig{},
		records:       map[string]map[string]string{},
	}
	f.runner.OIDC = func(config.OIDCSettings) (oidcProvider, error) {
		return &pocketID{url: srv.URL, key: "key", client: srv.Client()}, nil
	}
	f.runner.OIDCOwners = map[string]string{}
	f.runner.Compile = func(tg target, _ host.Facts) (compiled, error) {
		if f.records[tg.name] == nil {
			f.records[tg.name] = map[string]string{}
		}
		records := f.records[tg.name]
		return compiled{
			resources:   testResources,
			oidcClients: f.declared[tg.name],
			oidc: oidcRecords{
				clients: maps.Clone(records),
				save: func(id, secretID string) error {
					records[id] = secretID
					return nil
				},
				drop: func(id string) error {
					delete(records, id)
					return nil
				},
			},
			save: func() error {
				f.saved = append(f.saved, tg.name)
				return nil
			},
		}, nil
	}
	return f
}

// manage records that sensible manages the client for acidburn.
func (f *oidcFixture) manage(id, secretID string) {
	if f.records["acidburn"] == nil {
		f.records["acidburn"] = map[string]string{}
	}
	f.records["acidburn"][id] = secretID
	f.runner.OIDCOwners[id] = "acidburn"
}

// existing puts a client in Pocket ID with one secret, which is the test
// secret if secretID is "ours".
func (f *oidcFixture) existing(id string, settings map[string]any, secretID string) {
	client := map[string]any{
		"id":                 id,
		"name":               "App",
		"callbackURLs":       []any{"https://app.example.com/callback"},
		"logoutCallbackURLs": nil,
		"isPublic":           false,
		"pkceEnabled":        false,
		"isGroupRestricted":  true,
		"allowedUserGroups":  []any{map[string]any{"id": "g1", "name": "admins"}},
		"description":        "Set by hand",
	}
	maps.Copy(client, settings)
	f.pocketID.clients[id] = client
	prefix := "OTHR"
	if secretID == "ours" {
		prefix = testSecret[:4]
	}
	f.pocketID.secrets[id] = []fakeSecret{{ID: secretID, Prefix: prefix, IsActive: true}}
}

var testClient = config.OIDCClientConfig{
	Name:         "App",
	CallbackURLs: config.Set{"https://app.example.com/callback"},
	Groups:       config.Set{"admins"},
	Secret:       "oidc",
	SecretValue:  testSecret,
}

func TestExecute_oidcClientIsCreatedWithOnlySensiblesSecret(t *testing.T) {
	f := newOIDCFixture(t)
	f.declared["acidburn"] = map[string]config.OIDCClientConfig{"app": testClient}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, true)

	require.NoError(t, err)
	out := f.out.String()
	assert.Contains(t, out, "> Resolving OIDC changes\n  + client app\n")
	assert.Contains(t, out, "1 change on 1 target")
	assert.Contains(t, out, "> Applying OIDC changes\n  ✓ client app\n")
	assert.Equal(t, []string{"acidburn"}, f.saved, "the new secret is saved first")
	client := f.pocketID.clients["app"]
	assert.Equal(t, "App", client["name"])
	assert.Equal(t, true, client["isGroupRestricted"])
	assert.Equal(t, []any{map[string]string{"id": "g1"}}, client["allowedUserGroups"])
	assert.Equal(t, []string{"s1"}, f.pocketID.appSecretIDs())
	assert.Equal(t, map[string]string{"app": "s1"}, f.records["acidburn"])
}

func TestExecute_oidcClientNeedsNoChange(t *testing.T) {
	f := newOIDCFixture(t)
	f.declared["acidburn"] = map[string]config.OIDCClientConfig{"app": testClient}
	f.existing("app", nil, "ours")
	f.manage("app", "ours")

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, false)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "> Resolving OIDC changes\n  ✓ 1 unchanged\n")
	assert.Contains(t, f.out.String(), "No changes\n")
}

func TestExecute_oidcClientIsUpdatedKeepingWhatSensibleDoesntManage(t *testing.T) {
	f := newOIDCFixture(t)
	changed := testClient
	changed.Name = "New name"
	changed.Groups = config.Set{"family", "admins"}
	f.declared["acidburn"] = map[string]config.OIDCClientConfig{"app": changed}
	f.existing("app", nil, "ours")
	f.manage("app", "ours")

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, true)

	require.NoError(t, err)
	assert.Contains(
		t,
		f.out.String(),
		"> Resolving OIDC changes\n"+
			"  ~ client app  name: App → New name\n"+
			"  ~ client app  groups: admins → admins, family\n",
	)
	client := f.pocketID.clients["app"]
	assert.Equal(t, "New name", client["name"])
	assert.Equal(t, "Set by hand", client["description"])
	assert.Equal(t, []any{map[string]string{"id": "g1"}, map[string]string{"id": "g2"}}, client["allowedUserGroups"])
	assert.Equal(t, []string{"ours"}, f.pocketID.appSecretIDs())
	assert.NotContains(t, f.pocketID.requests, "POST /api/oidc/clients/app/secrets")
}

func TestExecute_oidcSecretIsReplacedWhenItDoesntMatch(t *testing.T) {
	f := newOIDCFixture(t)
	f.declared["acidburn"] = map[string]config.OIDCClientConfig{"app": testClient}
	f.existing("app", nil, "stale")
	f.manage("app", "stale")

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, true)

	require.NoError(t, err)
	assert.Contains(
		t,
		f.out.String(),
		"> Resolving OIDC changes\n  ~ client app  secret\n  - client app  1 other secret\n",
	)
	assert.Equal(t, []string{"s1"}, f.pocketID.appSecretIDs())
	assert.Equal(t, map[string]string{"app": "s1"}, f.records["acidburn"])
	assert.NotContains(t, f.pocketID.requests, "PUT /api/oidc/clients/app")
}

func TestExecute_oidcClientMadeByHandIsTakenOver(t *testing.T) {
	f := newOIDCFixture(t)
	f.declared["acidburn"] = map[string]config.OIDCClientConfig{
		"app": {Name: "App", CallbackURLs: config.Set{"https://app.example.com/callback"}, Public: true},
	}
	f.existing("app", map[string]any{"isGroupRestricted": false, "allowedUserGroups": []any{}}, "hand")

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, true)

	require.NoError(t, err)
	assert.Contains(
		t,
		f.out.String(),
		"> Resolving OIDC changes\n"+
			"  ~ client app  public: false → true\n"+
			"  ~ client app  pkce: false → true\n"+
			"  - client app  1 other secret\n"+
			"  ~ client app  host: none → acidburn\n",
	)
	assert.Equal(t, true, f.pocketID.clients["app"]["isPublic"])
	assert.Empty(t, f.pocketID.appSecretIDs())
	assert.Equal(t, map[string]string{"app": ""}, f.records["acidburn"])
}

func TestExecute_oidcClientMovesBetweenHostsInTheSameRun(t *testing.T) {
	f := newOIDCFixture(t)
	f.declared["smarts"] = map[string]config.OIDCClientConfig{"app": testClient}
	f.existing("app", nil, "ours")
	f.manage("app", "ours")

	err := f.runner.Execute(
		t.Context(),
		[]target{f.target("acidburn", &fakeAgent{}), f.target("smarts", &fakeAgent{})},
		true,
	)

	require.NoError(t, err)
	assert.Contains(
		t,
		f.out.String(),
		"  ~ client app  secret\n  - client app  1 other secret\n  ~ client app  host: acidburn → smarts\n",
	)
	assert.Empty(t, f.records["acidburn"])
	assert.Equal(t, map[string]string{"app": "s1"}, f.records["smarts"])
}

func TestExecute_oidcPlanErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *oidcFixture)
		want  string
	}{
		{
			"unknown group",
			func(f *oidcFixture) {
				c := testClient
				c.Groups = config.Set{"nobody"}
				f.declared["acidburn"] = map[string]config.OIDCClientConfig{"app": c}
			},
			`client app: no user group named "nobody"`,
		},
		{
			"declared by two hosts",
			func(f *oidcFixture) {
				f.declared["acidburn"] = map[string]config.OIDCClientConfig{"app": testClient}
				f.declared["smarts"] = map[string]config.OIDCClientConfig{"app": testClient}
			},
			"client app: both acidburn and smarts declare it",
		},
		{
			"managed for a host outside the run",
			func(f *oidcFixture) {
				f.declared["acidburn"] = map[string]config.OIDCClientConfig{"app": testClient}
				f.runner.OIDCOwners["app"] = "penderghast"
			},
			"client app: sensible manages it for penderghast; apply penderghast and acidburn together to move it",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				f := newOIDCFixture(t)
				tt.setup(f)

				err := f.runner.Execute(
					t.Context(),
					[]target{f.target("acidburn", &fakeAgent{}), f.target("smarts", &fakeAgent{})},
					true,
				)

				require.ErrorIs(t, err, errFailed)
				assert.Contains(t, f.out.String(), tt.want)
				assert.Empty(t, f.pocketID.clients)
			},
		)
	}
}

func TestPocketID_reportsAPIErrors(t *testing.T) {
	_, srv := newFakePocketID(t)
	p := &pocketID{url: srv.URL, key: "wrong", client: srv.Client()}

	_, err := p.Groups(t.Context())

	assert.ErrorContains(t, err, "GET /api/user-groups?pagination%5Blimit%5D=100&pagination%5Bpage%5D=1: Invalid API key")
}

func TestPrune_offersOIDCClientsNoLongerDeclared(t *testing.T) {
	f := newOIDCFixture(t)
	f.existing("old", nil, "ours")
	f.existing("kept", nil, "ours")
	f.manage("old", "ours")
	f.manage("kept", "ours")
	f.declared["acidburn"] = map[string]config.OIDCClientConfig{"kept": testClient}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", &fakeAgent{})})

	require.NoError(t, err)
	assert.Equal(t, []string{"Remove OIDC client old from acidburn? [y/N] "}, f.confirmed)
	assert.Contains(t, f.out.String(), "  ✓ acidburn: OIDC client old\n")
	assert.NotContains(t, f.pocketID.clients, "old")
	assert.Contains(t, f.pocketID.clients, "kept")
	assert.Equal(t, map[string]string{"kept": "ours"}, f.records["acidburn"])
}

func TestPrune_dropsOIDCClientsAlreadyGone(t *testing.T) {
	f := newOIDCFixture(t)
	f.manage("gone", "ours")

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", &fakeAgent{})})

	require.NoError(t, err)
	assert.Empty(t, f.records["acidburn"])
}

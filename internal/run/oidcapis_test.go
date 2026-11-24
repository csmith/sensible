package run

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/config"
)

type fakePermission struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type fakeAPI struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Resource    string           `json:"resource"`
	Permissions []fakePermission `json:"permissions"`
}

type fakeGrant struct {
	user, client                       bool
	userPermissions, clientPermissions []string
}

func (f *fakePocketID) routeAPIs(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/apis", f.listAPIs)
	mux.HandleFunc("POST /api/apis", f.createAPI)
	mux.HandleFunc("PUT /api/apis/{id}", f.api(f.renameAPI))
	mux.HandleFunc("DELETE /api/apis/{id}", f.api(f.deleteAPI))
	mux.HandleFunc("PUT /api/apis/{id}/permissions", f.api(f.setPermissions))
	mux.HandleFunc("GET /api/apis/{id}/clients", f.api(f.listGrants))
	mux.HandleFunc("PUT /api/apis/{id}/clients/{client}", f.api(f.grant))
	mux.HandleFunc("DELETE /api/apis/{id}/clients/{client}", f.api(f.revoke))
}

// api serves a request about an existing API.
func (f *fakePocketID) api(handle func(http.ResponseWriter, *http.Request, *fakeAPI)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, a := range f.apis {
			if a.ID == r.PathValue("id") {
				handle(w, r, a)
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "API not found"})
	}
}

func (f *fakePocketID) listAPIs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(
		w,
		http.StatusOK,
		map[string]any{"data": slices.Collect(maps.Values(f.apis)), "pagination": map[string]int{"totalPages": 1}},
	)
}

func (f *fakePocketID) createAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Resource string `json:"resource"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.nextID++
	a := &fakeAPI{ID: "api" + strconv.Itoa(f.nextID), Name: body.Name, Resource: body.Resource}
	f.apis[a.Resource] = a
	writeJSON(w, http.StatusCreated, a)
}

func (f *fakePocketID) renameAPI(w http.ResponseWriter, r *http.Request, a *fakeAPI) {
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	a.Name = body.Name
	writeJSON(w, http.StatusOK, a)
}

func (f *fakePocketID) deleteAPI(w http.ResponseWriter, _ *http.Request, a *fakeAPI) {
	delete(f.apis, a.Resource)
	delete(f.grants, a.ID)
	w.WriteHeader(http.StatusNoContent)
}

// setPermissions keeps the IDs of the permissions whose keys stay, and drops
// grants of those that go.
func (f *fakePocketID) setPermissions(w http.ResponseWriter, r *http.Request, a *fakeAPI) {
	var body struct {
		Permissions []fakePermission `json:"permissions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ids := map[string]string{}
	for _, p := range a.Permissions {
		ids[p.Key] = p.ID
	}
	kept := map[string]bool{}
	for i, p := range body.Permissions {
		if body.Permissions[i].ID = ids[p.Key]; body.Permissions[i].ID == "" {
			f.nextID++
			body.Permissions[i].ID = "perm" + strconv.Itoa(f.nextID)
		}
		kept[body.Permissions[i].ID] = true
	}
	a.Permissions = body.Permissions
	for client, g := range f.grants[a.ID] {
		g.userPermissions = slices.DeleteFunc(g.userPermissions, func(id string) bool { return !kept[id] })
		g.clientPermissions = slices.DeleteFunc(g.clientPermissions, func(id string) bool { return !kept[id] })
		f.grants[a.ID][client] = g
	}
	writeJSON(w, http.StatusOK, a)
}

func (f *fakePocketID) listGrants(w http.ResponseWriter, _ *http.Request, a *fakeAPI) {
	data := make([]map[string]any, 0, len(f.grants[a.ID]))
	for _, client := range slices.Sorted(maps.Keys(f.grants[a.ID])) {
		g := f.grants[a.ID][client]
		data = append(
			data,
			map[string]any{
				"client":                     map[string]string{"id": client},
				"userDelegatedAccess":        g.user,
				"clientAccess":               g.client,
				"userDelegatedPermissionIds": append([]string{}, g.userPermissions...),
				"clientPermissionIds":        append([]string{}, g.clientPermissions...),
			},
		)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "pagination": map[string]int{"totalPages": 1}})
}

func (f *fakePocketID) grant(w http.ResponseWriter, r *http.Request, a *fakeAPI) {
	client := r.PathValue("client")
	if _, ok := f.clients[client]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "OIDC client not found"})
		return
	}
	var body struct {
		UserDelegatedAccess        bool     `json:"userDelegatedAccess"`
		ClientAccess               bool     `json:"clientAccess"`
		UserDelegatedPermissionIDs []string `json:"userDelegatedPermissionIds"`
		ClientPermissionIDs        []string `json:"clientPermissionIds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if f.grants[a.ID] == nil {
		f.grants[a.ID] = map[string]fakeGrant{}
	}
	f.grants[a.ID][client] = fakeGrant{
		user:              body.UserDelegatedAccess,
		client:            body.ClientAccess,
		userPermissions:   body.UserDelegatedPermissionIDs,
		clientPermissions: body.ClientPermissionIDs,
	}
	writeJSON(w, http.StatusOK, body)
}

func (f *fakePocketID) revoke(w http.ResponseWriter, r *http.Request, a *fakeAPI) {
	delete(f.grants[a.ID], r.PathValue("client"))
	w.WriteHeader(http.StatusNoContent)
}

// grantedKeys are the keys of the permissions the client is granted on the
// API with the identifier, or nil if it can't call it as itself.
func (f *fakePocketID) grantedKeys(identifier, client string) []string {
	a := f.apis[identifier]
	g, ok := f.grants[a.ID][client]
	if !ok || !g.client {
		return nil
	}
	keys := []string{}
	for _, p := range a.Permissions {
		if slices.Contains(g.clientPermissions, p.ID) {
			keys = append(keys, p.Key)
		}
	}
	return keys
}

const testIdentifier = "https://pb.example.net"

var testAPI = config.OIDCAPIConfig{
	Name: "PocketBase",
	Permissions: map[string]config.OIDCPermissionConfig{
		"read":  {Name: "Read"},
		"write": {Name: "Write", Description: "Change records"},
	},
	Clients: map[string]config.Set{"app": {"read"}},
}

// existingAPI puts testAPI in Pocket ID with app granted it as declared,
// with settings changed by change.
func (f *oidcFixture) existingAPI(change func(a *fakeAPI)) {
	a := &fakeAPI{
		ID:       "pb",
		Name:     "PocketBase",
		Resource: testIdentifier,
		Permissions: []fakePermission{
			{ID: "p-read", Key: "read", Name: "Read"},
			{ID: "p-write", Key: "write", Name: "Write", Description: "Change records"},
		},
	}
	f.pocketID.apis[testIdentifier] = a
	f.pocketID.grants["pb"] = map[string]fakeGrant{"app": {client: true, clientPermissions: []string{"p-read"}}}
	if change != nil {
		change(a)
	}
}

// manageAPI records that sensible manages testAPI for acidburn.
func (f *oidcFixture) manageAPI() {
	f.apiRecords["acidburn"] = []string{testIdentifier}
	f.runner.OIDCAPIOwners[testIdentifier] = "acidburn"
}

func TestExecute_oidcAPIIsCreatedAndGrantedToAClientMadeInTheSameRun(t *testing.T) {
	f := newOIDCFixture(t)
	f.declared["smarts"] = map[string]config.OIDCClientConfig{"app": testClient}
	f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}

	err := f.runner.Execute(
		t.Context(),
		[]target{f.target("acidburn", &fakeAgent{}), f.target("smarts", &fakeAgent{})},
		true,
	)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "> Resolving OIDC changes\n  + client app\n  + api "+testIdentifier+"\n")
	assert.Contains(t, f.out.String(), "  ✓ client app\n  ✓ api "+testIdentifier+"\n")
	a := f.pocketID.apis[testIdentifier]
	require.NotNil(t, a)
	assert.Equal(t, "PocketBase", a.Name)
	assert.Equal(t, []string{"read"}, f.pocketID.grantedKeys(testIdentifier, "app"))
	assert.Equal(t, []string{testIdentifier}, f.apiRecords["acidburn"])
}

func TestExecute_oidcAPINeedsNoChange(t *testing.T) {
	f := newOIDCFixture(t)
	f.existing("app", nil, "ours")
	f.existingAPI(nil)
	f.manageAPI()
	f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, false)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "> Resolving OIDC changes\n  ✓ 1 unchanged\n")
}

func TestExecute_oidcAPIChangedByHandIsPutBack(t *testing.T) {
	f := newOIDCFixture(t)
	f.existing("app", nil, "ours")
	f.existing("other", nil, "ours")
	f.existing("both", nil, "ours")
	f.existing("users", nil, "ours")
	f.existingAPI(
		func(a *fakeAPI) {
			a.Name = "Renamed"
			a.Permissions[1].Name = "Write by hand"
			a.Permissions = append(a.Permissions, fakePermission{ID: "p-admin", Key: "admin", Name: "Admin"})
			f.pocketID.grants["pb"] = map[string]fakeGrant{
				"app":   {client: true, clientPermissions: []string{"p-read", "p-admin"}},
				"other": {client: true},
				"both": {
					user:              true,
					client:            true,
					userPermissions:   []string{"p-read"},
					clientPermissions: []string{"p-read"},
				},
				"users": {user: true, userPermissions: []string{"p-read"}},
			}
		},
	)
	f.manageAPI()
	api := testAPI
	api.Clients = map[string]config.Set{"app": {"read", "write"}, "both": {"read"}, "users": {"read"}}
	f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: api}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, true)

	require.NoError(t, err)
	label := "api " + testIdentifier + "  "
	assert.Contains(
		t,
		f.out.String(),
		"> Resolving OIDC changes\n"+
			"  ~ "+label+"name: Renamed → PocketBase\n"+
			"  ~ "+label+"permission write\n"+
			"  - "+label+"permission admin\n"+
			"  ~ "+label+"client app: admin, read → read, write\n"+
			"  ~ "+label+"client both: read; for users: read → read\n"+
			"  ~ "+label+"client users: for users: read → read\n"+
			"  - "+label+"client other\n",
	)
	a := f.pocketID.apis[testIdentifier]
	assert.Equal(t, "PocketBase", a.Name)
	assert.Equal(
		t,
		[]fakePermission{
			{ID: "p-read", Key: "read", Name: "Read"},
			{ID: "p-write", Key: "write", Name: "Write", Description: "Change records"},
		},
		a.Permissions,
	)
	assert.Equal(t, []string{"read", "write"}, f.pocketID.grantedKeys(testIdentifier, "app"))
	for _, client := range []string{"both", "users"} {
		assert.Equal(
			t,
			fakeGrant{client: true, userPermissions: []string{}, clientPermissions: []string{"p-read"}},
			f.pocketID.grants["pb"][client],
		)
	}
	assert.NotContains(t, f.pocketID.grants["pb"], "other")
}

func TestExecute_oidcAPIGrantsAccessOnBehalfOfUsers(t *testing.T) {
	f := newOIDCFixture(t)
	f.existing("app", nil, "ours")
	f.existing("both", nil, "ours")
	f.existing("public", map[string]any{"isPublic": true}, "ours")
	f.existingAPI(
		func(*fakeAPI) {
			f.pocketID.grants["pb"]["both"] = fakeGrant{user: true, userPermissions: []string{"p-read"}}
		},
	)
	f.manageAPI()
	api := testAPI
	api.Clients = map[string]config.Set{"app": {"read"}, "both": {"write"}}
	api.Users = map[string]config.Set{"public": {"read", "write"}, "both": {"read"}}
	f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: api}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, true)

	require.NoError(t, err)
	label := "api " + testIdentifier + "  "
	assert.Contains(
		t,
		f.out.String(),
		"> Resolving OIDC changes\n"+
			"  ~ "+label+"client both: for users: read → write; for users: read\n"+
			"  + "+label+"client public: for users: read, write\n\n",
	)
	assert.Equal(
		t,
		fakeGrant{user: true, userPermissions: []string{"p-read", "p-write"}, clientPermissions: []string{}},
		f.pocketID.grants["pb"]["public"],
	)
	assert.Equal(
		t,
		fakeGrant{
			user:              true,
			client:            true,
			userPermissions:   []string{"p-read"},
			clientPermissions: []string{"p-write"},
		},
		f.pocketID.grants["pb"]["both"],
	)
	assert.Equal(t, []string{"read"}, f.pocketID.grantedKeys(testIdentifier, "app"))
}

func TestExecute_oidcAPIMadeByHandIsTakenOver(t *testing.T) {
	f := newOIDCFixture(t)
	f.existing("app", nil, "ours")
	f.existingAPI(nil)
	f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}

	err := f.runner.Execute(t.Context(), []target{f.target("acidburn", &fakeAgent{})}, true)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "> Resolving OIDC changes\n  ~ api "+testIdentifier+"  host: none → acidburn\n")
	assert.Equal(t, []string{testIdentifier}, f.apiRecords["acidburn"])
}

func TestExecute_oidcAPIMovesBetweenHostsInTheSameRun(t *testing.T) {
	f := newOIDCFixture(t)
	f.existing("app", nil, "ours")
	f.existingAPI(nil)
	f.manageAPI()
	f.declaredAPIs["smarts"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}

	err := f.runner.Execute(
		t.Context(),
		[]target{f.target("acidburn", &fakeAgent{}), f.target("smarts", &fakeAgent{})},
		true,
	)

	require.NoError(t, err)
	assert.Contains(t, f.out.String(), "  ~ api "+testIdentifier+"  host: acidburn → smarts\n")
	assert.Empty(t, f.apiRecords["acidburn"])
	assert.Equal(t, []string{testIdentifier}, f.apiRecords["smarts"])
}

func TestExecute_oidcAPIPlanErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *oidcFixture)
		want  string
	}{
		{
			"client that doesn't exist",
			func(f *oidcFixture) {
				f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}
			},
			"api " + testIdentifier + ": no OIDC client app to grant access to",
		},
		{
			"client that can't be planned",
			func(f *oidcFixture) {
				c := testClient
				c.Groups = config.Set{"nobody"}
				f.declared["smarts"] = map[string]config.OIDCClientConfig{"app": c}
				f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}
			},
			"api " + testIdentifier + ": no OIDC client app to grant access to",
		},
		{
			"public client",
			func(f *oidcFixture) {
				f.declared["smarts"] = map[string]config.OIDCClientConfig{
					"app": {Name: "App", CallbackURLs: config.Set{"https://app.example.com/callback"}, Public: true},
				}
				f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}
			},
			"api " + testIdentifier + ": client app is public, so it can't use client credentials",
		},
		{
			"client for users that doesn't exist",
			func(f *oidcFixture) {
				api := testAPI
				api.Clients, api.Users = nil, map[string]config.Set{"app": nil}
				f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: api}
			},
			"api " + testIdentifier + ": no OIDC client app to grant access to",
		},
		{
			"declared by two hosts",
			func(f *oidcFixture) {
				f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}
				f.declaredAPIs["smarts"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}
			},
			"api " + testIdentifier + ": both acidburn and smarts declare it",
		},
		{
			"managed for a host outside the run",
			func(f *oidcFixture) {
				f.declaredAPIs["acidburn"] = map[string]config.OIDCAPIConfig{testIdentifier: testAPI}
				f.runner.OIDCAPIOwners[testIdentifier] = "penderghast"
			},
			"api " + testIdentifier + ": sensible manages it for penderghast; apply penderghast and acidburn together",
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
				assert.Empty(t, f.pocketID.apis)
			},
		)
	}
}

func TestPrune_offersOIDCAPIsNoLongerDeclared(t *testing.T) {
	f := newOIDCFixture(t)
	f.existing("app", nil, "ours")
	f.existingAPI(nil)
	f.manageAPI()

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", &fakeAgent{})})

	require.NoError(t, err)
	assert.Equal(t, []string{"Remove OIDC API " + testIdentifier + " from acidburn? [y/N] "}, f.confirmed)
	assert.Empty(t, f.pocketID.apis)
	assert.Empty(t, f.apiRecords["acidburn"])
}

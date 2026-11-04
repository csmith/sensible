package config

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCertRepo(t *testing.T) *testRepo {
	t.Helper()
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {api: , worker: }\nbeta:\n  roles: {worker: }\n",
			"roles/api/role.yml": `
certs:
  api-server:
    ca: internal
    server: [api.example.com, api]
    owner: "1000"
`,
			"roles/api/docker-compose.yml": `
services:
  api:
    volumes:
      - !cert api-server/ca.crt:/ca.crt:ro
      - !cert api-server/tls.crt:/tls.crt:ro
      - !cert api-server/tls.key:/tls.key:ro
`,
			"roles/worker/role.yml": `
certs:
  worker-client:
    ca: internal
    client: worker
    dir: /opt/worker/certs
`,
		},
	)
	tr.allowCAs(t, "internal", "other")
	return tr
}

func (tr *testRepo) allowCAs(t *testing.T, ids ...string) {
	t.Helper()
	settings, err := os.ReadFile(filepath.Join(tr.dir, "sensible.yml"))
	require.NoError(t, err)
	tr.write(t, "sensible.yml", string(settings)+"cas: ["+strings.Join(ids, ", ")+"]\n")
}

func (tr *testRepo) write(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(tr.dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func issuedCert(t *testing.T, c Config, name string) Cert {
	t.Helper()
	for _, cert := range c.IssuedCerts {
		if cert.Name == name {
			return cert
		}
	}
	require.FailNow(t, "no such certificate", name)
	return Cert{}
}

func TestHostCerts_issuedCertsAuthenticateBothWays(t *testing.T) {
	c, err := newCertRepo(t).open(t).HostConfig("alpha", "")
	require.NoError(t, err)
	server, client := issuedCert(t, c, "api-server"), issuedCert(t, c, "worker-client")

	serverPair, err := tls.X509KeyPair([]byte(server.Cert), []byte(server.Key))
	require.NoError(t, err)
	clientPair, err := tls.X509KeyPair([]byte(client.Cert), []byte(client.Key))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(server.CACert)))

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	serverSide := tls.Server(
		serverConn,
		&tls.Config{
			Certificates: []tls.Certificate{serverPair},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS13,
		},
	)
	clientSide := tls.Client(
		clientConn,
		&tls.Config{
			Certificates: []tls.Certificate{clientPair},
			RootCAs:      pool,
			ServerName:   "api.example.com",
			MinVersion:   tls.VersionTLS13,
		},
	)
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverSide.HandshakeContext(t.Context()) }()
	require.NoError(t, clientSide.HandshakeContext(t.Context()))
	require.NoError(t, <-serverDone)
	assert.Equal(t, "worker", serverSide.ConnectionState().PeerCertificates[0].Subject.CommonName)
}

func TestHostCerts_usagesKeepCertsToTheirRole(t *testing.T) {
	c, err := newCertRepo(t).open(t).HostConfig("alpha", "")
	require.NoError(t, err)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(issuedCert(t, c, "api-server").CACert)))
	verify := func(name string, usage x509.ExtKeyUsage) error {
		cert, err := parseCertPEM(issuedCert(t, c, name).Cert)
		require.NoError(t, err)
		_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}})
		return err
	}
	require.NoError(t, verify("api-server", x509.ExtKeyUsageServerAuth))
	require.Error(t, verify("api-server", x509.ExtKeyUsageClientAuth))
	require.NoError(t, verify("worker-client", x509.ExtKeyUsageClientAuth))
	require.Error(t, verify("worker-client", x509.ExtKeyUsageServerAuth))
}

func TestHostCerts_stackRefersToFiles(t *testing.T) {
	c, err := newCertRepo(t).open(t).HostConfig("alpha", "")
	require.NoError(t, err)

	require.Len(t, c.Stacks, 1)
	s := c.Stacks[0]
	dir := filepath.Join(CertsDir, "api-server")
	assert.Equal(
		t,
		[]string{filepath.Join(dir, CACertFile), filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)},
		s.CertPaths,
	)
	assert.Contains(t, stackFile(t, s, "docker-compose.yml").Content, filepath.Join(dir, KeyFile)+":/tls.key:ro")
	assert.Equal(t, "/opt/worker/certs", issuedCert(t, c, "worker-client").Dir)
}

func TestHostCerts_savedCertsAreKept(t *testing.T) {
	tr := newCertRepo(t)
	r := tr.open(t)

	first, err := r.HostConfig("alpha", "")
	require.NoError(t, err)
	again, err := r.HostConfig("alpha", "")
	require.NoError(t, err)
	assert.NotEqual(t, issuedCert(t, first, "api-server").Key, issuedCert(t, again, "api-server").Key)
	assert.Equal(t, issuedCert(t, first, "api-server").CACert, issuedCert(t, again, "api-server").CACert)

	require.NoError(t, r.SaveCerts("alpha", first.IssuedCerts))

	for name, repo := range map[string]*Repo{"same repo": r, "reopened": tr.open(t)} {
		t.Run(
			name,
			func(t *testing.T) {
				saved, err := repo.HostConfig("alpha", "")
				require.NoError(t, err)
				want := issuedCert(t, first, "api-server")
				got := issuedCert(t, saved, "api-server")
				assert.Equal(t, want.CACert, got.CACert)
				assert.Equal(t, want.Cert, got.Cert)
				assert.Equal(t, want.Key, got.Key)
				assert.False(t, got.Unsaved())
			},
		)
	}

	for _, file := range []string{caStateFile, stateFile("alpha")} {
		content, err := os.ReadFile(filepath.Join(tr.dir, file))
		require.NoError(t, err)
		assert.NotContains(t, string(content), "PRIVATE KEY", file)
	}
}

func TestHostCerts_hostsShareACA(t *testing.T) {
	tr := newCertRepo(t)
	r := tr.open(t)

	// Beta is saved alone, which must save the CA that alpha's unsaved
	// certificates also use.
	alpha, err := r.HostConfig("alpha", "")
	require.NoError(t, err)
	beta, err := r.HostConfig("beta", "")
	require.NoError(t, err)
	want := issuedCert(t, alpha, "worker-client").CACert
	assert.Equal(t, want, issuedCert(t, beta, "worker-client").CACert)

	require.NoError(t, r.SaveCerts("beta", beta.IssuedCerts))
	require.NoError(t, r.SaveCerts("alpha", alpha.IssuedCerts))

	reopened, err := tr.open(t).HostConfig("alpha", "")
	require.NoError(t, err)
	assert.Equal(t, want, issuedCert(t, reopened, "worker-client").CACert)
	assert.False(t, issuedCert(t, reopened, "worker-client").Unsaved())
}

func TestHostCerts_reissues(t *testing.T) {
	workerRole := func(cert string) func(*testing.T, *testRepo) {
		return func(t *testing.T, tr *testRepo) {
			t.Helper()
			tr.write(t, "roles/worker/role.yml", "certs:\n  worker-client: "+cert+"\n")
		}
	}
	tests := []struct {
		name   string
		change func(*testing.T, *testRepo)
		after  time.Duration
		want   bool
	}{
		{name: "nothing changed"},
		{name: "not yet due", after: certLifetime - 2*certRenewal},
		{name: "due for renewal", after: certLifetime - certRenewal/2, want: true},
		{name: "names changed", change: workerRole("{ca: internal, client: other}"), want: true},
		{name: "different CA", change: workerRole("{ca: other, client: worker}"), want: true},
		{
			name: "CA replaced",
			change: func(t *testing.T, tr *testRepo) {
				t.Helper()
				require.NoError(t, os.Remove(filepath.Join(tr.dir, caStateFile)))
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				tr := newCertRepo(t)
				r := tr.open(t)
				before, err := r.HostConfig("beta", "")
				require.NoError(t, err)
				require.NoError(t, r.SaveCerts("beta", before.IssuedCerts))

				if tt.change != nil {
					tt.change(t, tr)
				}
				reopened := tr.open(t)
				reopened.now = func() time.Time { return time.Now().Add(tt.after) }
				after, err := reopened.HostConfig("beta", "")
				require.NoError(t, err)

				got := issuedCert(t, after, "worker-client")
				assert.Equal(t, tt.want, got.Unsaved())
				assert.Equal(t, tt.want, got.Cert != issuedCert(t, before, "worker-client").Cert)
				assert.Equal(t, tt.want, got.Key != issuedCert(t, before, "worker-client").Key)
			},
		)
	}
}

func TestHostCerts_expiringCARefusesToIssue(t *testing.T) {
	tr := newCertRepo(t)
	r := tr.open(t)
	before, err := r.HostConfig("beta", "")
	require.NoError(t, err)
	require.NoError(t, r.SaveCerts("beta", before.IssuedCerts))

	later := tr.open(t)
	later.now = func() time.Time { return time.Now().Add(caLifetime - certRenewal) }
	_, err = later.HostConfig("beta", "")
	require.ErrorContains(t, err, "ca internal expires")
}

func TestHostCerts_preview(t *testing.T) {
	tr := newCertRepo(t)
	r := tr.open(t)
	r.Preview(func(string) {})

	c, err := r.HostConfig("alpha", "")
	require.NoError(t, err)
	cert := issuedCert(t, c, "api-server")
	assert.False(t, cert.Unsaved())
	assert.Equal(t, 0, tr.fetches, "previewing shouldn't need the identity")
	assert.NoFileExists(t, filepath.Join(tr.dir, caStateFile))
	require.NoError(t, r.SaveCerts("alpha", c.IssuedCerts))
	assert.NoFileExists(t, filepath.Join(tr.dir, caStateFile))
	assert.NoFileExists(t, filepath.Join(tr.dir, stateFile("alpha")))
}

func TestHostCerts_fromAPartial(t *testing.T) {
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml": "alpha:\n  roles: {web: }\n",
			"partials/tls/partial.yml": `
params:
  host: ~
certs:
  "{stack}-tls":
    ca: internal
    server: ["{host}"]
`,
			"partials/tls/docker-compose.yml": `
services:
  proxy:
    volumes:
      - !cert "{stack}-tls/tls.key:/tls.key:ro"
`,
			"roles/web/role.yml": `
partials:
  - {partial: tls, host: web.example.com}
compose:
  env:
    CA_PATH: !cert web-tls/ca.crt
`,
		},
	)
	tr.allowCAs(t, "internal")

	c, err := tr.open(t).HostConfig("alpha", "")
	require.NoError(t, err)

	cert, err := parseCertPEM(issuedCert(t, c, "web-tls").Cert)
	require.NoError(t, err)
	assert.Equal(t, []string{"web.example.com"}, cert.DNSNames)
	dir := filepath.Join(CertsDir, "web-tls")
	require.Len(t, c.Stacks, 1)
	assert.Contains(t, stackFile(t, c.Stacks[0], "docker-compose.yml").Content, filepath.Join(dir, KeyFile)+":/tls.key:ro")
	assert.Contains(t, stackFile(t, c.Stacks[0], ".env").Content, "CA_PATH='"+filepath.Join(dir, CACertFile)+"'")
	assert.ElementsMatch(t, []string{filepath.Join(dir, KeyFile), filepath.Join(dir, CACertFile)}, c.Stacks[0].CertPaths)
}

func TestHostCerts_invalid(t *testing.T) {
	tests := []struct {
		name    string
		role    string
		compose string
		want    string
	}{
		{name: "unknown CA", role: "certs: {a: {ca: nope, client: c}}", want: `ca "nope" isn't in`},
		{name: "no purpose", role: "certs: {a: {ca: internal}}", want: "needs server, client or both"},
		{name: "bad name", role: `certs: {"a/b": {ca: internal, client: c}}`, want: "a certificate's name"},
		{name: "bad server name", role: `certs: {a: {ca: internal, server: ["no spaces"]}}`, want: "isn't a DNS name"},
		{name: "relative dir", role: "certs: {a: {ca: internal, client: c, dir: certs}}", want: "must be an absolute path"},
		{name: "root dir", role: "certs: {a: {ca: internal, client: c, dir: /}}", want: "must be an absolute path"},
		{
			name: "shared dir",
			role: "certs: {a: {ca: internal, client: c, dir: /x}, b: {ca: internal, client: c, dir: /x/}}",
			want: "would both be written to /x",
		},
		{name: "unknown setting", role: "certs: {a: {ca: internal, client: c, mode: 0600}}", want: "mode"},
		{
			name:    "unknown certificate",
			role:    "certs: {a: {ca: internal, client: c}}",
			compose: "services: {s: {volumes: [!cert b/tls.key]}}",
			want:    `certificate "b" isn't in`,
		},
		{
			name:    "unknown file",
			role:    "certs: {a: {ca: internal, client: c}}",
			compose: "services: {s: {volumes: [!cert a/other.pem]}}",
			want:    "needs a certificate's name and one of",
		},
		{
			name: "tag outside a stack",
			role: "certs: {a: {ca: internal, client: c}}\nbackups: {b: {path: !cert a/tls.key}}",
			want: "!cert only works in",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				files := map[string]string{
					"hosts.d/hosts.yml":  "alpha:\n  roles: {web: }\n",
					"roles/web/role.yml": tt.role,
				}
				if tt.compose != "" {
					files["roles/web/docker-compose.yml"] = tt.compose
				}
				tr := newTestRepo(t, files)
				tr.allowCAs(t, "internal")

				r, err := tr.tryOpen()
				if err == nil {
					_, err = r.HostConfig("alpha", "")
				}
				require.ErrorContains(t, err, tt.want)
			},
		)
	}
}

func TestHostConfig_rolesCantDisagreeAboutACert(t *testing.T) {
	tr := newTestRepo(
		t,
		map[string]string{
			"hosts.d/hosts.yml":  "alpha:\n  roles: {one: , two: }\n",
			"roles/one/role.yml": "certs: {a: {ca: internal, client: one}}\n",
			"roles/two/role.yml": "certs: {a: {ca: internal, client: two}}\n",
		},
	)
	tr.allowCAs(t, "internal")

	_, err := tr.open(t).HostConfig("alpha", "")
	require.ErrorContains(t, err, "certs.a.client differently")
}

func TestReadSettings_rejectsBadCANames(t *testing.T) {
	_, err := newTestRepo(t, map[string]string{"sensible.yml": "cas: [\"a/b\"]\n"}).tryOpen()
	require.ErrorContains(t, err, `"a/b"`)
}

package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/goccy/go-yaml/ast"
)

const (
	// CertsDir holds each certificate that doesn't set its own dir, in a
	// directory named after it.
	CertsDir = "/srv/certs"

	// The files written for each certificate.
	CACertFile = "ca.crt"
	CertFile   = "tls.crt"
	KeyFile    = "tls.key"

	certTag     = "!cert"
	caStateFile = "ca.state.yml"

	caLifetime   = 10 * 365 * 24 * time.Hour
	certLifetime = 365 * 24 * time.Hour
	// certRenewal is how long before it expires a certificate is replaced.
	// Certificates are only checked when a host is applied, so it's long
	// enough to survive a host not being touched for a while.
	certRenewal = 90 * 24 * time.Hour
	// clockSkew backdates certificates, for hosts whose clocks are behind.
	clockSkew = time.Hour
)

// CertConfig is a certificate a role or partial asks for on a host.
type CertConfig struct {
	// CA is one of sensible.yml's cas.
	CA string `yaml:"ca"`
	// Server makes it a server certificate for these DNS names.
	Server Set `yaml:"server"`
	// Client makes it a client certificate with this common name.
	Client string `yaml:"client"`
	// Dir is where its files are written, rather than under CertsDir. Files
	// that are no longer wanted are removed from it, but nothing else is.
	Dir string `yaml:"dir"`
	// Owner and Group are treated as they are for a file, and also apply to
	// Dir. The private key is only readable by Owner.
	Owner string `yaml:"owner"`
	Group string `yaml:"group"`
	// Reload and Restart are systemd units that use it, acted on when its
	// files change. A unit in both is only restarted.
	Reload  Set `yaml:"reload"`
	Restart Set `yaml:"restart"`
}

// Cert is a certificate as it's written to a host.
type Cert struct {
	Name         string
	Dir          string
	Owner, Group string
	// Reload and Restart are as for CertConfig, without overlap.
	Reload, Restart []string
	// CACert, Cert and Key are PEM encoded. In a Repo set to Preview, they
	// may be placeholders.
	CACert, Cert, Key string
	ca                string
	// unsaved is set when it's newly issued, so Repo.SaveCerts must save it
	// before it's deployed.
	unsaved bool
}

// Unsaved reports whether the certificate needs saving with Repo.SaveCerts.
func (c Cert) Unsaved() bool { return c.unsaved }

// savedCert is a certificate or CA in a state file.
type savedCert struct {
	Cert string `yaml:"cert"`
	Key  Secret `yaml:"key"`
}

func (s savedCert) yaml(prefix string) string {
	var out strings.Builder
	out.WriteString(prefix + "cert: |")
	for line := range strings.Lines(s.Cert) {
		out.WriteString("\n" + prefix + "  " + strings.TrimRight(line, "\n"))
	}
	out.WriteString("\n" + prefix + "key: " + indent(s.Key.yaml(), prefix) + "\n")
	return out.String()
}

// hostCerts gives the host's certificates, issuing those that are missing,
// close to expiry or no longer match their config.
func (r *Repo) hostCerts(name string, configs map[string]CertConfig) ([]Cert, error) {
	var certs []Cert
	dirs := map[string]string{}
	for _, certName := range slices.Sorted(maps.Keys(configs)) {
		cert, err := r.hostCert(name, certName, configs[certName])
		if err != nil {
			return nil, fmt.Errorf("certs: %s: %w", certName, err)
		}
		if other, ok := dirs[cert.Dir]; ok {
			return nil, fmt.Errorf("certs: %s and %s would both be written to %s", other, certName, cert.Dir)
		}
		dirs[cert.Dir] = certName
		certs = append(certs, cert)
	}
	return certs, nil
}

func (r *Repo) hostCert(host, name string, cfg CertConfig) (Cert, error) {
	if !generatedName.MatchString(name) {
		return Cert{}, errors.New("a certificate's name must be letters, digits, \"-\" and \"_\"")
	}
	dir, err := certDir(name, cfg.Dir)
	if err != nil {
		return Cert{}, err
	}
	spec, err := newCertSpec(cfg)
	if err != nil {
		return Cert{}, err
	}
	ca, err := r.authority(cfg.CA)
	if err != nil {
		return Cert{}, err
	}
	out := Cert{
		Name:  name,
		Dir:   dir,
		Owner: cfg.Owner,
		Group: cfg.Group,
		Reload: slices.DeleteFunc(
			slices.Clone(cfg.Reload),
			func(u string) bool { return slices.Contains(cfg.Restart, u) },
		),
		Restart: cfg.Restart,
		ca:      cfg.CA,
	}

	now := r.now()
	saved, ok := r.inventory.Hosts[host].Certs[name]
	if ok && ca != nil {
		current, err := ca.isCurrent(saved.Cert, spec, now)
		if err != nil {
			return Cert{}, err
		}
		if current {
			out.CACert, out.Cert = ca.certPEM, saved.Cert
			out.Key, err = saved.Key.Reveal()
			return out, err
		}
	}
	if r.keys.preview {
		out.CACert, out.Cert, out.Key = "<ca:"+cfg.CA+">\n", "<cert:"+name+">\n", "<key:"+name+">\n"
		if ca != nil {
			out.CACert = ca.certPEM
		}
		return out, nil
	}
	out.CACert = ca.certPEM
	out.Cert, out.Key, err = ca.issue(spec, now)
	out.unsaved = true
	return out, err
}

func certDir(name, dir string) (string, error) {
	if dir == "" {
		return filepath.Join(CertsDir, name), nil
	}
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(clean) || clean == "/" {
		return "", fmt.Errorf("dir %q must be an absolute path to a directory other than /", dir)
	}
	return clean, nil
}

// certSpec is what a certificate must say to match its config.
type certSpec struct {
	commonName string
	dnsNames   []string
	usages     []x509.ExtKeyUsage
}

func newCertSpec(cfg CertConfig) (certSpec, error) {
	var s certSpec
	for _, name := range cfg.Server {
		norm := normaliseName(name)
		invalid := func(l string) bool { return !domainLabel.MatchString(l) }
		if slices.ContainsFunc(strings.Split(norm, "."), invalid) {
			return certSpec{}, fmt.Errorf("server: %q isn't a DNS name", name)
		}
		s.dnsNames = append(s.dnsNames, norm)
	}
	slices.Sort(s.dnsNames)
	s.dnsNames = slices.Compact(s.dnsNames)

	if len(s.dnsNames) > 0 {
		s.commonName = s.dnsNames[0]
		s.usages = append(s.usages, x509.ExtKeyUsageServerAuth)
	}
	if cfg.Client != "" {
		s.commonName = cfg.Client
		s.usages = append(s.usages, x509.ExtKeyUsageClientAuth)
	}
	if len(s.usages) == 0 {
		return certSpec{}, errors.New("needs server, client or both")
	}
	return s, nil
}

// authority is a CA that can sign certificates.
type authority struct {
	id      string
	cert    *x509.Certificate
	certPEM string
	// key is its encrypted private key, once saved.
	key Secret
	// newKey is its PEM encoded private key, until it's saved.
	newKey string
}

// authority gives the named CA, creating it if it doesn't exist yet. A new
// CA is shared by every host in the run, and saved by the first to be
// applied. In a Repo set to Preview, a CA that doesn't exist is nil.
func (r *Repo) authority(id string) (*authority, error) {
	if !slices.Contains(r.caNames, id) {
		return nil, fmt.Errorf("ca %q isn't in sensible.yml's cas", id)
	}
	if a, ok := r.authorities[id]; ok {
		return a, nil
	}
	var a *authority
	if saved, ok := r.cas[id]; ok {
		cert, err := parseCertPEM(saved.Cert)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", r.path(caStateFile), id, err)
		}
		a = &authority{id: id, cert: cert, certPEM: saved.Cert, key: saved.Key}
	} else if r.keys.preview {
		return nil, nil
	} else {
		var err error
		if a, err = newAuthority(id, r.now()); err != nil {
			return nil, fmt.Errorf("creating ca %s: %w", id, err)
		}
	}
	if r.authorities == nil {
		r.authorities = map[string]*authority{}
	}
	r.authorities[id] = a
	return a, nil
}

func newAuthority(id string, now time.Time) (*authority, error) {
	key, keyPEM, err := newKey()
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{id: id, cert: cert, certPEM: certPEM(der), newKey: keyPEM}, nil
}

// isCurrent reports whether certificate is one this CA signed, says what
// spec asks for, and isn't due for renewal.
func (a *authority) isCurrent(certificate string, spec certSpec, now time.Time) (bool, error) {
	cert, err := parseCertPEM(certificate)
	if err != nil {
		return false, err
	}
	return cert.CheckSignatureFrom(a.cert) == nil &&
		now.Add(certRenewal).Before(cert.NotAfter) &&
		cert.Subject.CommonName == spec.commonName &&
		slices.Equal(cert.DNSNames, spec.dnsNames) &&
		slices.Equal(cert.ExtKeyUsage, spec.usages), nil
}

func (a *authority) issue(spec certSpec, now time.Time) (certificate, privateKey string, err error) {
	// It wouldn't outlive the renewal window, so would be reissued every run.
	if a.cert.NotAfter.Before(now.Add(2 * certRenewal)) {
		return "", "", fmt.Errorf(
			"ca %s expires at %s, so can't issue more certificates; remove it from %s to create a new one",
			a.id,
			a.cert.NotAfter.Format(time.RFC3339),
			caStateFile,
		)
	}
	signer, err := a.signer()
	if err != nil {
		return "", "", err
	}
	key, keyPEM, err := newKey()
	if err != nil {
		return "", "", err
	}
	serial, err := newSerial()
	if err != nil {
		return "", "", err
	}
	notAfter := now.Add(certLifetime)
	if a.cert.NotAfter.Before(notAfter) {
		notAfter = a.cert.NotAfter
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		&x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: spec.commonName},
			DNSNames:     spec.dnsNames,
			NotBefore:    now.Add(-clockSkew),
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  spec.usages,
		},
		a.cert,
		key.Public(),
		signer,
	)
	if err != nil {
		return "", "", err
	}
	return certPEM(der), keyPEM, nil
}

func (a *authority) signer() (crypto.Signer, error) {
	keyPEM := a.newKey
	if keyPEM == "" {
		var err error
		if keyPEM, err = a.key.Reveal(); err != nil {
			return nil, fmt.Errorf("ca %s: %w", a.id, err)
		}
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("ca %s: its key isn't PEM encoded", a.id)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca %s: %w", a.id, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ca %s: its key can't sign", a.id)
	}
	return signer, nil
}

func newKey() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func parseCertPEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("certificate isn't PEM encoded")
	}
	return x509.ParseCertificate(block.Bytes)
}

// SaveCerts encrypts the host's newly issued certificates into its state
// file, along with any new CAs that signed them.
func (r *Repo) SaveCerts(name string, certs []Cert) error {
	if err := r.checkHost(name); err != nil {
		return err
	}
	issued := map[string]savedCert{}
	for _, c := range certs {
		if !c.unsaved {
			continue
		}
		if err := r.saveAuthority(c.ca); err != nil {
			return err
		}
		key, err := r.encryptSecret(c.Key)
		if err != nil {
			return err
		}
		issued[c.Name] = savedCert{Cert: c.Cert, Key: key}
	}
	if len(issued) == 0 {
		return nil
	}
	return r.updateState(
		name,
		func(s *hostState) {
			if s.Certs == nil {
				s.Certs = map[string]savedCert{}
			}
			maps.Copy(s.Certs, issued)
		},
	)
}

func (r *Repo) saveAuthority(id string) error {
	a := r.authorities[id]
	if a == nil || a.newKey == "" {
		return nil
	}
	key, err := r.encryptSecret(a.newKey)
	if err != nil {
		return err
	}
	if r.cas == nil {
		r.cas = map[string]savedCert{}
	}
	r.cas[id] = savedCert{Cert: a.certPEM, Key: key}

	var out strings.Builder
	out.WriteString("# Managed by sensible. Local changes will be overwritten.\n")
	for _, id := range slices.Sorted(maps.Keys(r.cas)) {
		out.WriteString(id + ":\n" + r.cas[id].yaml("  "))
	}
	if err := writeAtomic(r.path(caStateFile), []byte(out.String()), 0o600); err != nil {
		return err
	}
	a.key, a.newKey = key, ""
	return nil
}

func (r *Repo) readCAs() error {
	node, err := r.readLayer(caStateFile, true)
	if err != nil || node == nil {
		return err
	}
	if err := decode(r.keys.context(), node, &r.cas); err != nil {
		return fmt.Errorf("%s: %w", r.path(caStateFile), err)
	}
	return nil
}

// certPath resolves a !cert tag: a certificate's name and one of its files,
// optionally followed by the rest of a mount.
func (c *composeRenderer) certPath(tag *ast.TagNode) (string, error) {
	v, ok := tag.Value.(*ast.StringNode)
	if !ok {
		return "", nodeError(tag, "!cert needs a certificate's name and file, e.g. name/"+CertFile)
	}
	ref, rest, mount := strings.Cut(v.Value, ":")
	name, file, ok := strings.Cut(ref, "/")
	if !ok || !slices.Contains([]string{CACertFile, CertFile, KeyFile}, file) {
		return "", nodeError(
			tag,
			fmt.Sprintf("%q needs a certificate's name and one of %s, %s and %s", ref, CACertFile, CertFile, KeyFile),
		)
	}
	i := slices.IndexFunc(c.certs, func(cert Cert) bool { return cert.Name == name })
	if i < 0 {
		return "", nodeError(tag, fmt.Sprintf("certificate %q isn't in this host's certs", name))
	}
	path := filepath.Join(c.certs[i].Dir, file)
	if !slices.Contains(c.certPaths, path) {
		c.certPaths = append(c.certPaths, path)
	}
	if mount {
		path += ":" + rest
	}
	return path, nil
}

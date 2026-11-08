package config

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/goccy/go-yaml/ast"
)

const (
	ageTag       = "!age"
	generatedTag = "!generated"
)

// Secret is an age-encrypted value, written in YAML as a scalar tagged !age.
// Plain scalars are rejected when loading.
type Secret struct {
	armored string
	keys    *keyring
}

// Reveal decrypts the secret, fetching the identity the first time any
// secret from the same Repo is revealed. In a Repo set to Preview, a secret
// that can't be decrypted reveals its Placeholder.
func (s Secret) Reveal() (string, error) {
	if s.IsZero() {
		return "", errors.New("secret is not set")
	}
	if s.keys == nil {
		return "", errors.New("secret was not loaded from a repo")
	}
	identity, err := s.keys.identity()
	if err != nil {
		if s.keys.preview {
			return s.Placeholder(), nil
		}
		return "", err
	}
	plain, err := s.decrypt(identity)
	if err != nil && s.keys.preview {
		s.keys.warn(fmt.Sprintf("%s: %v", s.Placeholder(), err))
		return s.Placeholder(), nil
	}
	return plain, err
}

// Placeholder stands in for the secret's value when it can't be decrypted.
// It's derived from the ciphertext, so it's the same wherever the secret is
// written and changes only when the secret is re-encrypted.
func (s Secret) Placeholder() string {
	ciphertext, err := io.ReadAll(armor.NewReader(strings.NewReader(s.armored)))
	if err != nil {
		ciphertext = []byte(s.armored)
	}
	sum := sha256.Sum256(ciphertext)
	return fmt.Sprintf("<age:%x>", sum[:4])
}

func (s Secret) IsZero() bool { return s.armored == "" }

// UnmarshalYAML accepts a scalar tagged !age holding an armored age file.
func (s *Secret) UnmarshalYAML(ctx context.Context, node ast.Node) error {
	if node.Type() == ast.NullType {
		*s = Secret{}
		return nil
	}
	tag, ok := node.(*ast.TagNode)
	if !ok || tag.Start.Value != ageTag {
		return nodeError(node, "secrets must be encrypted: replace the value with the output of `sensible secret encrypt`")
	}
	var value string
	switch v := tag.Value.(type) {
	case *ast.StringNode:
		value = v.Value
	case *ast.LiteralNode:
		value = v.Value.Value
	}
	armored := strings.TrimSpace(value)
	if !strings.HasPrefix(armored, armor.Header) || !strings.HasSuffix(armored, armor.Footer) {
		return nodeError(node, "an !age value must be an ASCII-armored age file")
	}
	keys, _ := ctx.Value(keyringKey{}).(*keyring)
	*s = Secret{armored: armored + "\n", keys: keys}
	return nil
}

func (s Secret) decrypt(identity age.Identity) (string, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(s.armored)), identity)
	if err != nil {
		return "", fmt.Errorf("decrypting secret: %w", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("decrypting secret: %w", err)
	}
	return string(b), nil
}

// Value is a plain scalar, or a Secret.
type Value struct {
	plain  string
	secret Secret
}

func (v *Value) UnmarshalYAML(ctx context.Context, node ast.Node) error {
	if tag, ok := node.(*ast.TagNode); ok && tag.Start.Value == ageTag {
		*v = Value{}
		return v.secret.UnmarshalYAML(ctx, node)
	}
	scalar, ok := node.(ast.ScalarNode)
	if !ok || node.Type() == ast.NullType || node.Type() == ast.TagType {
		return nodeError(node, "expected a scalar or an !age secret")
	}
	*v = Value{plain: scalarValue(scalar)}
	return nil
}

func (v Value) reveal() (value string, secret bool, err error) {
	if v.secret.IsZero() {
		return v.plain, false, nil
	}
	value, err = v.secret.Reveal()
	return value, true, err
}

var (
	generatedName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	generatedRef  = regexp.MustCompile(`^([A-Za-z0-9_-]+)(?: +([0-9]+))?$`)
)

// generatedLength is how long a !generated value is when its tag doesn't ask
// for more: the length of rand.Text.
const generatedLength = 26

// parseGenerated reads a !generated tag's name and the length it asks for,
// which is zero when it doesn't give one.
func parseGenerated(tag *ast.TagNode) (string, int, error) {
	v, ok := tag.Value.(*ast.StringNode)
	var m []string
	if ok {
		m = generatedRef.FindStringSubmatch(v.Value)
	}
	if m == nil {
		return "", 0, nodeError(
			tag,
			"!generated needs a name of letters, digits, \"-\" and \"_\", and optionally a length after a space",
		)
	}
	if m[2] == "" {
		return m[1], 0, nil
	}
	length, err := strconv.Atoi(m[2])
	if err != nil || length < 1 || length > 1024 {
		return "", 0, nodeError(tag, "a !generated length must be from 1 to 1024")
	}
	return m[1], length, nil
}

// generator gives the values of a stack's !generated tags on one host:
// those saved in the host's state, and new ones for names it hasn't saved.
type generator struct {
	saved  map[string]Secret
	values map[string]string
	// lengths are the lengths the tags asked for, by name.
	lengths map[string]int
	// preview gives names that aren't saved a placeholder instead of a new
	// value.
	preview bool
	// created are the new values, which must be saved before they're used.
	created map[string]string
}

func (g *generator) value(tag *ast.TagNode) (string, error) {
	name, length, err := parseGenerated(tag)
	if err != nil {
		return "", err
	}
	if value, ok := g.values[name]; ok {
		if g.lengths[name] != length {
			return "", nodeError(tag, fmt.Sprintf("generated value %s is used with different lengths", name))
		}
		return value, nil
	}
	if g.values == nil {
		g.values = map[string]string{}
		g.lengths = map[string]int{}
	}
	g.lengths[name] = length
	if s, ok := g.saved[name]; ok {
		value, err := s.Reveal()
		if err != nil {
			return "", nodeError(tag, fmt.Sprintf("generated value %s: %v", name, err))
		}
		if len(value) < length {
			return "", nodeError(
				tag,
				fmt.Sprintf(
					"generated value %s is saved with %d characters, fewer than the %d asked for; use a new name to generate another",
					name,
					len(value),
					length,
				),
			)
		}
		g.values[name] = value
		return value, nil
	}
	if g.preview {
		g.values[name] = "<generated:" + name + ">"
		return g.values[name], nil
	}
	if g.created == nil {
		g.created = map[string]string{}
	}
	g.values[name] = generate(length)
	g.created[name] = g.values[name]
	return g.values[name], nil
}

// generate makes a random value of length characters, or of
// generatedLength if that's longer.
func generate(length int) string {
	length = max(length, generatedLength)
	var b strings.Builder
	for b.Len() < length {
		b.WriteString(rand.Text())
	}
	return b.String()[:length]
}

func nodeError(node ast.Node, msg string) error {
	pos := node.GetToken().Position
	return fmt.Errorf("[%d:%d] %s", pos.Line, pos.Column, msg)
}

// Encrypt encrypts plaintext to the inventory's recipients, returning the
// YAML text for a !age scalar.
func (r *Repo) Encrypt(plaintext string) (string, error) {
	s, err := r.encryptSecret(plaintext)
	if err != nil {
		return "", err
	}
	return s.yaml(), nil
}

// EncryptFile encrypts plaintext to the inventory's recipients, returning an
// ASCII-armored age file.
func (r *Repo) EncryptFile(plaintext string) (string, error) {
	s, err := r.encryptSecret(plaintext)
	return s.armored, err
}

func (r *Repo) encryptSecret(plaintext string) (Secret, error) {
	if len(r.recipients) == 0 {
		return Secret{}, errors.New("no secrets.recipients in sensible.yml")
	}
	var buf bytes.Buffer
	a := armor.NewWriter(&buf)
	w, err := age.Encrypt(a, r.recipients...)
	if err != nil {
		return Secret{}, err
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return Secret{}, err
	}
	if err := w.Close(); err != nil {
		return Secret{}, err
	}
	if err := a.Close(); err != nil {
		return Secret{}, err
	}
	return Secret{armored: buf.String(), keys: r.keys}, nil
}

func (s Secret) yaml() string {
	var out strings.Builder
	out.WriteString(ageTag + " |")
	for line := range strings.Lines(s.armored) {
		out.WriteString("\n  " + strings.TrimRight(line, "\n"))
	}
	return out.String()
}

// LoadIdentity fetches the identity now, rather than when the first secret
// is revealed.
func (r *Repo) LoadIdentity() error {
	_, err := r.keys.identity()
	return err
}

// Preview makes secrets that can't be decrypted, and unsaved !generated
// values, render as placeholders. warn is told why secrets can't be.
func (r *Repo) Preview(warn func(string)) {
	r.keys.preview = true
	r.keys.notify = warn
}

// keyring fetches a Repo's identity once, when the first secret is revealed.
type keyring struct {
	source  IdentitySource
	preview bool
	notify  func(string)

	mu      sync.Mutex
	fetched bool
	id      age.Identity
	err     error
	warned  map[string]bool
}

func (k *keyring) warn(msg string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.warnLocked(msg)
}

func (k *keyring) warnLocked(msg string) {
	if k.notify == nil || k.warned[msg] {
		return
	}
	if k.warned == nil {
		k.warned = map[string]bool{}
	}
	k.warned[msg] = true
	k.notify(msg)
}

type keyringKey struct{}

func (k *keyring) context() context.Context {
	return context.WithValue(context.Background(), keyringKey{}, k)
}

func (k *keyring) identity() (age.Identity, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.fetched {
		k.fetched = true
		k.id, k.err = k.source()
		if k.err != nil {
			k.err = fmt.Errorf("fetching age identity: %w", k.err)
			if k.preview {
				k.warnLocked(k.err.Error() + "; secrets are shown as placeholders")
			}
		}
	}
	return k.id, k.err
}

// IdentitySource provides the age identity used to decrypt secrets. A Repo
// calls it at most once, and only if a secret is revealed.
type IdentitySource func() (age.Identity, error)

// CommandIdentity runs sensible.yml's secrets.identity_command and parses its
// output as an age identity.
func (r *Repo) CommandIdentity() IdentitySource {
	if len(r.identityCommand) == 0 {
		return func() (age.Identity, error) {
			return nil, errors.New("no secrets.identity_command in sensible.yml")
		}
	}
	return commandIdentity(r.identityCommand[0], r.identityCommand[1:]...)
}

func commandIdentity(name string, args ...string) IdentitySource {
	return func() (age.Identity, error) {
		// The command gets no terminal, as the caller may be drawing on it.
		// Anything it needs to ask must be asked some other way, such as a
		// desktop prompt.
		cmd := exec.CommandContext(context.Background(), name, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return nil, fmt.Errorf("running %s: %w: %s", name, err, msg)
			}
			return nil, fmt.Errorf("running %s: %w", name, err)
		}
		ids, err := age.ParseIdentities(bytes.NewReader(out))
		if err != nil {
			return nil, fmt.Errorf("parsing output of %s: %w", name, err)
		}
		if len(ids) != 1 {
			return nil, fmt.Errorf("expected one identity from %s, got %d", name, len(ids))
		}
		return ids[0], nil
	}
}

func (r *Repo) readSettings() error {
	type settingsFile struct {
		Secrets struct {
			// Recipients are age public keys; secrets are encrypted to all of them.
			Recipients []string `yaml:"recipients"`
			// IdentityCommand prints the age identity, e.g. [op, read, op://...].
			IdentityCommand []string `yaml:"identity_command"`
		} `yaml:"secrets"`
		DNS  DNSSettings  `yaml:"dns"`
		OIDC OIDCSettings `yaml:"oidc"`
		// CAs are the certificate authorities that certs may name.
		CAs []string `yaml:"cas"`
	}

	file := r.path("sensible.yml")
	node, err := r.readLayer("sensible.yml", true)
	if err != nil || node == nil {
		return err
	}
	var s settingsFile
	if err := decode(r.keys.context(), node, &s); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	if len(s.Secrets.Recipients) > 0 {
		r.recipients, err = age.ParseRecipients(strings.NewReader(strings.Join(s.Secrets.Recipients, "\n")))
		if err != nil {
			return fmt.Errorf("%s: secrets.recipients: %w", file, err)
		}
	}
	r.identityCommand = s.Secrets.IdentityCommand
	if err := s.DNS.check(); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for i, rec := range s.DNS.Vhosts {
		s.DNS.Vhosts[i].Type = strings.ToUpper(rec.Type)
	}
	r.dns = s.DNS
	if err := s.OIDC.check(); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	s.OIDC.PocketID.URL = strings.TrimSuffix(s.OIDC.PocketID.URL, "/")
	r.oidc = s.OIDC
	for _, id := range s.CAs {
		if !generatedName.MatchString(id) {
			return fmt.Errorf("%s: cas: %q must be letters, digits, \"-\" and \"_\"", file, id)
		}
	}
	r.caNames = s.CAs
	return nil
}

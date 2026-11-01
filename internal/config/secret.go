package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/goccy/go-yaml/ast"
)

const ageTag = "!age"

// Secret is an age-encrypted value, written in YAML as a scalar tagged !age.
// Plain scalars are rejected when loading.
type Secret struct {
	armored string
	keys    *keyring
}

// Reveal decrypts the secret, fetching the identity the first time any
// secret from the same Repo is revealed.
func (s Secret) Reveal() (string, error) {
	if s.IsZero() {
		return "", errors.New("secret is not set")
	}
	if s.keys == nil {
		return "", errors.New("secret was not loaded from a repo")
	}
	identity, err := s.keys.identity()
	if err != nil {
		return "", err
	}
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

// keyring fetches a Repo's identity once, when the first secret is revealed.
type keyring struct {
	source IdentitySource

	mu      sync.Mutex
	fetched bool
	id      age.Identity
	err     error
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
		DNS DNSCredentials `yaml:"dns"`
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
	r.dns = s.DNS
	return nil
}

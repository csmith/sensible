package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	if len(r.recipients) == 0 {
		return "", errors.New("no secrets.recipients in hosts.yml")
	}
	var buf bytes.Buffer
	a := armor.NewWriter(&buf)
	w, err := age.Encrypt(a, r.recipients...)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := a.Close(); err != nil {
		return "", err
	}

	var out strings.Builder
	out.WriteString(ageTag + " |")
	for line := range strings.Lines(buf.String()) {
		out.WriteString("\n  " + strings.TrimRight(line, "\n"))
	}
	return out.String(), nil
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

// OnePasswordIdentity reads the identity with `op read <ref>`.
func OnePasswordIdentity(ref string) IdentitySource {
	return commandIdentity("op", "read", ref)
}

func commandIdentity(name string, args ...string) IdentitySource {
	return func() (age.Identity, error) {
		cmd := exec.CommandContext(context.Background(), name, args...)
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
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

func (r *Repo) defaultIdentity() IdentitySource {
	ref := r.inventory.Secrets.Identity
	if ref == "" {
		return func() (age.Identity, error) {
			return nil, errors.New("no secrets.identity in hosts.yml")
		}
	}
	return OnePasswordIdentity(ref)
}

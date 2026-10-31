package config

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"golang.org/x/crypto/ssh"
)

// Inventory is the parsed hosts.yml.
type Inventory struct {
	Hosts map[string]HostEntry `yaml:"hosts"`
}

type HostEntry struct {
	// Address is the host's public or LAN address. Empty for the local host.
	Address string `yaml:"address"`
	// HostKeys are the host's SSH public keys, which connections must match.
	HostKeys []HostKey `yaml:"host_keys"`
}

// HostKey is an SSH public key written as in authorized_keys.
type HostKey struct {
	ssh.PublicKey
}

func (k *HostKey) UnmarshalText(b []byte) error {
	key, _, _, rest, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return fmt.Errorf("invalid host key %q: %w", b, err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("invalid host key %q: expected a single key", b)
	}
	k.PublicKey = key
	return nil
}

func (k HostKey) String() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey)))
}

// Credentials are the generated contents of credentials/<host>.yml.
type Credentials struct {
	// SSHKey is an OpenSSH-format private key.
	SSHKey       Secret    `yaml:"ssh_key"`
	SudoPassword Secret    `yaml:"sudo_password"`
	Rotated      time.Time `yaml:"rotated"`
}

// Config is one host's merged configuration: built-in defaults, all.yml,
// os/<family>.yml, then hosts/<name>.yml.
type Config struct {
	Packages  PackagesConfig        `yaml:"packages"`
	AUR       AURConfig             `yaml:"aur"`
	Users     map[string]UserConfig `yaml:"users"`
	Sudoers   map[string][]string   `yaml:"sudoers"`
	PamRSSH   PamRSSHConfig         `yaml:"pam_rssh"`
	SSHD      SSHDConfig            `yaml:"sshd"`
	Tailscale TailscaleConfig       `yaml:"tailscale"`
	Zsh       ZshConfig             `yaml:"zsh"`
	Docker    DockerConfig          `yaml:"docker"`
	DNS       DNSConfig             `yaml:"dns"`
}

type PackagesConfig struct {
	Install []string `yaml:"install"`
	// Remove is applied before Install, so replacements can be installed.
	Remove []string `yaml:"remove"`
}

type AURConfig struct {
	Packages []string `yaml:"packages"`
}

type UserConfig struct {
	Shell   string   `yaml:"shell"`
	Groups  []string `yaml:"groups"`
	SSHKeys []string `yaml:"ssh_keys"`
}

type PamRSSHConfig struct {
	Keys []string `yaml:"keys"`
}

type SSHDConfig struct {
	Enabled  bool              `yaml:"enabled"`
	Settings map[string]string `yaml:"settings"`
}

type TailscaleConfig struct {
	Settings map[string]string `yaml:"settings"`
}

type ZshConfig struct {
	Plugins []string `yaml:"plugins"`
	// PromptColours colours the host segment of each user's prompt.
	PromptColours map[string]string `yaml:"prompt_colours"`
}

type DockerConfig struct {
	Enabled bool     `yaml:"enabled"`
	Users   []string `yaml:"users"`
}

type DNSConfig struct {
	// Hostname gets A and AAAA records for the host's default addresses.
	// Empty disables DNS management for the host.
	Hostname string `yaml:"hostname"`
	AuthUser Secret `yaml:"auth_user"`
	AuthKey  Secret `yaml:"auth_key"`
}

// Repo is a configuration directory.
type Repo struct {
	dir             string
	inventory       Inventory
	recipients      []age.Recipient
	identityCommand []string
	keys            *keyring
}

// Open reads hosts.yml and secrets.yml from dir and checks the directory's
// layout. A nil identity means CommandIdentity.
func Open(dir string, identity IdentitySource) (*Repo, error) {
	r := &Repo{dir: dir}

	root, err := r.readLayer("hosts.yml", false)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, fmt.Errorf("%s: empty file", r.path("hosts.yml"))
	}
	if err := decode(context.Background(), root, &r.inventory); err != nil {
		return nil, fmt.Errorf("%s: %w", r.path("hosts.yml"), err)
	}

	if err := r.readSecrets(); err != nil {
		return nil, err
	}

	if identity == nil {
		identity = r.CommandIdentity()
	}
	r.keys = &keyring{source: identity}

	if err := r.checkLayout(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Repo) Inventory() Inventory {
	return r.inventory
}

// HostConfig merges the layers for the named host. osFamily is the host's
// Facts.OSFamily, used to choose os/<family>.yml.
func (r *Repo) HostConfig(name, osFamily string) (Config, error) {
	if err := r.checkHost(name); err != nil {
		return Config{}, err
	}
	if strings.ContainsAny(osFamily, `/\`) || strings.HasPrefix(osFamily, ".") {
		return Config{}, fmt.Errorf("invalid OS family %q", osFamily)
	}

	layers := []struct {
		file   string
		source func() (ast.Node, error)
	}{
		{r.path("all.yml"), func() (ast.Node, error) { return r.readLayer("all.yml", true) }},
		{r.path("os", osFamily+".yml"), func() (ast.Node, error) {
			if osFamily == "" {
				return nil, nil
			}
			return r.readLayer(filepath.Join("os", osFamily+".yml"), true)
		}},
		{r.path("hosts", name+".yml"), func() (ast.Node, error) {
			return r.readLayer(filepath.Join("hosts", name+".yml"), true)
		}},
	}

	var configured ast.Node
	var nodes []ast.Node
	for _, l := range layers {
		node, err := l.source()
		if err != nil {
			return Config{}, err
		}
		if node == nil {
			continue
		}
		// Each layer is checked alone first, so errors name the file at fault.
		if err := decode(r.keys.context(), merge(nil, node), &Config{}); err != nil {
			return Config{}, fmt.Errorf("%s: %w", l.file, err)
		}
		configured = merge(configured, node)
		nodes = append(nodes, node)
	}

	merged, err := parseLayer("built-in defaults", defaults)
	if err != nil {
		return Config{}, err
	}
	if configured != nil {
		merged = withoutSetSequences(merged, configured)
	}
	for _, node := range nodes {
		merged = merge(merged, node)
	}

	var c Config
	if err := decode(r.keys.context(), merged, &c); err != nil {
		return Config{}, fmt.Errorf("merging configuration for %s: %w", name, err)
	}
	return c, nil
}

//go:embed defaults.yml
var defaults []byte

// Credentials reads credentials/<host>.yml, returning nil if it doesn't
// exist.
func (r *Repo) Credentials(host string) (*Credentials, error) {
	if err := r.checkHost(host); err != nil {
		return nil, err
	}
	file := filepath.Join("credentials", host+".yml")
	node, err := r.readLayer(file, true)
	if err != nil || node == nil {
		return nil, err
	}
	c := &Credentials{}
	if err := decode(r.keys.context(), node, c); err != nil {
		return nil, fmt.Errorf("%s: %w", r.path(file), err)
	}
	return c, nil
}

// WriteCredentials encrypts and writes credentials/<host>.yml, replacing any
// existing file atomically.
func (r *Repo) WriteCredentials(host, sshKey, sudoPassword string, rotated time.Time) error {
	if err := r.checkHost(host); err != nil {
		return err
	}
	key, err := r.Encrypt(sshKey)
	if err != nil {
		return err
	}
	password, err := r.Encrypt(sudoPassword)
	if err != nil {
		return err
	}

	content := fmt.Sprintf(
		"# Generated by `sensible bootstrap`. Do not edit.\nssh_key: %s\nsudo_password: %s\nrotated: %s\n",
		key,
		password,
		rotated.Format(time.RFC3339),
	)

	dir := r.path("credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, host+".yml"), []byte(content), 0o600)
}

// AddHostKey adds a key to the host's host_keys in hosts.yml, leaving the
// rest of the file as it was.
func (r *Repo) AddHostKey(name string, key ssh.PublicKey) error {
	if err := r.checkHost(name); err != nil {
		return err
	}
	file := r.path("hosts.yml")
	manual := fmt.Errorf("add it to %s by hand:\n  %s:\n    host_keys:\n      - %s", file, name, HostKey{key})

	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	updated, err := insertHostKey(src, name, HostKey{key})
	if err != nil {
		return fmt.Errorf("%w; %w", err, manual)
	}

	// The edit is textual, so check it changed exactly what was meant to.
	want := Inventory{Hosts: map[string]HostEntry{}}
	for n, e := range r.inventory.Hosts {
		if n == name {
			e.HostKeys = append(slices.Clone(e.HostKeys), HostKey{key})
		}
		want.Hosts[n] = e
	}
	var got Inventory
	root, err := parseLayer(file, updated)
	if err == nil {
		err = decode(context.Background(), root, &got)
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		return fmt.Errorf("couldn't update the layout of %s; %w", file, manual)
	}

	if err := writeAtomic(file, updated, info.Mode().Perm()); err != nil {
		return err
	}
	r.inventory = got
	return nil
}

// insertHostKey adds a host_keys list to the end of the host's entry.
func insertHostKey(src []byte, name string, key HostKey) ([]byte, error) {
	f, err := parser.ParseBytes(src, 0)
	if err != nil {
		return nil, err
	}
	if len(f.Docs) != 1 {
		return nil, errors.New("expected a single document")
	}
	hosts, ok := mappingValue(f.Docs[0].Body, "hosts").(*ast.MappingNode)
	if !ok || hosts.IsFlowStyle {
		return nil, errors.New("hosts isn't a block mapping")
	}
	var entry *ast.MappingValueNode
	for _, v := range hosts.Values {
		if keyString(v.Key) == name {
			entry = v
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("no entry for %s", name)
	}

	start := entry.Key.GetToken().Position
	indent := start.Column + 1
	switch v := entry.Value.(type) {
	case *ast.NullNode:
	case *ast.MappingNode:
		if v.IsFlowStyle {
			return nil, fmt.Errorf("%s isn't a block mapping", name)
		}
		if mappingValue(v, "host_keys") != nil {
			return nil, fmt.Errorf("%s already has host_keys", name)
		}
		indent = v.Values[0].Key.GetToken().Position.Column - 1
	default:
		return nil, fmt.Errorf("%s isn't a mapping", name)
	}

	// The entry runs until the next token as far left as its key. Block
	// scalar contents have no column.
	last := start.Line
	for tk := entry.Key.GetToken().Next; tk != nil; tk = tk.Next {
		if tk.Type == token.CommentType {
			continue
		}
		if tk.Position.Line > start.Line && tk.Position.Column > 0 && tk.Position.Column <= start.Column {
			break
		}
		last = max(last, tk.Position.Line+strings.Count(strings.TrimRight(tk.Value, "\n"), "\n"))
	}

	text := string(src)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	lines := strings.SplitAfter(text, "\n")
	pad := strings.Repeat(" ", indent)
	return []byte(
		strings.Join(
			slices.Insert(lines, last, fmt.Sprintf("%shost_keys:\n%s  - %s\n", pad, pad, key)),
			"",
		),
	), nil
}

func mappingValue(node ast.Node, key string) ast.Node {
	m, ok := node.(*ast.MappingNode)
	if !ok {
		return nil
	}
	for _, v := range m.Values {
		if keyString(v.Key) == key {
			return v.Value
		}
	}
	return nil
}

func writeAtomic(path string, content []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()

	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// checkLayout rejects files in hosts/ and credentials/ that don't belong to an
// inventory host, and files in os/ that would never be read.
func (r *Repo) checkLayout() error {
	for _, dir := range []string{"hosts", "credentials", "os"} {
		entries, err := os.ReadDir(r.path(dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			name, ok := strings.CutSuffix(e.Name(), ".yml")
			if !ok || e.IsDir() {
				return fmt.Errorf("%s: unexpected file; expected <name>.yml", r.path(dir, e.Name()))
			}
			if _, known := r.inventory.Hosts[name]; dir != "os" && !known {
				return fmt.Errorf("%s: host %q isn't in hosts.yml", r.path(dir, e.Name()), name)
			}
		}
	}
	return nil
}

func (r *Repo) checkHost(name string) error {
	if _, ok := r.inventory.Hosts[name]; !ok {
		return fmt.Errorf("host %q isn't in %s", name, r.path("hosts.yml"))
	}
	return nil
}

func (r *Repo) path(elem ...string) string {
	return filepath.Join(append([]string{r.dir}, elem...)...)
}

// readLayer parses a YAML file in the repo, returning a nil node if the file
// is empty, or if it doesn't exist and is optional.
func (r *Repo) readLayer(file string, optional bool) (ast.Node, error) {
	b, err := os.ReadFile(r.path(file))
	if optional && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseLayer(r.path(file), b)
}

func decode(ctx context.Context, node ast.Node, v any) error {
	return yaml.NewDecoder(strings.NewReader(""), yaml.Strict()).DecodeFromNodeContext(ctx, node, v)
}

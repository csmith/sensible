package config

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
)

// Inventory is the parsed hosts.yml.
type Inventory struct {
	Secrets SecretsConfig        `yaml:"secrets"`
	Hosts   map[string]HostEntry `yaml:"hosts"`
}

type SecretsConfig struct {
	// Recipients are age public keys; secrets are encrypted to all of them.
	Recipients []string `yaml:"recipients"`
	// Identity is a 1Password reference (op://...) to the age identity.
	Identity string `yaml:"identity"`
}

type HostEntry struct {
	// Address is the host's public or LAN address. Empty for the local host.
	Address string `yaml:"address"`
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
	// PromptColour colours the host segment of the user's zsh prompt.
	PromptColour string `yaml:"prompt_colour"`
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
	dir        string
	inventory  Inventory
	recipients []age.Recipient
	keys       *keyring
}

// Open reads hosts.yml from dir and checks the directory's layout. A nil
// identity means OnePasswordIdentity with the inventory's secrets.identity.
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

	if len(r.inventory.Secrets.Recipients) > 0 {
		r.recipients, err = age.ParseRecipients(strings.NewReader(strings.Join(r.inventory.Secrets.Recipients, "\n")))
		if err != nil {
			return nil, fmt.Errorf("%s: secrets.recipients: %w", r.path("hosts.yml"), err)
		}
	}

	if identity == nil {
		identity = r.defaultIdentity()
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

// KnownHostsPath is the known_hosts file, keyed by inventory name.
func (r *Repo) KnownHostsPath() string {
	return r.path("known_hosts")
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
	return writeAtomic(filepath.Join(dir, host+".yml"), []byte(content))
}

func writeAtomic(path string, content []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()

	if err := f.Chmod(0o600); err != nil {
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

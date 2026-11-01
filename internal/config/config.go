package config

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"golang.org/x/crypto/ssh"

	"chameth.com/sensible/internal/host"
)

// Inventory is the hosts merged from hosts.d.
type Inventory struct {
	Hosts map[string]HostEntry
}

type HostEntry struct {
	// Address is the host's public or LAN address. Empty for the local host.
	Address string `yaml:"address"`
	// DNSName gets A and AAAA records for the host's default addresses.
	// Empty disables DNS management for the host.
	DNSName string `yaml:"dns_name"`
	// HostKeys are the host's SSH public keys, which connections must match.
	HostKeys []HostKey `yaml:"host_keys"`
	// Roles are the host's roles, each with the parameters the host sets.
	Roles map[string]RoleParams `yaml:"roles"`
	// SSHKey is an OpenSSH-format private key for the sensible account. A
	// host without one hasn't been bootstrapped.
	SSHKey       Secret    `yaml:"ssh_key"`
	SudoPassword Secret    `yaml:"sudo_password"`
	Rotated      time.Time `yaml:"rotated"`
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

// Config is one host's configuration, merged from its roles. A nil module
// is one no role mentions, which doesn't run.
type Config struct {
	Packages  *PackagesConfig       `yaml:"packages"`
	AUR       *AURConfig            `yaml:"aur"`
	Users     map[string]UserConfig `yaml:"users"`
	Sudoers   map[string][]string   `yaml:"sudoers"`
	PamRSSH   *PamRSSHConfig        `yaml:"pam_rssh"`
	SSHD      *SSHDConfig           `yaml:"sshd"`
	Tailscale *TailscaleConfig      `yaml:"tailscale"`
	Zsh       *ZshConfig            `yaml:"zsh"`
	Docker    *DockerConfig         `yaml:"docker"`
	Vim       *VimConfig            `yaml:"vim"`
	Hostname  *HostnameConfig       `yaml:"hostname"`
	Timezone  *TimezoneConfig       `yaml:"timezone"`
	Locale    *LocaleConfig         `yaml:"locale"`
	NTP       *NTPConfig            `yaml:"ntp"`
	// Stacks come from the host's roles that have a docker-compose.yml,
	// rather than from a module, and are in name order.
	Stacks []Stack `yaml:"-"`
	// Volumes are those of the host's roles and their parents, in path
	// order.
	Volumes []Volume `yaml:"-"`
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
	Groups []string `yaml:"groups"`
}

type PamRSSHConfig struct {
	Keys []string `yaml:"keys"`
}

type SSHDConfig struct {
	Settings map[string]string `yaml:"settings"`
	// AuthorizedKeys are each user's login keys.
	AuthorizedKeys map[string][]string `yaml:"authorized_keys"`
}

type TailscaleConfig struct {
	Settings map[string]string `yaml:"settings"`
}

type ZshConfig struct {
	// Users get zsh as their shell.
	Users   []string `yaml:"users"`
	Plugins []string `yaml:"plugins"`
	// PromptColours colours the host segment of each user's prompt.
	PromptColours map[string]string `yaml:"prompt_colours"`
}

type DockerConfig struct {
	Users []string `yaml:"users"`
	// Networks are created before any stack, so stacks can share them as
	// external networks.
	Networks map[string]DockerNetworkConfig `yaml:"networks"`
}

type DockerNetworkConfig struct {
	// Subnets are in CIDR form. Docker picks one for each address family
	// without one.
	Subnets []string `yaml:"subnets"`
	IPv6    bool     `yaml:"ipv6"`
}

type VimConfig struct{}

type HostnameConfig struct {
	// Name defaults to the host's inventory name.
	Name string `yaml:"name"`
}

type TimezoneConfig struct {
	// Zone is a tz database name, e.g. "Europe/London".
	Zone string `yaml:"zone"`
}

type LocaleConfig struct {
	// Lang is the system's LANG, e.g. "en_GB.UTF-8". It's always generated.
	Lang string `yaml:"lang"`
	// Generate are further locales to generate.
	Generate []string `yaml:"generate"`
}

type NTPConfig struct {
	// Servers replace the distribution's default servers. Empty keeps them.
	Servers []string `yaml:"servers"`
}

// DNSCredentials are the DNS provider's API credentials.
type DNSCredentials struct {
	AuthUser Secret `yaml:"auth_user"`
	AuthKey  Secret `yaml:"auth_key"`
}

// Repo is a configuration directory.
type Repo struct {
	dir             string
	inventory       Inventory
	sources         map[string]setBy
	recipients      []age.Recipient
	identityCommand []string
	dns             DNSCredentials
	keys            *keyring
	// roles maps every role, including child roles, to its children.
	roles map[string][]string
	// stacks are the roles with a docker-compose.yml.
	stacks map[string]*stackDef
	// volumes are the compose.volumes of the roles that declare any.
	volumes map[string]map[string]Perms
}

// Open reads hosts.d and sensible.yml from dir and checks the directory's
// layout. A nil identity means CommandIdentity.
func Open(dir string, identity IdentitySource) (*Repo, error) {
	r, err := OpenSettings(dir)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		identity = r.CommandIdentity()
	}
	r.keys.source = identity

	if err := r.readHosts(); err != nil {
		return nil, err
	}
	if err := r.checkLayout(); err != nil {
		return nil, err
	}
	return r, nil
}

// OpenSettings reads only the repo's sensible.yml, which is enough to
// encrypt secrets, without checking the rest of the repo.
func OpenSettings(dir string) (*Repo, error) {
	r := &Repo{dir: dir, keys: &keyring{}}
	if err := r.readSettings(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Repo) Inventory() Inventory {
	return r.inventory
}

// DNS is the DNS provider credentials from sensible.yml.
func (r *Repo) DNS() DNSCredentials {
	return r.dns
}

// WriteCredentials encrypts the host's credentials into its state file.
func (r *Repo) WriteCredentials(name, sshKey, sudoPassword string, rotated time.Time) error {
	if err := r.checkHost(name); err != nil {
		return err
	}
	file := stateFile(name)
	for _, key := range []string{"ssh_key", "sudo_password", "rotated"} {
		if s, ok := r.sources[joinPath(name, key)]; ok && s.source != r.path(file) {
			return fmt.Errorf("%s sets %s's %s, so its credentials can't be written to %s", s.source, name, key, r.path(file))
		}
	}
	key, err := r.encryptSecret(sshKey)
	if err != nil {
		return err
	}
	password, err := r.encryptSecret(sudoPassword)
	if err != nil {
		return err
	}
	return r.updateState(
		name,
		func(s *hostState) {
			s.SSHKey = key
			s.SudoPassword = password
			s.Rotated = rotated
		},
	)
}

// AddHostKey adds a key to the host's host_keys in its state file.
func (r *Repo) AddHostKey(name string, key ssh.PublicKey) error {
	if err := r.checkHost(name); err != nil {
		return err
	}
	err := r.updateState(
		name,
		func(s *hostState) {
			s.HostKeys = append(s.HostKeys, HostKey{key})
		},
	)
	if err != nil {
		return fmt.Errorf(
			"%w; add the host key to %s by hand:\n  %s:\n    host_keys:\n      - %s",
			err,
			r.path("hosts.d", name+".yml"),
			name,
			HostKey{key},
		)
	}
	return nil
}

// readHosts merges every file in hosts.d into the inventory. Each file is
// checked alone first, so errors name the file at fault, and no two files
// may set a value differently, so the order they're read in never matters.
func (r *Repo) readHosts() error {
	dir := r.path("hosts.d")
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	entries, err := readDir(dir)
	if err != nil {
		return err
	}
	var merged ast.Node
	sources := map[string]setBy{}
	for _, e := range entries {
		file := filepath.Join("hosts.d", e.Name())
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			return fmt.Errorf("%s: unexpected file; expected a .yml file", r.path(file))
		}
		node, err := r.readLayer(file, false)
		if err != nil {
			return err
		}
		if node == nil {
			continue
		}
		if tag := findTag(node, volumeTag); tag != nil {
			return fmt.Errorf("%s: %w", r.path(file), nodeError(tag, "!volume only works in roles, which own volumes"))
		}
		if err := decode(r.keys.context(), node, &map[string]HostEntry{}); err != nil {
			return fmt.Errorf("%s: %w", r.path(file), err)
		}
		if err := checkConflicts(r.path(file), node, "", sources); err != nil {
			return err
		}
		merged = mergeFragments(merged, node)
	}

	inv := Inventory{Hosts: map[string]HostEntry{}}
	if merged != nil {
		if err := decode(r.keys.context(), merged, &inv.Hosts); err != nil {
			return fmt.Errorf("merging %s: %w", dir, err)
		}
	}
	r.inventory = inv
	r.sources = sources
	return nil
}

// hostState is what sensible writes for a host.
type hostState struct {
	SSHKey       Secret    `yaml:"ssh_key"`
	SudoPassword Secret    `yaml:"sudo_password"`
	Rotated      time.Time `yaml:"rotated"`
	HostKeys     []HostKey `yaml:"host_keys"`
}

func stateFile(host string) string {
	return filepath.Join("hosts.d", host+".state.yml")
}

// updateState rewrites the host's state file with change applied to what it
// holds now, then reloads the inventory.
func (r *Repo) updateState(name string, change func(*hostState)) error {
	file := stateFile(name)
	states := map[string]hostState{}
	node, err := r.readLayer(file, true)
	if err != nil {
		return err
	}
	if node != nil {
		if err := decode(r.keys.context(), node, &states); err != nil {
			return fmt.Errorf("%s: %w", r.path(file), err)
		}
	}
	s := states[name]
	change(&s)
	states[name] = s

	var out strings.Builder
	out.WriteString("# Managed by sensible. Local changes will be overwritten.\n")
	for _, host := range slices.Sorted(maps.Keys(states)) {
		s := states[host]
		out.WriteString(host + ":\n")
		if !s.SSHKey.IsZero() {
			out.WriteString("  ssh_key: " + indent(s.SSHKey.yaml(), "  ") + "\n")
		}
		if !s.SudoPassword.IsZero() {
			out.WriteString("  sudo_password: " + indent(s.SudoPassword.yaml(), "  ") + "\n")
		}
		if !s.Rotated.IsZero() {
			out.WriteString("  rotated: " + s.Rotated.UTC().Format(time.RFC3339) + "\n")
		}
		if len(s.HostKeys) > 0 {
			out.WriteString("  host_keys:\n")
			for _, k := range s.HostKeys {
				out.WriteString("    - " + k.String() + "\n")
			}
		}
	}

	if err := writeAtomic(r.path(file), []byte(out.String()), 0o600); err != nil {
		return err
	}
	return r.readHosts()
}

func indent(s, prefix string) string {
	return strings.ReplaceAll(s, "\n", "\n"+prefix)
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

// checkLayout rejects role files that would never be read, and roles hosts
// have that don't exist.
func (r *Repo) checkLayout() error {
	r.roles = map[string][]string{}
	r.stacks = map[string]*stackDef{}
	r.volumes = map[string]map[string]Perms{}
	entries, err := readDir(r.path("roles"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			return fmt.Errorf("%s: unexpected file; expected a role directory", r.path("roles", e.Name()))
		}
		if err := r.checkRole(e.Name(), true); err != nil {
			return err
		}
	}
	if err := r.checkStackNames(); err != nil {
		return err
	}

	for _, host := range slices.Sorted(maps.Keys(r.inventory.Hosts)) {
		roles := r.inventory.Hosts[host].Roles
		for _, role := range slices.Sorted(maps.Keys(roles)) {
			source := r.sources[joinPath(host, "roles", role)].source
			if _, ok := r.roles[role]; !ok {
				return fmt.Errorf("%s: %s has role %q, which isn't in %s", source, host, role, r.path("roles"))
			}
			if parent, _, ok := strings.Cut(role, "/"); ok {
				if _, ok := roles[parent]; ok {
					return fmt.Errorf("%s: %s has role %q and its parent %q, which already includes it", source, host, role, parent)
				}
			}
		}
	}
	return nil
}

// checkRole records the role, its child roles and its stack. Only
// top-level roles may have children.
func (r *Repo) checkRole(role string, topLevel bool) error {
	dir := r.path("roles", role)
	entries, err := readDir(dir)
	if err != nil {
		return err
	}
	settings, err := r.readRoleSettings(role)
	if err != nil {
		return err
	}
	if len(settings.Children) > 0 && !topLevel {
		return fmt.Errorf("%s: children: roles nest one level deep", r.path("roles", role, "role.yml"))
	}

	isStack := slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() == host.ComposeFile })
	covered, err := r.checkCompose(role, settings, isStack)
	if err != nil {
		return err
	}

	var children []string
	for _, name := range settings.Children {
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			return fmt.Errorf("%s: children: invalid name %q", r.path("roles", role, "role.yml"), name)
		}
		if covered[name] {
			return fmt.Errorf("%s: %q is both a child role and in compose.files", r.path("roles", role, "role.yml"), name)
		}
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || !info.IsDir() {
			return fmt.Errorf("%s: children: %q isn't a directory in %s", r.path("roles", role, "role.yml"), name, dir)
		}
		child := role + "/" + name
		if err := r.checkRole(child, false); err != nil {
			return err
		}
		children = append(children, child)
	}

	hasBase, hasVariant := false, false
	for _, e := range entries {
		file := filepath.Join(dir, e.Name())
		switch {
		case covered[e.Name()] || slices.Contains(settings.Children, e.Name()):
		case e.IsDir():
			return fmt.Errorf("%s: unexpected directory; list it in children, or in compose.files for a stack", file)
		case e.Name() == "role.yml":
			hasBase = true
		case e.Name() == host.ComposeFile:
		case isVariantFile(e.Name()):
			family := strings.TrimSuffix(strings.TrimPrefix(e.Name(), "role."), ".yml")
			if !slices.Contains(host.OSFamilies, family) {
				return fmt.Errorf("%s: unknown OS %q; expected one of %s", file, family, strings.Join(host.OSFamilies, ", "))
			}
			hasVariant = true
		default:
			return fmt.Errorf(
				"%s: unexpected file; expected role.yml, role.<os>.yml, %s, or a file in compose.files",
				file,
				host.ComposeFile,
			)
		}
	}
	// A stack needs no settings of its own, but OS variants need a base.
	if !hasBase && (hasVariant || !isStack) {
		return fmt.Errorf("%s: missing role.yml", dir)
	}
	slices.Sort(children)
	r.roles[role] = children
	return nil
}

// checkCompose records the role's volumes and stack, returning the names of
// the role directory's entries its stack's files cover.
func (r *Repo) checkCompose(role string, settings roleSettings, isStack bool) (map[string]bool, error) {
	if settings.Compose != nil {
		if err := r.checkVolumes(role, settings.Compose.Volumes); err != nil {
			return nil, err
		}
	}
	if isStack {
		return r.checkStack(role, settings)
	}
	if settings.Compose != nil && len(settings.Compose.Files) > 0 {
		return nil, fmt.Errorf("%s: compose.files needs a %s", r.path("roles", role, "role.yml"), host.ComposeFile)
	}
	return map[string]bool{}, nil
}

func isVariantFile(name string) bool {
	return strings.HasPrefix(name, "role.") && strings.HasSuffix(name, ".yml") && name != "role.yml"
}

// readDir lists a directory without hidden files, returning nothing if it
// doesn't exist.
func readDir(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return slices.DeleteFunc(entries, func(e os.DirEntry) bool { return strings.HasPrefix(e.Name(), ".") }), err
}

func (r *Repo) checkHost(name string) error {
	if _, ok := r.inventory.Hosts[name]; !ok {
		return fmt.Errorf("host %q isn't in %s", name, r.path("hosts.d"))
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

func findTag(node ast.Node, tag string) ast.Node {
	switch n := node.(type) {
	case *ast.TagNode:
		if n.Start.Value == tag {
			return n
		}
		return findTag(n.Value, tag)
	case *ast.MappingNode:
		for _, mv := range n.Values {
			if found := findTag(mv.Value, tag); found != nil {
				return found
			}
		}
	case *ast.SequenceNode:
		for _, item := range n.Values {
			if found := findTag(item, tag); found != nil {
				return found
			}
		}
	default:
	}
	return nil
}

func decode(ctx context.Context, node ast.Node, v any) error {
	return yaml.NewDecoder(strings.NewReader(""), yaml.Strict()).DecodeFromNodeContext(ctx, node, v)
}

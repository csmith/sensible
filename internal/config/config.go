package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	// Address is the host's public or LAN address, optionally with a port. The
	// machine the controller runs on is reached over loopback instead, using
	// the same port, so it can leave this empty.
	Address string `yaml:"address"`
	// DNSName gets A and AAAA records for the host's default addresses.
	// Empty disables DNS management for the host.
	DNSName string `yaml:"dns_name"`
	// HostKeys are the host's SSH public keys, which connections must match.
	HostKeys HostKeys `yaml:"host_keys"`
	// Roles are the host's roles, each with the parameters the host sets.
	Roles map[string]RoleParams `yaml:"roles"`
	// SSHKey is an OpenSSH-format private key for the sensible account. A
	// host without one hasn't been bootstrapped.
	SSHKey       Secret    `yaml:"ssh_key"`
	SudoPassword Secret    `yaml:"sudo_password"`
	Rotated      time.Time `yaml:"rotated"`
	// Generated are the values of the host's !generated tags, by stack and
	// name.
	Generated map[string]map[string]Secret `yaml:"generated"`
	// Certs are the certificates issued to the host, by name.
	Certs map[string]savedCert `yaml:"certs"`
	// Ignored are leftovers that are meant to stay on the host, as items by
	// the ID of the resource that lists them.
	Ignored map[string][]string `yaml:"ignored"`
}

// HostKeys drops duplicate keys, as a key is often in both a hand-written
// file and the state file.
type HostKeys []HostKey

func (k *HostKeys) UnmarshalYAML(ctx context.Context, node ast.Node) error {
	var keys []HostKey
	if err := decode(ctx, node, &keys); err != nil {
		return err
	}
	*k = nil
	for _, key := range keys {
		if !slices.ContainsFunc(*k, func(o HostKey) bool { return bytes.Equal(o.Marshal(), key.Marshal()) }) {
			*k = append(*k, key)
		}
	}
	return nil
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

// Set is a list whose duplicates are dropped, keeping the first of each.
// Lists merged from several roles concatenate, so a plain []string keeps
// every role's copy of an item.
type Set []string

func (s *Set) UnmarshalYAML(ctx context.Context, node ast.Node) error {
	var items []string
	if err := decode(ctx, node, &items); err != nil {
		return err
	}
	*s = nil
	for _, item := range items {
		if !slices.Contains(*s, item) {
			*s = append(*s, item)
		}
	}
	return nil
}

// Command is a program and its arguments. Unlike other lists, roles setting
// it differently conflict, and an OS variant replaces it.
type Command []string

// Config is one host's configuration, merged from its roles. A nil module
// is one no role mentions, which doesn't run.
type Config struct {
	AptRepos   map[string]AptRepoConfig `yaml:"apt_repos"`
	Packages   *PackagesConfig          `yaml:"packages"`
	AUR        *AURConfig               `yaml:"aur"`
	Users      map[string]UserConfig    `yaml:"users"`
	Sudoers    map[string]Set           `yaml:"sudoers"`
	PamRSSH    *PamRSSHConfig           `yaml:"pam_rssh"`
	SSHD       *SSHDConfig              `yaml:"sshd"`
	Tailscale  *TailscaleConfig         `yaml:"tailscale"`
	Zsh        *ZshConfig               `yaml:"zsh"`
	Docker     *DockerConfig            `yaml:"docker"`
	Vim        *VimConfig               `yaml:"vim"`
	QuietLogin *QuietLoginConfig        `yaml:"quiet_login"`
	Hostname   *HostnameConfig          `yaml:"hostname"`
	Timezone   *TimezoneConfig          `yaml:"timezone"`
	Locale     *LocaleConfig            `yaml:"locale"`
	NTP        *NTPConfig               `yaml:"ntp"`
	Jobs       map[string]JobConfig     `yaml:"jobs"`
	Backups    map[string]BackupConfig  `yaml:"backups"`
	Restic     *ResticConfig            `yaml:"restic"`
	Certs      map[string]CertConfig    `yaml:"certs"`
	Remove     *RemoveConfig            `yaml:"remove"`
	Files      []FileConfig             `yaml:"files"`
	Leftovers  *LeftoversConfig         `yaml:"leftovers"`
	// Stacks come from the host's roles that have a docker-compose.yml,
	// rather than from a module, and are in name order.
	Stacks []Stack `yaml:"-"`
	// Volumes are those of the host's roles and their parents, in path
	// order.
	Volumes []Volume `yaml:"-"`
	// IssuedCerts are the certificates in Certs, ready to be written.
	IssuedCerts []Cert `yaml:"-"`
}

// AptRepoConfig is a deb822 apt source, named by its key. "{distro}" and
// "{release}" in any field are replaced by the host's os-release ID and
// release codename, e.g. "ubuntu" and "noble".
type AptRepoConfig struct {
	URIs          Set    `yaml:"uris"`
	Suites        Set    `yaml:"suites"`
	Components    Set    `yaml:"components"`
	SigningKeyURL string `yaml:"signing_key_url"`
}

type PackagesConfig struct {
	Install Set `yaml:"install"`
	// Remove is applied before Install, so replacements can be installed.
	Remove Set `yaml:"remove"`
}

type AURConfig struct {
	Packages Set `yaml:"packages"`
}

type UserConfig struct {
	Groups Set `yaml:"groups"`
	// Home defaults to /home/<name>, or /root. Changing it doesn't move the
	// existing directory.
	Home string `yaml:"home"`
	// Shell is left alone if empty, unless zsh.users sets it.
	Shell string `yaml:"shell"`
}

type PamRSSHConfig struct {
	Keys Set `yaml:"keys"`
}

type SSHDConfig struct {
	Settings map[string]string `yaml:"settings"`
	// AuthorizedKeys are each user's login keys.
	AuthorizedKeys map[string]Set `yaml:"authorized_keys"`
}

type TailscaleConfig struct {
	Settings map[string]string `yaml:"settings"`
}

type ZshConfig struct {
	// Users get zsh as their shell.
	Users   Set `yaml:"users"`
	Plugins Set `yaml:"plugins"`
	// Theme is the oh-my-zsh theme, defaulting to agnoster.
	Theme string `yaml:"theme"`
	// Editor is $EDITOR, defaulting to vim.
	Editor string `yaml:"editor"`
	// PromptColours colours the host segment of each user's prompt. Only
	// agnoster has one.
	PromptColours map[string]string `yaml:"prompt_colours"`
}

type DockerConfig struct {
	Users Set `yaml:"users"`
	// Networks are created before any stack, so stacks can share them as
	// external networks.
	Networks map[string]DockerNetworkConfig `yaml:"networks"`
	// Registries are the credentials root's Docker client pulls with, by
	// registry host, e.g. "ghcr.io".
	Registries map[string]RegistryConfig `yaml:"registries"`
	// Daemon is the content of /etc/docker/daemon.json, using Docker's own
	// option names. Without it, the file is left alone. dockerd checks it
	// before it's replaced, and changing it restarts Docker.
	Daemon map[string]any `yaml:"daemon"`

	// Auths are each registry's base64 "username:password", as Docker's
	// client config holds them. HostConfig sets it.
	Auths map[string]string `yaml:"-"`
}

type RegistryConfig struct {
	Username string `yaml:"username"`
	Password Secret `yaml:"password"`
}

func (c *DockerConfig) reveal() error {
	if len(c.Registries) == 0 {
		return nil
	}
	c.Auths = map[string]string{}
	for name, r := range c.Registries {
		if r.Username == "" {
			return fmt.Errorf("docker.registries.%s needs a username", name)
		}
		password, err := r.Password.Reveal()
		if err != nil {
			return fmt.Errorf("docker.registries.%s.password: %w", name, err)
		}
		c.Auths[name] = base64.StdEncoding.EncodeToString([]byte(r.Username + ":" + password))
	}
	return nil
}

type DockerNetworkConfig struct {
	// Subnets are in CIDR form. Docker picks one for each address family
	// without one.
	Subnets Set  `yaml:"subnets"`
	IPv6    bool `yaml:"ipv6"`
}

type VimConfig struct{}

// QuietLoginConfig hides the message of the day and the last login notice.
// Removing it doesn't restore the lines it commented out.
type QuietLoginConfig struct{}

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
	Generate Set `yaml:"generate"`
}

type NTPConfig struct {
	// Servers replace the distribution's default servers. Empty keeps them.
	Servers Set `yaml:"servers"`
}

type RemoveConfig struct {
	// Paths are removed, recursively, on every apply. Each is absolute, or
	// "~user/..." for a path in a user's home.
	Paths Set `yaml:"paths"`
}

// LeftoversConfig acknowledges what sensible finds on a host but didn't put
// there. Paths are absolute, and they and Packages may be glob patterns.
type LeftoversConfig struct {
	// Ignore may or may not be there, and is never warned about or pruned.
	Ignore KeptConfig `yaml:"ignore"`
	// External is managed outside sensible: it's never pruned, and is warned
	// about if it's missing.
	External KeptConfig `yaml:"external"`
}

type KeptConfig struct {
	Paths    Set `yaml:"paths"`
	Packages Set `yaml:"packages"`
}

// FileConfig is a file written as given. Its content is either Content, or
// read from Source, a file in the files directory of the role or partial that
// declares it.
type FileConfig struct {
	Path    string `yaml:"path"`
	Content *Value `yaml:"content"`
	// Source is read when HostConfig merges the host's roles, and decrypted
	// if its name ends in .age.
	Source string `yaml:"source"`
	Perms  `yaml:",inline"`

	// Data is the file's content, decrypted. HostConfig sets it.
	Data string `yaml:"-"`
	// Hidden is set when Data is secret.
	Hidden bool `yaml:"-"`
}

// reveal decrypts the secrets the modules need ready to write.
func (c *Config) reveal(keys *keyring) error {
	if c.Docker != nil {
		if err := c.Docker.reveal(); err != nil {
			return err
		}
	}
	if c.Restic != nil {
		if err := c.Restic.reveal(); err != nil {
			return err
		}
	}
	for i := range c.Files {
		if err := c.Files[i].reveal(keys); err != nil {
			return fmt.Errorf("files: %s: %w", c.Files[i].Path, err)
		}
	}
	return nil
}

// checkFilePaths rejects files in node, the role's settings, that the role
// or a role before it already writes. written maps each path to its role.
func checkFilePaths(role string, node ast.Node, written map[string]string) error {
	for _, v := range mappingValues(node) {
		if keyString(v.Key) != "files" {
			continue
		}
		var files []FileConfig
		if err := decode(context.Background(), merge(nil, v.Value), &files); err != nil {
			return fmt.Errorf("role %s: files: %w", role, err)
		}
		for _, f := range files {
			if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path {
				return fmt.Errorf("role %s: files: %q isn't a clean absolute path", role, f.Path)
			}
			switch prev, ok := written[f.Path]; {
			case ok && prev == role:
				return fmt.Errorf("role %s writes %s more than once", role, f.Path)
			case ok:
				return fmt.Errorf("roles %s and %s both write %s", prev, role, f.Path)
			}
			written[f.Path] = role
		}
	}
	return nil
}

// reveal sets the file's Data, and fills in the default ownership and mode,
// root:root 0644. As elsewhere, a named owner without a group means the
// owner's primary group.
func (f *FileConfig) reveal(keys *keyring) error {
	switch {
	case f.Content != nil && f.Source != "":
		return errors.New("set content or source, not both")
	case f.Content != nil:
		var err error
		if f.Data, f.Hidden, err = f.Content.reveal(); err != nil {
			return err
		}
	case f.Source != "":
		b, err := os.ReadFile(f.Source)
		if err != nil {
			return err
		}
		f.Data = string(b)
		if strings.HasSuffix(f.Source, ageSuffix) {
			secret, err := parseArmored(f.Data)
			if err != nil {
				return fmt.Errorf("%s: %w", f.Source, err)
			}
			secret.keys = keys
			if f.Data, err = secret.Reveal(); err != nil {
				return fmt.Errorf("%s: %w", f.Source, err)
			}
			f.Hidden = true
		}
	default:
		return errors.New("needs content or source")
	}
	if f.Owner == "" {
		f.Owner = "root"
		if f.Group == "" {
			f.Group = "root"
		}
	}
	if f.Mode == 0 {
		f.Mode = 0o644
	}
	return nil
}

// JobConfig is a command run on a schedule by a systemd timer.
type JobConfig struct {
	Command Command `yaml:"command"`
	// Schedule is a systemd calendar expression, as for OnCalendar.
	Schedule string `yaml:"schedule"`
	// User runs the command. Empty means root.
	User string `yaml:"user"`
}

// BackupConfig is something to back up: a directory, or what a command
// prints. A command needs restic 0.17 or later on the host.
type BackupConfig struct {
	Path    string  `yaml:"path"`
	Command Command `yaml:"command"`
}

// ResticConfig is where and how a host's backups are kept.
type ResticConfig struct {
	Repository string `yaml:"repository"`
	Password   Secret `yaml:"password"`
	// Environment is added to restic's, e.g. for the repository's
	// credentials.
	Environment map[string]Value `yaml:"environment"`
	// Options are restic's -o options.
	Options map[string]string `yaml:"options"`
	// Keep are the counts for forget's --keep-* flags, e.g. "daily".
	Keep map[string]int `yaml:"keep"`
	// Schedule is when backups run, as a systemd calendar expression. Empty
	// means daily.
	Schedule string `yaml:"schedule"`

	// Env is the environment restic runs with: the repository, password and
	// Environment, decrypted. HostConfig sets it.
	Env map[string]string `yaml:"-"`
	// Secrets are the decrypted values in Env.
	Secrets []string `yaml:"-"`
}

func (c *ResticConfig) reveal() error {
	if c.Repository == "" {
		return errors.New("restic needs a repository")
	}
	password, err := c.Password.Reveal()
	if err != nil {
		return fmt.Errorf("restic.password: %w", err)
	}
	c.Env = map[string]string{"RESTIC_REPOSITORY": c.Repository, "RESTIC_PASSWORD": password}
	c.Secrets = []string{password}
	for name, v := range c.Environment {
		if _, ok := c.Env[name]; ok {
			return fmt.Errorf("restic.environment: %s is set from restic's own settings", name)
		}
		value, secret, err := v.reveal()
		if err != nil {
			return fmt.Errorf("restic.environment.%s: %w", name, err)
		}
		c.Env[name] = value
		if secret {
			c.Secrets = append(c.Secrets, value)
		}
	}
	return nil
}

// DNSSettings are the DNS provider, its settings, and the records each vhost
// gets.
type DNSSettings struct {
	// Provider names the DNS provider. Its settings are under its name.
	Provider  string            `yaml:"provider"`
	MyDNSHost MyDNSHostSettings `yaml:"mydnshost"`
	// Vhosts are the records a vhost gets for each host serving it, with
	// "{host}" in their content replaced by the host's dns_name. Empty leaves
	// vhosts' DNS alone.
	Vhosts []VhostRecord `yaml:"vhosts"`
}

type VhostRecord struct {
	Type    string `yaml:"type"`
	Content string `yaml:"content"`
}

type MyDNSHostSettings struct {
	AuthUser Secret `yaml:"auth_user"`
	AuthKey  Secret `yaml:"auth_key"`
}

func (s DNSSettings) check() error {
	switch s.Provider {
	case "":
		if len(s.Vhosts) > 0 || !s.MyDNSHost.AuthUser.IsZero() || !s.MyDNSHost.AuthKey.IsZero() {
			return errors.New("dns.provider isn't set")
		}
	case "mydnshost":
		if s.MyDNSHost.AuthUser.IsZero() || s.MyDNSHost.AuthKey.IsZero() {
			return errors.New("dns.mydnshost: needs an auth_user and auth_key")
		}
	default:
		return fmt.Errorf("dns.provider: unknown provider %q", s.Provider)
	}
	for i, rec := range s.Vhosts {
		if rec.Type == "" || rec.Content == "" {
			return fmt.Errorf("dns.vhosts[%d]: needs a type and content", i)
		}
	}
	return nil
}

// Repo is a configuration directory.
type Repo struct {
	dir             string
	inventory       Inventory
	sources         map[string]setBy
	recipients      []age.Recipient
	identityCommand []string
	dns             DNSSettings
	keys            *keyring
	// roles maps every role, including child roles, to its children.
	roles map[string][]string
	// stacks are the roles with a docker-compose.yml, or whose partials
	// have one.
	stacks map[string]*stackDef
	// partials are the partials in partials/, by name.
	partials map[string]*partialDef
	// rolePartials are the partials each role includes, in order.
	rolePartials map[string][]partialUse
	// volumes are the compose.volumes of the roles that declare any.
	volumes map[string]map[string]Perms
	// roleVhosts are the !vhost tags written in each role's files, outside
	// its params.
	roleVhosts map[string][]*ast.TagNode
	// vhostFiles are the role files each !vhost written in a role is in,
	// including those in its params and partial arguments. Their
	// placeholders are filled for each host.
	vhostFiles map[*ast.TagNode]string
	// params are each role's declared parameters: role.yml's, then those
	// with each OS variant's merged over them.
	params map[string][]ast.Node
	// vhosts maps each vhost to the hosts serving it.
	vhosts map[string][]string
	// caNames are sensible.yml's cas.
	caNames []string
	// cas are the CAs in the CA state file.
	cas map[string]savedCert
	// authorities are the CAs used so far, including any not yet saved.
	authorities map[string]*authority
	now         func() time.Time
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

	if err := r.readCAs(); err != nil {
		return nil, err
	}
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
	r := &Repo{dir: dir, keys: &keyring{}, now: time.Now}
	if err := r.readSettings(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Repo) Inventory() Inventory {
	return r.inventory
}

// DNS is the DNS settings from sensible.yml.
func (r *Repo) DNS() DNSSettings {
	return r.dns
}

// Vhosts maps each vhost, as written with !vhost, to the hosts serving it.
func (r *Repo) Vhosts() map[string][]string {
	return r.vhosts
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

// SaveGenerated encrypts the values the stacks generated for the host into
// its state file. Values the host already has are kept as they are.
func (r *Repo) SaveGenerated(name string, stacks []Stack) error {
	if err := r.checkHost(name); err != nil {
		return err
	}
	values := map[string]map[string]Secret{}
	for _, s := range stacks {
		for key, plain := range s.Generated {
			secret, err := r.encryptSecret(plain)
			if err != nil {
				return err
			}
			if values[s.Name] == nil {
				values[s.Name] = map[string]Secret{}
			}
			values[s.Name][key] = secret
		}
	}
	if len(values) == 0 {
		return nil
	}
	return r.updateState(
		name,
		func(s *hostState) {
			for stack, secrets := range values {
				for key, secret := range secrets {
					if s.Generated == nil {
						s.Generated = map[string]map[string]Secret{}
					}
					if s.Generated[stack] == nil {
						s.Generated[stack] = map[string]Secret{}
					}
					if s.Generated[stack][key].IsZero() {
						s.Generated[stack][key] = secret
					}
				}
			}
		},
	)
}

// DropGenerated removes the named values saved for one of the host's stacks
// from its state file.
func (r *Repo) DropGenerated(name, stack string, keys []string) error {
	if err := r.checkHost(name); err != nil {
		return err
	}
	file := stateFile(name)
	for _, key := range keys {
		if s, ok := r.sources[joinPath(name, "generated", stack, key)]; ok && s.source != r.path(file) {
			return fmt.Errorf("%s sets %s's generated %s for %s, so it can't be removed", s.source, name, key, stack)
		}
	}
	return r.updateState(
		name,
		func(s *hostState) {
			for _, key := range keys {
				delete(s.Generated[stack], key)
			}
			if len(s.Generated[stack]) == 0 {
				delete(s.Generated, stack)
			}
		},
	)
}

// IgnoreLeftover records in the host's state file that the item the
// resource with the given ID lists as a leftover is meant to stay.
func (r *Repo) IgnoreLeftover(name, id, item string) error {
	if err := r.checkHost(name); err != nil {
		return err
	}
	return r.updateState(
		name,
		func(s *hostState) {
			if slices.Contains(s.Ignored[id], item) {
				return
			}
			if s.Ignored == nil {
				s.Ignored = map[string][]string{}
			}
			s.Ignored[id] = append(s.Ignored[id], item)
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
		if err := checkHostVhosts(node); err != nil {
			return fmt.Errorf("%s: %w", r.path(file), err)
		}
		if err := decode(r.keys.context(), node, &map[string]HostEntry{}); err != nil {
			return fmt.Errorf("%s: %w", r.path(file), err)
		}
		if err := checkConflicts(r.path(file), node, sources); err != nil {
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
	SSHKey       Secret                       `yaml:"ssh_key"`
	SudoPassword Secret                       `yaml:"sudo_password"`
	Rotated      time.Time                    `yaml:"rotated"`
	HostKeys     []HostKey                    `yaml:"host_keys"`
	Generated    map[string]map[string]Secret `yaml:"generated"`
	Certs        map[string]savedCert         `yaml:"certs"`
	Ignored      map[string][]string          `yaml:"ignored"`
}

// write adds the state to a state file, under its host's key.
func (s hostState) write(out *strings.Builder) {
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
	if len(s.Generated) > 0 {
		out.WriteString("  generated:\n")
		for _, stack := range slices.Sorted(maps.Keys(s.Generated)) {
			out.WriteString("    " + stack + ":\n")
			for _, key := range slices.Sorted(maps.Keys(s.Generated[stack])) {
				out.WriteString("      " + key + ": " + indent(s.Generated[stack][key].yaml(), "      ") + "\n")
			}
		}
	}
	if len(s.Certs) > 0 {
		out.WriteString("  certs:\n")
		for _, cert := range slices.Sorted(maps.Keys(s.Certs)) {
			out.WriteString("    " + cert + ":\n" + s.Certs[cert].yaml("      "))
		}
	}
	if len(s.Ignored) > 0 {
		out.WriteString("  ignored:\n")
		for _, id := range slices.Sorted(maps.Keys(s.Ignored)) {
			out.WriteString("    " + strconv.Quote(id) + ":\n")
			for _, item := range slices.Sorted(slices.Values(s.Ignored[id])) {
				out.WriteString("      - " + strconv.Quote(item) + "\n")
			}
		}
	}
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
	out.WriteString("# Written by sensible. Edit with care: comments and formatting aren't kept.\n")
	for _, host := range slices.Sorted(maps.Keys(states)) {
		out.WriteString(host + ":\n")
		states[host].write(&out)
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
	r.roleVhosts = map[string][]*ast.TagNode{}
	r.vhostFiles = map[*ast.TagNode]string{}
	r.params = map[string][]ast.Node{}
	r.rolePartials = map[string][]partialUse{}
	if err := r.readPartials(); err != nil {
		return err
	}
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
	return r.mapVhosts()
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
	if err := r.checkPartials(role, settings.Partials); err != nil {
		return err
	}

	isStack := slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() == host.ComposeFile }) ||
		slices.ContainsFunc(r.rolePartials[role], func(u partialUse) bool { return u.def.hasCompose })
	covered, err := r.checkCompose(role, settings, isStack)
	if err != nil {
		return err
	}

	children, err := r.checkChildren(role, settings, covered)
	if err != nil {
		return err
	}

	hasBase, hasVariant := false, false
	for _, e := range entries {
		file := filepath.Join(dir, e.Name())
		switch {
		case covered[e.Name()] || slices.Contains(settings.Children, e.Name()):
		case e.Name() == sourcesDir && e.IsDir():
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
	if err := r.readRoleVhosts(role, entries); err != nil {
		return err
	}
	slices.Sort(children)
	r.roles[role] = children
	return nil
}

// checkChildren checks and records the role's child roles, returning their
// names. covered are the role directory's entries its stack's files cover.
func (r *Repo) checkChildren(role string, settings roleSettings, covered map[string]bool) ([]string, error) {
	if err := r.checkSourcesDir(role, settings, covered); err != nil {
		return nil, err
	}
	dir := r.path("roles", role)
	var children []string
	for _, name := range settings.Children {
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			return nil, fmt.Errorf("%s: children: invalid name %q", r.path("roles", role, "role.yml"), name)
		}
		if covered[name] {
			return nil, fmt.Errorf("%s: %q is both a child role and in compose.files", r.path("roles", role, "role.yml"), name)
		}
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("%s: children: %q isn't a directory in %s", r.path("roles", role, "role.yml"), name, dir)
		}
		child := role + "/" + name
		if err := r.checkRole(child, false); err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return children, nil
}

// checkSourcesDir rejects other uses of the role's files directory.
func (r *Repo) checkSourcesDir(role string, settings roleSettings, covered map[string]bool) error {
	file := r.path("roles", role, "role.yml")
	switch {
	case slices.Contains(settings.Children, sourcesDir):
		return fmt.Errorf("%s: children: %q holds files' sources, so can't be a child role", file, sourcesDir)
	case covered[sourcesDir]:
		return fmt.Errorf("%s: %q holds files' sources, so can't be in compose.files", file, sourcesDir)
	default:
		return nil
	}
}

// checkCompose records the role's volumes and stack, returning the names of
// the role directory's entries its stack's files cover.
func (r *Repo) checkCompose(role string, settings roleSettings, isStack bool) (map[string]bool, error) {
	var volumes map[string]Perms
	if settings.Compose != nil {
		volumes = settings.Compose.Volumes
	}
	volumes, err := r.partialVolumes(role, volumes)
	if err != nil {
		return nil, err
	}
	if err := r.checkVolumes(role, volumes); err != nil {
		return nil, err
	}
	if isStack {
		return r.checkStack(role, settings)
	}
	if settings.Compose != nil && len(settings.Compose.Files) > 0 {
		return nil, fmt.Errorf(
			"%s: compose.files needs a %s, in the role or one of its partials",
			r.path("roles", role, "role.yml"),
			host.ComposeFile,
		)
	}
	hasEnv := settings.Compose != nil && !isNull(settings.Compose.Env.node)
	if hasEnv || slices.ContainsFunc(r.rolePartials[role], func(u partialUse) bool { return u.def.hasEnv }) {
		return nil, fmt.Errorf(
			"%s: compose.env needs a %s, in the role or one of its partials",
			r.path("roles", role, "role.yml"),
			host.ComposeFile,
		)
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

// findTags returns every tag in node, in order, looking through anchors.
func findTags(node ast.Node, tag string) []*ast.TagNode {
	var found []*ast.TagNode
	switch n := node.(type) {
	case *ast.TagNode:
		if n.Start.Value == tag {
			return []*ast.TagNode{n}
		}
		return findTags(n.Value, tag)
	case *ast.AnchorNode:
		return findTags(n.Value, tag)
	case *ast.MappingNode:
		for _, mv := range n.Values {
			found = append(found, findTags(mv.Value, tag)...)
		}
	case *ast.MappingValueNode:
		return findTags(n.Value, tag)
	case *ast.SequenceNode:
		for _, item := range n.Values {
			found = append(found, findTags(item, tag)...)
		}
	default:
	}
	return found
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

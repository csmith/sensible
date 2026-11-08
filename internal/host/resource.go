package host

import (
	"context"
	"errors"
	"io/fs"
	"strings"
)

// AgentPath is where bootstrap installs the agent.
const AgentPath = "/usr/local/libexec/sensible-agent"

// Resource is one piece of desired state on a host. Resources are values:
// they're built by features on the controller, sent to the agent as JSON,
// and checked and applied there.
type Resource interface {
	// ID identifies the resource, e.g. "file:/etc/ssh/sshd_config.d/10-sensible.conf".
	// Handlers with the same ID are run once.
	ID() string
	// Check reports whether the host already matches. It must not change
	// anything. It returns ErrNotYetCheckable when the answer depends on
	// something an earlier resource would change (e.g. a package from a
	// repository that isn't added yet).
	Check(ctx context.Context, sys Sys) (Change, error)
	// Apply makes the host match. It's only called after Check reported a
	// drift, and should re-check rather than assume.
	Apply(ctx context.Context, sys Sys) error
}

// Notifier is implemented by resources that trigger handlers when they
// change. Handlers run once each, after the host's other resources. One
// that doesn't succeed is run again on the next apply.
type Notifier interface {
	Notifies() ResourceList
}

// Pruner is implemented by resources that find leftovers they won't remove
// during an apply, such as data from removed stacks. The prune command
// offers to remove each one.
type Pruner interface {
	// Leftovers lists what could be removed, each item describing itself.
	// It must not change anything.
	Leftovers(ctx context.Context, sys Sys) ([]string, error)
	// Prune removes one of the items Leftovers listed.
	Prune(ctx context.Context, sys Sys, item string) error
}

// leftoverWarning is the Change for the Check of the Pruner with the given
// ID, warning about its leftovers that aren't ignored without changing them.
func leftoverWarning(ctx context.Context, id string, leftovers []string, why string) Change {
	leftovers = state(ctx).unignored(id, leftovers)
	if len(leftovers) == 0 {
		return Change{InSync: true}
	}
	return Change{
		InSync: true,
		Warning: strings.Join(leftovers, "\n") + "\n" + why +
			"; run `sensible prune` to remove them once they're not needed\n",
	}
}

var ErrNotYetCheckable = errors.New("can't be checked until earlier changes are applied")

type Change struct {
	InSync bool
	// Diff is a human-readable description of what would change.
	Diff string
	// Warning describes drift that won't be changed, e.g. because changing
	// it would be disruptive.
	Warning string
}

// Facts describe a host, as gathered by its agent.
type Facts struct {
	// OSFamily is "arch" or "debian".
	OSFamily string `json:"os_family"`
	// Distro is the os-release ID, e.g. "debian" or "ubuntu".
	Distro string `json:"distro"`
	// Release is the distribution's codename, e.g. "bookworm". Empty on Arch.
	Release string `json:"release"`
	// Arch is the machine as reported by uname, e.g. "x86_64" or "aarch64".
	Arch        string `json:"arch"`
	DefaultIPv4 string `json:"default_ipv4"`
	DefaultIPv6 string `json:"default_ipv6"`
}

type PasswdUser struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
	// Comment is the GECOS field.
	Comment string `json:"comment"`
	Home    string `json:"home"`
	Shell   string `json:"shell"`
}

var resourceTypes = registry(
	File{},
	Dir{},
	Absent{},
	Disowned{},
	Symlink{},
	Package{},
	AptRepo{},
	DisownedAptSources{},
	AURPackage{},
	DisownedPackages{},
	PackageUpdate{},
	Service{},
	ServiceAction{},
	User{},
	Users{},
	GroupMembers{},
	GitCheckout{},
	LineInFile{},
	CommentOut{},
	Download{},
	Command{},
	OwnedDir{},
	ComposeStack{},
	ComposeProjects{},
	Volumes{},
	Migration{},
	Migrations{},
	CertRecord{},
	CertRecords{},
	TailscaleSet{},
	DockerNetwork{},
	DockerNetworks{},
	SystemdReload{},
	ServiceRestart{},
	SystemdUnits{},
	KeptLeftovers{},
)

// File manages a regular file.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	// Owner is a user name or numeric ID. Empty leaves an existing file's
	// owner alone, and new files are owned by root.
	Owner string `json:"owner"`
	// Group is a group name or numeric ID. Empty means the owner's primary
	// group if Owner is a name, and is otherwise left alone.
	Group string `json:"group"`
	// Mode zero leaves an existing file's mode alone, and new files get 0644.
	Mode fs.FileMode `json:"mode"`
	// Validate is run against a temporary copy before it replaces Path, with
	// "%s" replaced by the temporary path, e.g. ["visudo", "-cf", "%s"].
	Validate []string     `json:"validate,omitempty"`
	Notify   ResourceList `json:"notify,omitempty"`
	// Secrets are replaced with a placeholder wherever they appear in diffs.
	// Old values that are no longer in Content can't be, so they still show
	// in a diff that changes them.
	Secrets []string `json:"secrets,omitempty"`
	// Hidden leaves the content out of diffs entirely.
	Hidden bool `json:"hidden,omitempty"`
}

// Dir manages a directory. Missing parents are created too.
type Dir struct {
	Path string `json:"path"`
	// Owner and Group are treated as they are for File.
	Owner string `json:"owner"`
	Group string `json:"group"`
	// Mode zero leaves an existing directory's mode alone, and new ones get
	// 0755.
	Mode fs.FileMode `json:"mode"`
}

// Absent removes whatever is at a path, recursively.
type Absent struct {
	Path string `json:"path"`
}

// Disowned warns about what's at Paths that nothing earlier in the same run
// declares, such as files a feature wrote before it was turned off.
// Applying never removes them, but pruning does.
type Disowned struct {
	// Name says what wrote them, e.g. "docker", and identifies the resource.
	Name string `json:"name"`
	// Paths may be glob patterns.
	Paths []string `json:"paths"`
	// Header, if set, limits it to regular files that start with it, so
	// files written by hand are left alone.
	Header string `json:"header,omitempty"`
	// Target, if set, limits it to symlinks to Target.
	Target string `json:"target,omitempty"`
	// Recorded limits it to regular files that are as their WrittenRecord
	// says, for files that can't have a Header. Applying forgets the
	// records of files that have changed or gone since.
	Recorded bool `json:"recorded,omitempty"`
	// Records, if set, is the directory of WrittenRecords to use in place
	// of WrittenDir, and the files they record are checked along with
	// Paths, limited as for Recorded. It's for files at paths that aren't
	// known in advance.
	Records string `json:"records,omitempty"`
	// Notify is applied after each item is pruned, e.g. to reload a service
	// that read it.
	Notify ResourceList `json:"notify,omitempty"`
}

type Symlink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// Package manages a package with the OS's package manager.
type Package struct {
	Name string `json:"name"`
	// Deb is a local .deb file to install, on Debian only. Name must still
	// be the package's name, and the file is reinstalled if its version
	// differs from the installed one.
	Deb string `json:"deb,omitempty"`
	// Absent removes the package instead.
	Absent bool `json:"absent,omitempty"`
	// Record marks the package as sensible's when it installs it, so a
	// DisownedPackages can tell it from one installed by hand.
	Record bool `json:"record,omitempty"`
}

// AptRepo manages a deb822 apt source. Changing it makes later Package
// resources refresh the package index.
type AptRepo struct {
	// Name names /etc/apt/sources.list.d/<Name>.sources, and the signing key
	// at /etc/apt/keyrings/<Name>.asc (or .gpg if it isn't armored).
	Name          string   `json:"name"`
	URIs          []string `json:"uris"`
	Suites        []string `json:"suites"`
	Components    []string `json:"components"`
	SigningKeyURL string   `json:"signing_key_url"`
}

// DisownedAptSources warns about the apt sources in AptSourcesDir that no
// AptRepo earlier in the same run declared, and the keys in AptKeyringsDir
// that no AptRepo declared and no source refers to. They may be the
// distribution's own, so applying never removes them, but pruning does.
type DisownedAptSources struct{}

// AURPackage installs a package from the AUR with paru.
type AURPackage struct {
	Name string `json:"name"`
	// BuildUser runs paru, as makepkg refuses to run as root.
	BuildUser string `json:"build_user"`
	// Record is as for Package.
	Record bool `json:"record,omitempty"`
}

// DisownedPackages warns about the packages sensible installed with Record
// that no Package or AURPackage earlier in the same run declares. Applying
// forgets the records of packages that have gone since, and never removes
// the packages, but pruning does.
type DisownedPackages struct{}

// PackageUpdate brings every installed package up to date: pacman -Syu on
// Arch, which doesn't rebuild AUR packages, and apt-get full-upgrade on
// Debian, so upgrades that need new packages, such as a new kernel's, aren't
// held back. It's always drifted, so it's only added on request. It never
// reboots, but warns once applied if the host needs a reboot to run its
// newest kernel.
type PackageUpdate struct{}

// Service manages a systemd unit's state.
type Service struct {
	Name string `json:"name"`
	// Enabled false disables the unit.
	Enabled bool `json:"enabled"`
	// Running false stops the unit.
	Running bool `json:"running"`
	// Masked stops and masks the unit, and Enabled and Running are ignored.
	// Otherwise, a masked unit is unmasked.
	Masked bool `json:"masked,omitempty"`
}

// ServiceAction acts on a unit every time it's applied, so it's only useful
// as a handler.
type ServiceAction struct {
	Name string `json:"name"`
	// Action is "reload" or "restart". Reloading a unit that isn't running
	// starts it instead.
	Action string `json:"action"`
}

// User manages an account. New accounts get a home directory.
type User struct {
	Name   string `json:"name"`
	Absent bool   `json:"absent,omitempty"`
	// System only affects new accounts.
	System bool `json:"system,omitempty"`
	// Home and Shell are left alone if empty. Changing Home doesn't move
	// the directory.
	Home  string `json:"home,omitempty"`
	Shell string `json:"shell,omitempty"`
	// Groups are added to, never removed from.
	Groups []string `json:"groups,omitempty"`
	// Password is a crypt(3) hash, or "!" to lock the account. Empty leaves
	// it alone.
	Password string `json:"password,omitempty"`
	// Managed marks the account as sensible's in its GECOS field, so Users
	// can find it once nothing declares it.
	Managed bool `json:"managed,omitempty"`
}

// Users warns about the accounts marked as sensible's that no User earlier
// in the same run declared. System accounts are never included. Applying
// never removes them, but pruning removes each account, and its home if it
// owns it.
type Users struct{}

// GroupMembers removes a group's members that aren't in Members. It never
// adds them, which User does.
type GroupMembers struct {
	Group   string   `json:"group"`
	Members []string `json:"members"`
}

// GitCheckout keeps a shallow clone of a repository at a commit, discarding
// local changes when it moves.
type GitCheckout struct {
	Path string `json:"path"`
	// Repo becomes the checkout's origin.
	Repo string `json:"repo"`
	// Commit is a full hash.
	Commit string `json:"commit"`
	// Owner runs git, and owns a new checkout. Empty means root.
	Owner string `json:"owner,omitempty"`
}

// LineInFile manages one line of an existing file, as Ansible's lineinfile
// does.
type LineInFile struct {
	Path string `json:"path"`
	// Regexp finds the line to replace. If several match, the last one is
	// replaced.
	Regexp string `json:"regexp"`
	Line   string `json:"line"`
	// InsertBefore is where Line goes when no line matches Regexp and Line
	// isn't already present: before the first line it matches. Empty, or no
	// match, appends it.
	InsertBefore string `json:"insert_before,omitempty"`
	// Absent removes every line matching Regexp instead, ignoring Line. A
	// missing file is then in sync.
	Absent bool         `json:"absent,omitempty"`
	Notify ResourceList `json:"notify,omitempty"`
}

// CommentOut comments out lines across a set of files by prefixing "# ".
type CommentOut struct {
	Glob string `json:"glob"`
	// Regexp is matched against uncommented lines.
	Regexp string `json:"regexp"`
}

// Download fetches a file, verifying its checksum.
type Download struct {
	URL  string `json:"url"`
	Path string `json:"path"`
	// SHA256 is hex-encoded. A file that doesn't match it is downloaded
	// again.
	SHA256 string `json:"sha256"`
	// Mode is treated as it is for File.
	Mode fs.FileMode `json:"mode"`
}

// Command is an escape hatch for state no other resource manages.
type Command struct {
	Name string `json:"name"`
	// CheckArgv exiting 0 means in sync. Any other status, or the program
	// not existing, means ApplyArgv is run.
	CheckArgv []string `json:"check"`
	// Watch, if set, replaces CheckArgv: ApplyArgv runs only if one of the
	// resources with these IDs changed earlier in the run, or since it last
	// ran.
	Watch     []string `json:"watch,omitempty"`
	ApplyArgv []string `json:"apply"`
	// User runs both commands. Empty means root.
	User string `json:"user,omitempty"`
	// Env is added to both commands' environment.
	Env map[string]string `json:"env,omitempty"`
	// Packages are installed by ApplyArgv, so they count as declared.
	Packages []string `json:"packages,omitempty"`
}

// OwnedDir removes every entry in Path that no File, Dir or AptRepo earlier
// in the same run declared. It's skipped if anything on the host failed.
type OwnedDir struct {
	Path string `json:"path"`
	// Recursive also cleans the declared directories inside Path.
	Recursive bool `json:"recursive,omitempty"`
	// Header, if set, limits removal to regular files that start with it.
	// The other undeclared entries may be the distribution's, so they're
	// only warned about, and left for pruning.
	Header string `json:"header,omitempty"`
	// Notify is applied after a change, and after each item is pruned.
	Notify ResourceList `json:"notify,omitempty"`
}

// ComposeStack keeps a Docker Compose project's containers up. Dir holds its
// docker-compose.yml, and its name is the project's name.
type ComposeStack struct {
	Dir string `json:"dir"`
	// Watch are the IDs of the resources that manage the stack's files. If
	// any of them changed earlier in the run, or since the stack was last
	// applied, the whole stack is recreated.
	Watch []string `json:"watch"`
}

// ComposeProjects takes down and removes each project directory in Path
// that no ComposeStack earlier in the same run declared. Volumes are kept.
// It's skipped if anything on the host failed.
type ComposeProjects struct {
	Path string `json:"path"`
}

// Volumes warns about the volume directories in Path that no Dir earlier in
// the same run declared, and about the stacks' directories in Path with none
// declared. Applying never removes them, but pruning does.
type Volumes struct {
	Path string `json:"path"`
}

// DockerNetwork creates a Docker network, labelled as sensible's. An
// existing network whose settings differ is left alone with a warning, as
// changing them means recreating it, disconnecting every container.
type DockerNetwork struct {
	Name string `json:"name"`
	// Subnets are in CIDR form. Empty lets Docker choose, and isn't checked.
	Subnets []string `json:"subnets,omitempty"`
	IPv6    bool     `json:"ipv6,omitempty"`
}

// DockerNetworks removes networks sensible created that no DockerNetwork
// earlier in the same run declared. It's skipped if anything on the host
// failed.
type DockerNetworks struct{}

// SystemdReload runs `systemctl daemon-reload` where it's listed, rather
// than as a handler, so units written earlier in the run can be started
// later in it.
type SystemdReload struct {
	// Watch are the IDs of the resources that manage unit files. It does
	// nothing unless one of them changed earlier in the run, or since it
	// last reloaded.
	Watch []string `json:"watch"`
}

// ServiceRestart restarts a unit where it's listed, rather than as a handler,
// so what comes later in the run uses the config written earlier in it.
type ServiceRestart struct {
	Name string `json:"name"`
	// Watch are the IDs of the resources that manage the unit's config. It
	// does nothing unless one of them changed earlier in the run, or since
	// it last restarted.
	Watch []string `json:"watch"`
}

// SystemdUnits stops, disables and removes the unit files in
// /etc/systemd/system whose names start with Prefix that no File earlier in
// the same run declared. It's skipped if anything on the host failed.
type SystemdUnits struct {
	Prefix string `json:"prefix"`
}

// TailscaleSet applies settings with `tailscale set`. It fails if Tailscale
// isn't logged in.
type TailscaleSet struct {
	// Settings are flag names without "--", and their values. Known flags
	// are checked against `tailscale debug prefs`; others are always set.
	Settings map[string]string `json:"settings"`
}

// KeptLeftovers keeps leftovers that match its glob patterns out of every
// Pruner later in the same run, so they're neither warned about nor pruned.
type KeptLeftovers struct {
	Paths    []string `json:"paths,omitempty"`
	Packages []string `json:"packages,omitempty"`
	// External warns about each pattern nothing on the host matches.
	External bool `json:"external,omitempty"`
}

func (r File) ID() string             { return "file:" + r.Path }
func (r File) Notifies() ResourceList { return r.Notify }

func (r Dir) ID() string { return "dir:" + r.Path }

func (r Absent) ID() string { return "absent:" + r.Path }

func (r Disowned) ID() string { return "disowned:" + r.Name }

func (r Symlink) ID() string { return "symlink:" + r.Path }

func (r Package) ID() string { return "package:" + r.Name }

func (r AptRepo) ID() string { return "apt-repo:" + r.Name }

func (r DisownedAptSources) ID() string { return "disowned-apt-sources" }

func (r AURPackage) ID() string { return "aur:" + r.Name }

func (r DisownedPackages) ID() string { return "disowned-packages" }

func (r PackageUpdate) ID() string { return "package-update" }

func (r Service) ID() string { return "service:" + r.Name }

func (r ServiceAction) ID() string { return r.Action + ":" + r.Name }

func (r User) ID() string { return "user:" + r.Name }

func (r Users) ID() string { return "users" }

func (r GroupMembers) ID() string { return "group-members:" + r.Group }

func (r GitCheckout) ID() string { return "git:" + r.Path }

func (r LineInFile) ID() string             { return "line:" + r.Path + ":" + r.Regexp }
func (r LineInFile) Notifies() ResourceList { return r.Notify }

func (r CommentOut) ID() string { return "comment-out:" + r.Glob + ":" + r.Regexp }

func (r Download) ID() string { return "download:" + r.Path }

func (r Command) ID() string        { return "command:" + r.Name }
func (r Command) watches() []string { return r.Watch }

func (r OwnedDir) ID() string             { return "owned-dir:" + r.Path }
func (r OwnedDir) Notifies() ResourceList { return r.Notify }

func (r ComposeStack) ID() string        { return "compose:" + r.Dir }
func (r ComposeStack) watches() []string { return r.Watch }

func (r ComposeProjects) ID() string { return "compose-projects:" + r.Path }

func (r Volumes) ID() string { return "volumes:" + r.Path }

func (r DockerNetwork) ID() string { return "docker-network:" + r.Name }

func (r DockerNetworks) ID() string { return "docker-networks" }

func (r SystemdReload) ID() string        { return "systemd-reload" }
func (r SystemdReload) watches() []string { return r.Watch }

func (r ServiceRestart) ID() string        { return "service-restart:" + r.Name }
func (r ServiceRestart) watches() []string { return r.Watch }

func (r SystemdUnits) ID() string { return "systemd-units:" + r.Prefix }

func (r TailscaleSet) ID() string { return "tailscale-set" }

func (r KeptLeftovers) ID() string {
	if r.External {
		return "leftovers:external"
	}
	return "leftovers:ignored"
}

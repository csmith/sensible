package host

import (
	"context"
	"errors"
	"io/fs"
)

// AgentPath is where bootstrap installs the agent on remote hosts.
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
// change. Handlers run once each, after the host's other resources.
type Notifier interface {
	Notifies() ResourceList
}

var ErrNotYetCheckable = errors.New("can't be checked until earlier changes are applied")

type Change struct {
	InSync bool
	// Diff is a human-readable description of what would change.
	Diff string
}

// Facts describe a host, as gathered by its agent.
type Facts struct {
	// OSFamily is "arch" or "debian".
	OSFamily string `json:"os_family"`
	// Release is the distribution's codename, e.g. "bookworm". Empty on Arch.
	Release string `json:"release"`
	// Arch is the machine as reported by uname, e.g. "x86_64" or "aarch64".
	Arch        string                `json:"arch"`
	DefaultIPv4 string                `json:"default_ipv4"`
	DefaultIPv6 string                `json:"default_ipv6"`
	Users       map[string]PasswdUser `json:"users"`
}

type PasswdUser struct {
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

var resourceTypes = registry(
	File{},
	Dir{},
	Absent{},
	Symlink{},
	Package{},
	AptRepo{},
	AURPackage{},
	Service{},
	ServiceAction{},
	User{},
	GitCheckout{},
	LineInFile{},
	CommentOut{},
	Download{},
	Command{},
	OwnedDir{},
	TailscaleSet{},
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

// AURPackage installs a package from the AUR with paru.
type AURPackage struct {
	Name string `json:"name"`
	// BuildUser runs paru, as makepkg refuses to run as root.
	BuildUser string `json:"build_user"`
}

// Service manages a systemd unit's state.
type Service struct {
	Name string `json:"name"`
	// Enabled false disables the unit.
	Enabled bool `json:"enabled"`
	// Running false stops the unit.
	Running bool `json:"running"`
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
	InsertBefore string       `json:"insert_before,omitempty"`
	Notify       ResourceList `json:"notify,omitempty"`
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
	ApplyArgv []string `json:"apply"`
	// User runs both commands. Empty means root.
	User string `json:"user,omitempty"`
	// Env is added to both commands' environment.
	Env map[string]string `json:"env,omitempty"`
}

// OwnedDir removes every entry in Path that no File earlier in the same run
// declared. It's skipped if anything on the host failed.
type OwnedDir struct {
	Path   string       `json:"path"`
	Notify ResourceList `json:"notify,omitempty"`
}

// TailscaleSet applies settings with `tailscale set`. It fails if Tailscale
// isn't logged in.
type TailscaleSet struct {
	// Settings are flag names without "--", and their values. Known flags
	// are checked against `tailscale debug prefs`; others are always set.
	Settings map[string]string `json:"settings"`
}

func (r File) ID() string             { return "file:" + r.Path }
func (r File) Notifies() ResourceList { return r.Notify }

func (r Dir) ID() string { return "dir:" + r.Path }

func (r Absent) ID() string { return "absent:" + r.Path }

func (r Symlink) ID() string { return "symlink:" + r.Path }

func (r Package) ID() string { return "package:" + r.Name }

func (r AptRepo) ID() string { return "apt-repo:" + r.Name }

func (r AURPackage) ID() string { return "aur:" + r.Name }

func (r Service) ID() string { return "service:" + r.Name }

func (r ServiceAction) ID() string { return r.Action + ":" + r.Name }

func (r User) ID() string { return "user:" + r.Name }

func (r GitCheckout) ID() string { return "git:" + r.Path }

func (r LineInFile) ID() string             { return "line:" + r.Path + ":" + r.Regexp }
func (r LineInFile) Notifies() ResourceList { return r.Notify }

func (r CommentOut) ID() string { return "comment-out:" + r.Glob + ":" + r.Regexp }

func (r Download) ID() string { return "download:" + r.Path }

func (r Command) ID() string { return "command:" + r.Name }

func (r OwnedDir) ID() string             { return "owned-dir:" + r.Path }
func (r OwnedDir) Notifies() ResourceList { return r.Notify }

func (r TailscaleSet) ID() string { return "tailscale-set" }

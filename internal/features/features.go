package features

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

// Host is everything features may use to decide a host's resources.
type Host struct {
	Name   string
	Local  bool
	Config config.Config
	Facts  host.Facts
	// SensibleKey is the public half of the host's sensible key, as an
	// authorized_keys line without options. Empty for the local host.
	SensibleKey string
}

const (
	archLinux = "arch"
	debian    = "debian"
)

// Resources returns the host's resources, in the order they're applied.
func Resources(h Host) (host.ResourceList, error) {
	switch h.Facts.OSFamily {
	case archLinux:
	case debian:
		if h.Facts.Release == "" {
			return nil, fmt.Errorf("host %s is Debian but its release isn't known", h.Name)
		}
	default:
		return nil, fmt.Errorf("host %s runs %q, which isn't supported", h.Name, h.Facts.OSFamily)
	}

	features := []func(Host) ([]host.Resource, error){
		packages,
		aur,
		hostname,
		timezone,
		locale,
		ntp,
		vim,
		users,
		zsh,
		sudoers,
		pamRSSH,
		loginMessages,
		sshd,
		access,
		tailscale,
		docker,
		// After everything that writes sudoers files.
		sudoersCleanUp,
	}

	var out host.ResourceList
	for _, f := range features {
		rs, err := f(h)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			// Features share dependencies, such as git or the AUR build account,
			// and each declares them. Only the first identical copy is kept.
			if !slices.ContainsFunc(out, func(o host.Resource) bool { return reflect.DeepEqual(o, r) }) {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// SensibleUser is the account remote hosts are managed through.
const SensibleUser = "sensible"

// SensibleHome is the sensible account's home. It's owned by root so the
// account can't plant shell startup files.
const SensibleHome = "/var/lib/sensible"

const sensibleAuthorizedKeysDir = "/etc/ssh/authorized_keys"

// AccessFiles are the root-owned files that let the controller reach a
// remote host's agent. Bootstrap and the access feature both write them.
// They don't notify anything, as the sshd unit's name depends on the OS.
func AccessFiles(sensibleKey string) []host.File {
	return []host.File{
		sudoersFile(
			SensibleUser,
			[]string{
				fmt.Sprintf("Defaults:%s passwd_tries=1, passwd_timeout=1", SensibleUser),
				fmt.Sprintf("%s ALL=(root) %s agent", SensibleUser, host.AgentPath),
			},
		),
		{
			Path: "/etc/ssh/sshd_config.d/05-sensible.conf",
			Content: managedHeader + strings.Join(
				[]string{
					"Match User " + SensibleUser,
					"    AuthenticationMethods publickey",
					"    KbdInteractiveAuthentication no",
					"    PasswordAuthentication no",
					"    AuthorizedKeysFile " + sensibleAuthorizedKeysDir + "/" + SensibleUser,
				},
				"\n",
			) + "\n",
			Owner:    "root",
			Group:    "root",
			Mode:     0o644,
			Validate: sshdValidate,
		},
		{
			Path: sensibleAuthorizedKeysDir + "/" + SensibleUser,
			Content: managedHeader + fmt.Sprintf(
				"restrict,command=\"/usr/bin/sudo -k -S -p '' %s agent\" %s\n",
				host.AgentPath,
				sensibleKey,
			),
			Owner: "root",
			Group: "root",
			Mode:  0o644,
		},
	}
}

// access keeps bootstrap's files in place on remote hosts, so the sudoers
// clean-up or an sshd change can't lock the tool out.
func access(h Host) ([]host.Resource, error) {
	if h.Local {
		return nil, nil
	}
	reload := host.ServiceAction{Name: sshdService(h), Action: "reload"}
	rs := []host.Resource{
		// The shell is /bin/sh, which reads no startup files, and the home is
		// root-owned, so a shell as the account can't capture the sudo password.
		host.User{Name: SensibleUser, System: true, Home: SensibleHome, Shell: "/bin/sh"},
		host.Dir{Path: SensibleHome, Owner: "root", Group: "root", Mode: 0o755},
		host.Dir{Path: sensibleAuthorizedKeysDir, Owner: "root", Group: "root", Mode: 0o755},
	}
	for _, f := range AccessFiles(h.SensibleKey) {
		if strings.HasPrefix(f.Path, "/etc/ssh/sshd_config.d/") {
			f.Notify = host.ResourceList{reload}
		}
		rs = append(rs, f)
	}
	return rs, nil
}

func sudoersCleanUp(Host) ([]host.Resource, error) {
	return []host.Resource{host.OwnedDir{Path: sudoersDir}}, nil
}

const managedHeader = "# Managed by sensible. Local changes will be overwritten.\n"

func managedLines(lines []string) string {
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

const sudoersDir = "/etc/sudoers.d"

func sudoersFile(name string, lines []string) host.File {
	return host.File{
		Path:     sudoersDir + "/" + name,
		Content:  managedLines(lines),
		Owner:    "root",
		Group:    "root",
		Mode:     0o440,
		Validate: []string{"visudo", "-cf", "%s"},
	}
}

func sysctl(name string, settings map[string]string) []host.Resource {
	lines := make([]string, 0, len(settings))
	for _, k := range slices.Sorted(maps.Keys(settings)) {
		lines = append(lines, k+" = "+settings[k])
	}
	return []host.Resource{
		host.File{
			Path:    "/etc/sysctl.d/" + name + ".conf",
			Content: managedLines(lines),
			Owner:   "root",
			Group:   "root",
			Mode:    0o644,
			Notify:  host.ResourceList{host.ServiceAction{Name: "systemd-sysctl", Action: "restart"}},
		},
	}
}

func installPackages(names ...string) []host.Resource {
	rs := make([]host.Resource, len(names))
	for i, n := range names {
		rs[i] = host.Package{Name: n}
	}
	return rs
}

// existingAccount reports false for accounts this run will create, whose
// files are written on the next run.
func existingAccount(h Host, name string) (host.PasswdUser, bool) {
	u, ok := h.Facts.Users[name]
	return u, ok && u.Home != ""
}

// Groups are given by ID, as facts don't include their names.
func gid(u host.PasswdUser) string {
	return strconv.Itoa(u.GID)
}

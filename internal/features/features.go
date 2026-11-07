package features

import (
	"fmt"
	"maps"
	"path"
	"reflect"
	"slices"
	"strings"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

// Host is everything features may use to decide a host's resources.
type Host struct {
	Name   string
	Config config.Config
	Facts  host.Facts
	// SensibleKey is the public half of the host's sensible key, as an
	// authorized_keys line without options.
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
		// First, so what it removes, such as an apt source, can't affect
		// the rest.
		remove,
		aptRepos,
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
		certs,
		stacks,
		backups,
		// After stacks and backups, as jobs may use them.
		jobs,
		// After everything that declares accounts.
		usersCleanUp,
		// After the stacks that may still have been mounting them.
		certsCleanUp,
		// After everything that writes sudoers files or adds apt repos.
		sudoersCleanUp,
		aptCleanUp,
		// Last, so it sees every path the others declare.
		disowned,
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
			if slices.ContainsFunc(out, func(o host.Resource) bool { return reflect.DeepEqual(o, r) }) {
				continue
			}
			// Repos with the same name write the same files, so would undo each
			// other every run.
			repo, ok := r.(host.AptRepo)
			if ok && slices.ContainsFunc(out, func(o host.Resource) bool { return o.ID() == r.ID() }) {
				return nil, fmt.Errorf("host %s: apt repo %s is declared twice with different settings", h.Name, repo.Name)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// SensibleUser is the account hosts are managed through.
const SensibleUser = "sensible"

// SensibleHome is the sensible account's home. It's owned by root so the
// account can't plant shell startup files.
const SensibleHome = "/var/lib/sensible"

const sensibleAuthorizedKeysDir = "/etc/ssh/authorized_keys"

// AccessFiles are the root-owned files that let the controller reach a
// host's agent. Bootstrap and the access feature both write them.
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

// access keeps bootstrap's files in place, so the sudoers
// clean-up or an sshd change can't lock the tool out.
func access(h Host) ([]host.Resource, error) {
	reload := host.ServiceAction{Name: sshdService(h), Action: "reload"}
	files := AccessFiles(h.SensibleKey)
	rs := make([]host.Resource, 0, 3+len(files))
	rs = append(
		rs,
		// The shell is /bin/sh, which reads no startup files, and the home is
		// root-owned, so a shell as the account can't capture the sudo password.
		host.User{Name: SensibleUser, System: true, Home: SensibleHome, Shell: "/bin/sh"},
		host.Dir{Path: SensibleHome, Owner: "root", Group: "root", Mode: 0o755},
		host.Dir{Path: sensibleAuthorizedKeysDir, Owner: "root", Group: "root", Mode: 0o755},
	)
	for _, f := range files {
		if strings.HasPrefix(f.Path, "/etc/ssh/sshd_config.d/") {
			f.Notify = host.ResourceList{reload}
		}
		rs = append(rs, f)
	}
	return rs, nil
}

// disowned reports the files features write that nothing declares any more,
// for prune to remove. Unlike the clean-ups, it's only a warning, as the host
// may still rely on them.
func disowned(h Host) ([]host.Resource, error) {
	homes := []string{"/root", "/home/*"}
	for _, name := range slices.Sorted(maps.Keys(h.Config.Users)) {
		if d := h.Config.Users[name].Home; d != "" && !slices.Contains(homes, d) {
			homes = append(homes, d)
		}
	}
	inHomes := func(name string) []string {
		paths := make([]string, len(homes))
		for i, d := range homes {
			paths[i] = path.Join(d, name)
		}
		return paths
	}
	rs := []host.Resource{
		host.Disowned{
			Name:   "sshd",
			Paths:  append([]string{sshdDropIn, sshdListenDropIn}, inHomes(".ssh/authorized_keys")...),
			Header: managedMark,
			Notify: host.ResourceList{
				host.ServiceAction{Name: sshdService(h), Action: "reload"},
				sshdSocketRestart(h),
			},
		},
		host.Disowned{Name: "zsh", Paths: inHomes(".zshrc"), Header: managedMark},
		host.Disowned{Name: "oh-my-zsh", Paths: []string{ohMyZshPath}},
		host.Disowned{Name: "pam_rssh", Paths: []string{sudoersKeys}, Header: managedMark},
		host.Disowned{Name: "tailscale", Paths: []string{tailscaleSysctl}, Header: managedMark},
		// Docker reads its settings only when it starts, and restarting it
		// would stop the containers, so it's left to pick up the change.
		host.Disowned{Name: "docker", Paths: []string{dockerDaemonFile, dockerClientFile}, Recorded: true},
	}
	switch h.Facts.OSFamily {
	case debian:
		rs = append(rs, host.Disowned{Name: "pam_rssh package", Paths: []string{pamRSSHDebGlob}})
	case archLinux:
		links := make([]string, len(vimLinks))
		for i, n := range vimLinks {
			links[i] = vimLinkDir + "/" + n
		}
		rs = append(rs, host.Disowned{Name: "vim", Paths: links, Target: vimBinary})
	}
	return rs, nil
}

func sudoersCleanUp(Host) ([]host.Resource, error) {
	return []host.Resource{host.OwnedDir{Path: sudoersDir}}, nil
}

// managedMark starts every file sensible writes with a comment header.
const managedMark = "# Managed by sensible."

const managedHeader = managedMark + " Local changes will be overwritten.\n"

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

func sysctl(file string, settings map[string]string) []host.Resource {
	lines := make([]string, 0, len(settings))
	for _, k := range slices.Sorted(maps.Keys(settings)) {
		lines = append(lines, k+" = "+settings[k])
	}
	return []host.Resource{
		host.File{
			Path:    file,
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

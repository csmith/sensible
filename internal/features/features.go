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
		// Before anything that lists leftovers.
		leftovers,
		// Next, so what it removes, such as an apt source, can't affect
		// the rest.
		remove,
		aptRepos,
		pacmanRepos,
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
		// Before jobs, whose clean-up removes its unit once it's turned off.
		firewall,
		certs,
		stacks,
		backups,
		// Before the files that may go in them.
		directories,
		// After the packages and accounts they may be for.
		files,
		// After the packages that install units.
		services,
		// After stacks, backups and files, as jobs may use them.
		jobs,
		// After everything that declares accounts.
		usersCleanUp,
		// After the stacks that may still have been mounting them.
		certsCleanUp,
		// After everything that writes sudoers files.
		sudoersCleanUp,
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
				return nil, fmt.Errorf(
					"host %s: apt repo %s is declared twice with different settings",
					h.Name,
					repo.Name,
				)
			}
			// As can files, such as one in files that a feature also writes.
			file, ok := r.(host.File)
			if ok && slices.ContainsFunc(out, func(o host.Resource) bool { return o.ID() == r.ID() }) {
				return nil, fmt.Errorf(
					"host %s: %s is written twice with different content or settings",
					h.Name,
					file.Path,
				)
			}
			// And directories, other than those that only need to exist.
			dir, ok := r.(host.Dir)
			if ok && dir != (host.Dir{Path: dir.Path}) && slices.ContainsFunc(
				out,
				func(o host.Resource) bool {
					d, ok := o.(host.Dir)
					return ok && d.Path == dir.Path && d != (host.Dir{Path: d.Path})
				},
			) {
				return nil, fmt.Errorf("host %s: directory %s is given different ownership or modes", h.Name, dir.Path)
			}
			// And services, such as one in services that a feature also runs.
			svc, ok := r.(host.Service)
			if ok && slices.ContainsFunc(out, func(o host.Resource) bool { return o.ID() == r.ID() }) {
				return nil, fmt.Errorf("host %s: service %s is given two different states", h.Name, svc.Name)
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

// AccessFiles are the root-owned files that let any of sensibleKeys reach
// the host's agent. They notify nothing, as sshd's unit name varies by OS.
func AccessFiles(sensibleKeys ...string) []host.File {
	return accessFiles(
		[]string{
			fmt.Sprintf("Defaults:%s passwd_tries=1, passwd_timeout=1", SensibleUser),
			fmt.Sprintf("%s ALL=(root) %s agent", SensibleUser, host.AgentPath),
		},
		sensibleKeys,
	)
}

// BootstrapAccessFiles are AccessFiles whose sudo needs no password, for a
// bootstrap binary, which locks the account's password instead.
func BootstrapAccessFiles(bootstrapKey string) []host.File {
	return accessFiles(
		[]string{fmt.Sprintf("%s ALL=(root) NOPASSWD: %s agent", SensibleUser, host.AgentPath)},
		[]string{bootstrapKey},
	)
}

func accessFiles(sudoers, sensibleKeys []string) []host.File {
	var keys strings.Builder
	for _, k := range sensibleKeys {
		_, _ = fmt.Fprintf(&keys, "restrict,command=\"/usr/bin/sudo -k -S -p '' %s agent\" %s\n", host.AgentPath, k)
	}
	return []host.File{
		sudoersFile(SensibleUser, sudoers),
		{
			Path: "/etc/ssh/sshd_config.d/05-sensible.conf",
			Content: managedHeader + strings.Join(
				[]string{
					"Match User " + SensibleUser,
					"    AuthenticationMethods publickey",
					"    PubkeyAuthentication yes",
					"    KbdInteractiveAuthentication no",
					"    PasswordAuthentication no",
					"    AuthorizedKeysFile " + sensibleAuthorizedKeysDir + "/" + SensibleUser,
					"    AuthorizedKeysCommand none",
					"    AuthorizedPrincipalsCommand none",
					"    AuthorizedPrincipalsFile none",
					"    TrustedUserCAKeys none",
				},
				"\n",
			) + "\n",
			Owner:    "root",
			Group:    "root",
			Mode:     0o644,
			Validate: sshdValidate,
		},
		{
			Path:    sensibleAuthorizedKeysDir + "/" + SensibleUser,
			Content: managedHeader + keys.String(),
			Owner:   "root",
			Group:   "root",
			Mode:    0o644,
		},
	}
}

// access keeps what bootstrap set up in place, so the sudoers clean-up or
// prune can't remove it. The access drop-in's Match block overrides global
// authentication settings for the account, but not access lists such as
// AllowUsers, so the sshd feature rejects those that would shut it out.
func access(h Host) ([]host.Resource, error) {
	reload := host.ServiceAction{Name: sshdService(h), Action: "reload"}
	files := AccessFiles(h.SensibleKey)
	rs := make([]host.Resource, 0, 5+len(files))
	rs = append(
		rs,
		host.Package{Name: "sudo"},
		host.Package{Name: sshdPackage(h)},
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

// directoriesRecords holds the records of the directories in the
// directories setting, so that prune finds those nothing declares any more.
const directoriesRecords = host.WrittenDir + "/directories"

// directories makes the directories roles give, parents first.
func directories(h Host) ([]host.Resource, error) {
	if len(h.Config.Directories) == 0 {
		return nil, nil
	}
	rs := []host.Resource{
		host.Dir{Path: host.WrittenDir, Owner: "root", Group: "root", Mode: 0o700},
		host.Dir{Path: directoriesRecords, Owner: "root", Group: "root", Mode: 0o700},
	}
	dirs := slices.SortedFunc(
		slices.Values(h.Config.Directories),
		func(a, b config.DirectoryConfig) int { return strings.Compare(a.Path, b.Path) },
	)
	for _, d := range dirs {
		rs = append(
			rs,
			host.Dir{Path: d.Path, Owner: d.Owner, Group: d.Group, Mode: d.Mode},
			host.DirRecordIn(directoriesRecords, d.Path),
		)
	}
	return rs, nil
}

// filesRecords holds the records of the files in the files setting, apart
// from features' own, so that prune finds those nothing declares any more.
const filesRecords = host.WrittenDir + "/files"

// files writes the files roles give as they are.
func files(h Host) ([]host.Resource, error) {
	if len(h.Config.Files) == 0 {
		return nil, nil
	}
	rs := []host.Resource{
		host.Dir{Path: host.WrittenDir, Owner: "root", Group: "root", Mode: 0o700},
		host.Dir{Path: filesRecords, Owner: "root", Group: "root", Mode: 0o700},
	}
	declared := map[string]bool{}
	for _, d := range h.Config.Directories {
		declared[d.Path] = true
	}
	for _, f := range h.Config.Files {
		file := host.File{
			Path:    f.Path,
			Content: f.Data,
			Owner:   f.Owner,
			Group:   f.Group,
			Mode:    f.Mode,
			Hidden:  f.Hidden,
		}
		record := host.WrittenRecordIn(filesRecords, file)
		if f.AcceptRemote {
			file.Record = record.Path
		}
		// Without an owner or mode, a directory that already exists is left
		// alone, and a missing one is created like its parents, as root:root
		// 0755.
		if !declared[path.Dir(f.Path)] {
			rs = append(rs, host.Dir{Path: path.Dir(f.Path)})
		}
		rs = append(rs, file, record)
	}
	return rs, nil
}

// services puts the units roles list in the state they give.
func services(h Host) ([]host.Resource, error) {
	rs := make([]host.Resource, 0, len(h.Config.Services))
	for _, name := range slices.Sorted(maps.Keys(h.Config.Services)) {
		state := h.Config.Services[name]
		rs = append(
			rs,
			host.Service{
				Name:    name,
				Enabled: state == config.ServiceEnabled,
				Masked:  state == config.ServiceMasked,
			},
		)
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
		host.Disowned{
			Name:   "zsh",
			Paths:  inHomes(".zshrc"),
			Header: managedMark,
		},
		host.Disowned{
			Name:  "oh-my-zsh",
			Paths: []string{ohMyZshPath},
		},
		host.Disowned{
			Name:   "pam_rssh",
			Paths:  []string{sudoersKeys},
			Header: managedMark,
		},
		host.Disowned{
			Name:   "tailscale",
			Paths:  []string{tailscaleSysctl},
			Header: managedMark,
		},
		host.DisownedTailscale{},
		// Docker reads its settings only when it starts, and restarting it
		// would stop the containers, so it's left to pick up the change.
		host.Disowned{
			Name:    "docker",
			Paths:   []string{dockerDaemonFile, dockerClientFile},
			Records: host.WrittenDir,
		},
		host.Disowned{
			Name:    "files",
			Records: filesRecords,
		},
		// After files, which may be in them.
		host.Disowned{
			Name:    "directories",
			Records: directoriesRecords,
			Dirs:    true,
		},
		host.DisownedPackages{},
	}
	switch h.Facts.OSFamily {
	case debian:
		rs = append(
			rs,
			host.Disowned{
				Name:  "pam_rssh package",
				Paths: []string{pamRSSHDebGlob},
			},
			// Declaring any repo takes over the distribution's, so the old
			// sources.list is left over too.
			host.DisownedAptSources{SourcesList: len(h.Config.AptRepos) > 0},
		)
	case archLinux:
		links := make([]string, len(vimLinks))
		for i, n := range vimLinks {
			links[i] = vimLinkDir + "/" + n
		}
		rs = append(rs, host.Disowned{Name: "vim", Paths: links, Target: vimBinary}, host.DisownedPacmanRepos{})
	}
	return rs, nil
}

func sudoersCleanUp(Host) ([]host.Resource, error) {
	return []host.Resource{
		host.OwnedDir{Path: sudoersDir, Header: managedMark},
	}, nil
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
			Notify: host.ResourceList{
				host.ServiceAction{Name: "systemd-sysctl", Action: "restart"},
			},
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

// recordedPackages installs packages that prune may offer to remove once
// nothing declares them. Packages other things may rely on, such as a login
// shell, use installPackages instead.
func recordedPackages(names ...string) []host.Resource {
	rs := make([]host.Resource, len(names))
	for i, n := range names {
		rs[i] = host.Package{Name: n, Record: true}
	}
	return rs
}

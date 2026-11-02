package features

import (
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

func aptRepos(h Host) ([]host.Resource, error) {
	if len(h.Config.AptRepos) == 0 {
		return nil, nil
	}
	if h.Facts.OSFamily != debian {
		return nil, fmt.Errorf("host %s: apt_repos only works on Debian", h.Name)
	}
	var rs []host.Resource
	for _, name := range slices.Sorted(maps.Keys(h.Config.AptRepos)) {
		c := h.Config.AptRepos[name]
		switch {
		case !jobName.MatchString(name):
			return nil, fmt.Errorf(
				"host %s: invalid apt repo name %q; use lower case letters, digits, \"-\" and \"_\"",
				h.Name,
				name,
			)
		case len(c.URIs) == 0 || len(c.Suites) == 0 || c.SigningKeyURL == "":
			return nil, fmt.Errorf("host %s: apt repo %s needs uris, suites and signing_key_url", h.Name, name)
		}
		rs = append(
			rs,
			host.AptRepo{
				Name:          name,
				URIs:          c.URIs,
				Suites:        c.Suites,
				Components:    c.Components,
				SigningKeyURL: c.SigningKeyURL,
			},
		)
	}
	return rs, nil
}

// aptCleanUp removes the apt sources and keys that no repo declared.
func aptCleanUp(h Host) ([]host.Resource, error) {
	if h.Facts.OSFamily != debian {
		return nil, nil
	}
	return []host.Resource{
		host.OwnedDir{Path: host.AptSourcesDir},
		host.OwnedDir{Path: host.AptKeyringsDir},
	}, nil
}

func packages(h Host) ([]host.Resource, error) {
	c := h.Config.Packages
	if c == nil {
		return nil, nil
	}
	// Removed before anything is installed, so they can be replaced by
	// packages that conflict with them.
	rs := make([]host.Resource, 0, len(c.Remove)+len(c.Install))
	for _, n := range c.Remove {
		rs = append(rs, host.Package{Name: n, Absent: true})
	}
	return append(rs, installPackages(c.Install...)...), nil
}

func aur(h Host) ([]host.Resource, error) {
	if h.Config.AUR == nil {
		return nil, nil
	}
	return aurPackages(h, h.Config.AUR.Packages...)
}

const aurUser = "aur"

const aurHome = "/var/lib/" + aurUser

// paru's release profile optimises the whole program at once, which takes
// more memory than small hosts have. makepkg leaves files the build account
// can't remove, so the build directory is removed as root.
const paruInstallScript = `set -eu
dir=$(runuser -u ` + aurUser + ` -- mktemp -d -t paru.XXXXXXXXXX)
trap 'rm -rf "$dir"' EXIT
cd "$dir"
runuser -u ` + aurUser + ` -- env HOME=` + aurHome + ` git clone --depth 1 https://aur.archlinux.org/paru.git "$dir"
runuser -u ` + aurUser + ` -- env HOME=` + aurHome + ` \
  CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  makepkg --syncdeps --rmdeps --install --noconfirm
`

func aurPackages(h Host, names ...string) ([]host.Resource, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if h.Facts.OSFamily != archLinux {
		return nil, fmt.Errorf("host %s: the AUR is only available on Arch Linux", h.Name)
	}
	rs := installPackages("base-devel", "git")
	rs = append(
		rs,
		// makepkg refuses to run as root.
		host.User{Name: aurUser, System: true, Home: aurHome, Shell: "/usr/bin/nologin", Password: "!"},
		host.Dir{Path: aurHome, Owner: aurUser, Group: aurUser, Mode: 0o700},
		sudoersFile(aurUser, []string{aurUser + " ALL=(root) NOPASSWD: /usr/bin/pacman"}),
		// paru stops working when pacman's library changes version, until it's
		// rebuilt, so check it runs rather than that it's installed.
		host.Command{
			Name:      "install paru",
			CheckArgv: []string{"paru", "--version"},
			ApplyArgv: []string{"sh", "-c", paruInstallScript},
		},
	)
	for _, n := range names {
		rs = append(rs, host.AURPackage{Name: n, BuildUser: aurUser})
	}
	return rs, nil
}

func vim(h Host) ([]host.Resource, error) {
	if h.Config.Vim == nil {
		return nil, nil
	}
	rs := installPackages("vim")
	// Debian's vim package already links these to it.
	if h.Facts.OSFamily != archLinux {
		return rs, nil
	}
	// In /usr/local/bin, which comes first in PATH, so they don't clash with
	// packages' files.
	for _, n := range []string{"edit", "ex", "vedit", "vi", "view"} {
		rs = append(rs, host.Symlink{Path: "/usr/local/bin/" + n, Target: "/usr/bin/vim"})
	}
	return rs, nil
}

const (
	pamRSSHRelease    = "v1.2.2-rc2"
	pamRSSHDebVersion = "1.2.2-1"
)

var pamRSSHDebChecksums = map[string]string{
	"debian-bookworm-amd64-pam-rssh_1.2.2-1_amd64.deb": "677ccb5b39a34265721c096b0efd39b21719bcf1bd6a24cff54d36de446e355b",
	"debian-bookworm-arm64-pam-rssh_1.2.2-1_arm64.deb": "266b94935d3174995cd8f91468ed1abbaeeadceb9e46760e908ffb6008e61b6b",
	"debian-trixie-amd64-pam-rssh_1.2.2-1_amd64.deb":   "b96f5ba6d39d76fb86344b71ca0a519f79e145f1ccca26e525ec15c3b02686d3",
	"debian-trixie-arm64-pam-rssh_1.2.2-1_arm64.deb":   "272c99a14206810accb51e8448a9c4f51b94074204c14528e21b443551e39f54",
}

func pamRSSH(h Host) ([]host.Resource, error) {
	if h.Config.PamRSSH == nil || len(h.Config.PamRSSH.Keys) == 0 {
		return nil, nil
	}

	rs, module, err := installPAMRSSH(h)
	if err != nil {
		return nil, err
	}
	return append(
		rs,
		// The keys that may authenticate sudo.
		host.File{
			Path:    "/etc/sudoers.keys",
			Content: managedLines(h.Config.PamRSSH.Keys),
			Owner:   "root",
			Group:   "root",
			Mode:    0o644,
		},
		// Let sudo pass the agent through to pam_rssh.
		sudoersFile("pam_rssh", []string{`Defaults env_keep += "SSH_AUTH_SOCK"`}),
		host.LineInFile{
			Path:         "/etc/pam.d/sudo",
			Regexp:       `^\s*auth\s+\S+\s+\S*pam_rssh\.so`,
			Line:         "auth sufficient " + module + " auth_key_file=/etc/sudoers.keys",
			InsertBefore: `^\s*(auth\s|@include\s+common-auth)`,
		},
	), nil
}

func installPAMRSSH(h Host) ([]host.Resource, string, error) {
	if h.Facts.OSFamily == archLinux {
		rs, err := aurPackages(h, "pam_rssh")
		return rs, "/usr/lib/security/pam_rssh.so", err
	}

	debArch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[h.Facts.Arch]
	if debArch == "" {
		debArch = h.Facts.Arch
	}
	deb := fmt.Sprintf("debian-%s-%s-pam-rssh_%s_%s.deb", h.Facts.Release, debArch, pamRSSHDebVersion, debArch)
	sum, ok := pamRSSHDebChecksums[deb]
	if !ok {
		return nil, "", fmt.Errorf("host %s: pam_rssh has no release for %s on %s", h.Name, h.Facts.Release, h.Facts.Arch)
	}
	path := "/var/cache/" + deb
	return []host.Resource{
		host.Download{
			URL:    "https://github.com/z4yx/pam_rssh/releases/download/" + pamRSSHRelease + "/" + deb,
			Path:   path,
			SHA256: sum,
			Mode:   0o644,
		},
		host.Package{Name: "pam-rssh", Deb: path},
	}, "/lib/" + h.Facts.Arch + "-linux-gnu/security/libpam_rssh.so", nil
}

func tailscale(h Host) ([]host.Resource, error) {
	if h.Config.Tailscale == nil {
		return nil, nil
	}
	settings := h.Config.Tailscale.Settings

	var rs []host.Resource
	if h.Facts.OSFamily == debian {
		rs = append(
			rs,
			host.AptRepo{
				Name:          "tailscale",
				URIs:          []string{"https://pkgs.tailscale.com/stable/debian"},
				Suites:        []string{h.Facts.Release},
				Components:    []string{"main"},
				SigningKeyURL: "https://pkgs.tailscale.com/stable/debian/" + h.Facts.Release + ".noarmor.gpg",
			},
			// The repository as added by Tailscale's installer.
			host.Absent{Path: "/etc/apt/sources.list.d/tailscale.list"},
		)
	}
	rs = append(
		rs,
		host.Package{Name: "tailscale"},
		host.Service{Name: "tailscaled", Enabled: true, Running: true},
	)
	if settings["advertise-exit-node"] == "true" || settings["advertise-routes"] != "" {
		rs = append(
			rs,
			sysctl(
				"99-tailscale",
				map[string]string{"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1"},
			)...,
		)
	}
	return append(rs, host.TailscaleSet{Settings: settings}), nil
}

func docker(h Host) ([]host.Resource, error) {
	c := h.Config.Docker
	if c == nil {
		return nil, nil
	}

	var rs []host.Resource
	if h.Facts.OSFamily == debian {
		// Debian's packages start Docker when they're installed.
		rs = append(
			rs,
			host.AptRepo{
				Name:          "docker",
				URIs:          []string{"https://download.docker.com/linux/debian"},
				Suites:        []string{h.Facts.Release},
				Components:    []string{"stable"},
				SigningKeyURL: "https://download.docker.com/linux/debian/gpg",
			},
		)
		rs = append(
			rs,
			installPackages(
				"docker-ce",
				"docker-ce-cli",
				"containerd.io",
				"docker-buildx-plugin",
				"docker-compose-plugin",
			)...,
		)
	} else {
		// Arch's packages don't start Docker, so it's started when it's first
		// installed. Existing installs are left as they are, e.g. if they rely
		// on socket activation.
		rs = append(
			rs,
			host.Command{
				Name:      "install and start docker",
				CheckArgv: []string{"test", "-e", "/usr/bin/dockerd"},
				ApplyArgv: []string{
					"sh",
					"-c",
					"pacman -S --needed --noconfirm docker docker-compose && systemctl enable --now docker",
				},
			},
		)
		rs = append(rs, installPackages("docker", "docker-compose")...)
	}

	members := slices.Clone(c.Users)
	for _, u := range c.Users {
		rs = append(rs, host.User{Name: u, Groups: []string{"docker"}})
	}
	// Users given the group directly keep it too.
	for name, u := range h.Config.Users {
		if slices.Contains(u.Groups, "docker") {
			members = append(members, name)
		}
	}
	slices.Sort(members)
	rs = append(rs, host.GroupMembers{Group: "docker", Members: slices.Compact(members)})
	for _, name := range slices.Sorted(maps.Keys(c.Networks)) {
		n := c.Networks[name]
		for _, s := range n.Subnets {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("host %s: docker network %s: %w", h.Name, name, err)
			}
			if p.Addr().Is6() && !n.IPv6 {
				return nil, fmt.Errorf("host %s: docker network %s has an IPv6 subnet, so needs ipv6: true", h.Name, name)
			}
		}
		rs = append(rs, host.DockerNetwork{Name: name, Subnets: n.Subnets, IPv6: n.IPv6})
	}
	return rs, nil
}

// stacks deploys the host's compose stacks, after the volumes they mount.
// Each is recreated whenever its files change, and stacks no role declares
// any more are taken down.
func stacks(h Host) ([]host.Resource, error) {
	var rs []host.Resource
	if len(h.Config.Volumes) > 0 {
		rs = append(rs, host.Dir{Path: config.VolumesDir, Owner: "root", Group: "root", Mode: 0o700})
	}
	owners := map[string]bool{}
	for _, v := range h.Config.Volumes {
		if owner := filepath.Dir(v.Path); !owners[owner] {
			owners[owner] = true
			rs = append(rs, host.Dir{Path: owner, Owner: "root", Group: "root", Mode: 0o755})
		}
		rs = append(rs, host.Dir{Path: v.Path, Owner: v.Owner, Group: v.Group, Mode: v.Mode})
	}
	if len(h.Config.Stacks) > 0 {
		rs = append(rs, host.Dir{Path: config.StacksDir, Owner: "root", Group: "docker", Mode: 0o750})
	}
	for _, s := range h.Config.Stacks {
		rs = append(rs, stack(s)...)
	}
	// Networks are removed after the stacks that might use them.
	return append(rs, host.ComposeProjects{Path: config.StacksDir}, host.DockerNetworks{}), nil
}

func stack(s config.Stack) []host.Resource {
	dir := s.Dir()
	rs := []host.Resource{host.Dir{Path: dir, Owner: "root", Group: "docker", Mode: 0o750}}
	watch := make([]string, 0, len(s.Files)+1)
	dirs := map[string]bool{dir: true}
	for _, f := range s.Files {
		path := filepath.Join(dir, f.Path)
		var parents []string
		for p := filepath.Dir(path); !dirs[p]; p = filepath.Dir(p) {
			dirs[p] = true
			parents = append([]string{p}, parents...)
		}
		for _, p := range parents {
			rel, _ := filepath.Rel(dir, p)
			perms, ok := s.Dirs[rel]
			if !ok {
				perms = config.Perms{Owner: "root", Group: "docker", Mode: 0o750}
			}
			rs = append(rs, host.Dir{Path: p, Owner: perms.Owner, Group: perms.Group, Mode: perms.Mode})
		}
		file := host.File{
			Path:    path,
			Content: f.Content,
			Owner:   f.Perms.Owner,
			Group:   f.Perms.Group,
			Mode:    f.Perms.Mode,
			Secrets: f.Secrets,
			Hidden:  f.Hidden,
		}
		rs = append(rs, file)
		watch = append(watch, file.ID())
	}
	owned := host.OwnedDir{Path: dir, Recursive: true}
	rs = append(rs, owned)
	watch = append(watch, owned.ID())
	return append(rs, host.ComposeStack{Dir: dir, Watch: watch})
}

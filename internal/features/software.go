package features

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

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
		case len(c.URIs) == 0 || len(c.Suites) == 0:
			return nil, fmt.Errorf("host %s: apt repo %s needs uris and suites", h.Name, name)
		case (c.SigningKeyURL == "") == (c.SigningKey == ""):
			return nil, fmt.Errorf("host %s: apt repo %s needs one of signing_key_url and signing_key", h.Name, name)
		}
		facts := strings.NewReplacer("{distro}", h.Facts.Distro, "{release}", h.Facts.Release)
		key := facts.Replace(c.SigningKey)
		if key != "" && !filepath.IsAbs(key) {
			return nil, fmt.Errorf("host %s: apt repo %s: signing_key must be an absolute path", h.Name, name)
		}
		replaceAll := func(items []string) []string {
			out := make([]string, len(items))
			for i, item := range items {
				out[i] = facts.Replace(item)
			}
			return out
		}
		rs = append(
			rs,
			host.AptRepo{
				Name:          name,
				URIs:          replaceAll(c.URIs),
				Suites:        replaceAll(c.Suites),
				Components:    replaceAll(c.Components),
				SigningKeyURL: facts.Replace(c.SigningKeyURL),
				SigningKey:    key,
			},
		)
	}
	return rs, nil
}

// pacmanRepoName is a pacman.conf section that can also name files.
var pacmanRepoName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

func pacmanRepos(h Host) ([]host.Resource, error) {
	if len(h.Config.PacmanRepos) == 0 {
		return nil, nil
	}
	if h.Facts.OSFamily != archLinux {
		return nil, fmt.Errorf("host %s: pacman_repos only works on Arch Linux", h.Name)
	}
	var rs []host.Resource
	for _, name := range slices.Sorted(maps.Keys(h.Config.PacmanRepos)) {
		c := h.Config.PacmanRepos[name]
		switch {
		// "local" is pacman's own database, and "options" its settings.
		case !pacmanRepoName.MatchString(name) || name == "local" || name == "options":
			return nil, fmt.Errorf(
				"host %s: invalid pacman repo name %q; use letters, digits, \".\", \"-\" and \"_\"",
				h.Name,
				name,
			)
		case len(c.Servers) == 0:
			return nil, fmt.Errorf("host %s: pacman repo %s needs servers", h.Name, name)
		case (c.SigningKeyURL == "") != (c.SigningKeyID == ""):
			return nil, fmt.Errorf(
				"host %s: pacman repo %s needs both signing_key_url and signing_key_id, or neither",
				h.Name,
				name,
			)
		case strings.HasPrefix(c.SigningKeyID, "-") || strings.ContainsFunc(c.SigningKeyID, unicode.IsSpace):
			return nil, fmt.Errorf("host %s: pacman repo %s: invalid signing_key_id %q", h.Name, name, c.SigningKeyID)
		case strings.ContainsAny(c.SigLevel+strings.Join(c.Servers, ""), "\n\r"):
			return nil, fmt.Errorf("host %s: pacman repo %s: servers and sig_level must be one line each", h.Name, name)
		}
		sigLevel := c.SigLevel
		if sigLevel == "" {
			sigLevel = "Required"
		}
		rs = append(
			rs,
			host.PacmanRepo{
				Name:          name,
				Servers:       slices.Clone(c.Servers),
				SigLevel:      sigLevel,
				SigningKeyURL: c.SigningKeyURL,
				SigningKeyID:  c.SigningKeyID,
			},
		)
	}
	return rs, nil
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
	return append(rs, recordedPackages(c.Install...)...), nil
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
// more memory than small hosts have. Nothing uses the debug package makepkg
// builds by default. makepkg reads a user config after makepkg.conf.d, so one
// can turn that off without replacing the system config. makepkg leaves files
// the build account can't remove, so the build directory is removed as root.
const paruInstallScript = `set -eu
dir=$(runuser -u ` + aurUser + ` -- mktemp -d -t paru.XXXXXXXXXX)
trap 'rm -rf "$dir"' EXIT
runuser -u ` + aurUser + ` -- mkdir -p "$dir/config/pacman"
echo 'OPTIONS+=(!debug)' | runuser -u ` + aurUser + ` -- tee "$dir/config/pacman/makepkg.conf" >/dev/null
runuser -u ` + aurUser + ` -- env HOME=` + aurHome + ` \
  git clone --depth 1 https://aur.archlinux.org/paru.git "$dir/paru"
cd "$dir/paru"
runuser -u ` + aurUser + ` -- env HOME=` + aurHome + ` XDG_CONFIG_HOME="$dir/config" \
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
		host.User{Name: aurUser, System: true, Home: aurHome, Shell: "/usr/bin/nologin", Password: "!", Managed: true},
		host.Dir{Path: aurHome, Owner: aurUser, Group: aurUser, Mode: 0o700},
		sudoersFile(aurUser, []string{aurUser + " ALL=(root) NOPASSWD: /usr/bin/pacman"}),
		// paru stops working when pacman's library changes version, until it's
		// rebuilt, so check it runs rather than that it's installed.
		host.Command{
			Name:      "install paru",
			CheckArgv: []string{"paru", "--version"},
			ApplyArgv: []string{"sh", "-c", paruInstallScript},
			Packages:  []string{"paru"},
		},
	)
	for _, n := range names {
		rs = append(rs, host.AURPackage{Name: n, BuildUser: aurUser, Record: true})
	}
	return rs, nil
}

const (
	vimBinary = "/usr/bin/vim"
	// vimLinkDir comes first in PATH, so the links don't clash with packages'
	// files.
	vimLinkDir = "/usr/local/bin"
)

var vimLinks = []string{"edit", "ex", "vedit", "vi", "view"}

func vim(h Host) ([]host.Resource, error) {
	if h.Config.Vim == nil {
		return nil, nil
	}
	rs := installPackages("vim")
	// Debian's vim package already links these to it.
	if h.Facts.OSFamily != archLinux {
		return rs, nil
	}
	for _, n := range vimLinks {
		rs = append(rs, host.Symlink{Path: vimLinkDir + "/" + n, Target: vimBinary})
	}
	return rs, nil
}

const (
	pamRSSHRelease = "v1.2.2-rc2"
	// pamRSSHDebGlob matches the packages of every release and distro.
	pamRSSHDebGlob = "/var/cache/*-pam-rssh_*.deb"
	// sudoersKeys are the keys that may authenticate sudo.
	sudoersKeys = "/etc/sudoers.keys"
)

// pamRSSHDebs are the release's packages, by distro, release and arch.
var pamRSSHDebs = map[string]struct{ file, sha256 string }{
	"debian bookworm x86_64": {
		"debian-bookworm-amd64-pam-rssh_1.2.2-1_amd64.deb",
		"677ccb5b39a34265721c096b0efd39b21719bcf1bd6a24cff54d36de446e355b",
	},
	"debian bookworm aarch64": {
		"debian-bookworm-arm64-pam-rssh_1.2.2-1_arm64.deb",
		"266b94935d3174995cd8f91468ed1abbaeeadceb9e46760e908ffb6008e61b6b",
	},
	"debian trixie x86_64": {
		"debian-trixie-amd64-pam-rssh_1.2.2-1_amd64.deb",
		"b96f5ba6d39d76fb86344b71ca0a519f79e145f1ccca26e525ec15c3b02686d3",
	},
	"debian trixie aarch64": {
		"debian-trixie-arm64-pam-rssh_1.2.2-1_arm64.deb",
		"272c99a14206810accb51e8448a9c4f51b94074204c14528e21b443551e39f54",
	},
	"ubuntu jammy x86_64": {
		"ubuntu-22.04-pam-rssh_1.2.2-1_amd64.deb",
		"c37bdac1a54ba27b06e357e34da50532ca4ac038b742e0134511c1c665b5c573",
	},
	"ubuntu jammy aarch64": {
		"ubuntu-22.04-arm-pam-rssh_1.2.2-1_arm64.deb",
		"2822b24adcc336c8474e3a11120f9c057735c2abeeddf6072767012ae958676f",
	},
	"ubuntu noble x86_64": {
		"ubuntu-24.04-pam-rssh_1.2.2-1_amd64.deb",
		"399858930cdfd7d22e20d9e6b15605d0af75c854c4fb9972e877c51a3baf9e5b",
	},
	"ubuntu noble aarch64": {
		"ubuntu-24.04-arm-pam-rssh_1.2.2-1_arm64.deb",
		"9b1fbbf886b93564433fcaa04682c0b51ead492ccdfc3cf922c5dce3e6aec11a",
	},
	"ubuntu resolute x86_64": {
		"ubuntu-26.04-pam-rssh_1.2.2-1_amd64.deb",
		"dd79d04cdbbfaf0c9ce74c42ce48c4e35ebf611a521b11d94c8d0d99a0666497",
	},
	"ubuntu resolute aarch64": {
		"ubuntu-26.04-arm-pam-rssh_1.2.2-1_arm64.deb",
		"38eda619e10d4dfbe560a440bbedcdf6c8d030fccb66cc7947192291aa289b3c",
	},
}

func pamRSSH(h Host) ([]host.Resource, error) {
	services := []string{"sudo"}
	if h.Facts.OSFamily == debian {
		// Debian's sudo authenticates `sudo -i` with its own PAM service.
		services = append(services, "sudo-i")
	}

	if h.Config.PamRSSH == nil || len(h.Config.PamRSSH.Keys) == 0 {
		// sudo falls back to the next auth module, so the line can go
		// straight away. Only lines using sensible's keys are ours.
		rs := make([]host.Resource, len(services))
		for i, service := range services {
			rs[i] = host.LineInFile{
				Path:   "/etc/pam.d/" + service,
				Regexp: `^\s*auth\s+\S+\s+\S*pam_rssh\.so\s.*auth_key_file=` + regexp.QuoteMeta(sudoersKeys) + `(\s|$)`,
				Absent: true,
			}
		}
		return rs, nil
	}

	rs, module, err := installPAMRSSH(h)
	if err != nil {
		return nil, err
	}
	rs = append(
		rs,
		host.File{
			Path:    sudoersKeys,
			Content: managedLines(h.Config.PamRSSH.Keys),
			Owner:   "root",
			Group:   "root",
			Mode:    0o644,
		},
		// Let sudo pass the agent through to pam_rssh.
		sudoersFile("pam_rssh", []string{`Defaults env_keep += "SSH_AUTH_SOCK"`}),
	)
	for _, service := range services {
		rs = append(
			rs,
			host.LineInFile{
				Path:         "/etc/pam.d/" + service,
				Regexp:       `^\s*auth\s+\S+\s+\S*pam_rssh\.so`,
				Line:         "auth sufficient " + module + " auth_key_file=" + sudoersKeys,
				InsertBefore: `^\s*(auth\s|@include\s+common-auth)`,
			},
		)
	}
	return rs, nil
}

func pamRSSHPackage(h Host) string {
	if h.Facts.OSFamily == archLinux {
		return "pam_rssh"
	}
	return "pam-rssh"
}

func installPAMRSSH(h Host) ([]host.Resource, string, error) {
	if h.Facts.OSFamily == archLinux {
		rs, err := aurPackages(h, pamRSSHPackage(h))
		return rs, "/usr/lib/security/pam_rssh.so", err
	}

	distro, err := vendorDistro(h, "pam_rssh")
	if err != nil {
		return nil, "", err
	}
	deb, ok := pamRSSHDebs[distro+" "+h.Facts.Release+" "+h.Facts.Arch]
	if !ok {
		return nil, "", fmt.Errorf(
			"host %s: pam_rssh has no package for %s %s on %s",
			h.Name,
			distro,
			h.Facts.Release,
			h.Facts.Arch,
		)
	}
	path := "/var/cache/" + deb.file
	return []host.Resource{
		host.Download{
			URL:    "https://github.com/z4yx/pam_rssh/releases/download/" + pamRSSHRelease + "/" + deb.file,
			Path:   path,
			SHA256: deb.sha256,
			Mode:   0o644,
		},
		host.Package{Name: pamRSSHPackage(h), Deb: path, Record: true},
	}, "/lib/" + h.Facts.Arch + "-linux-gnu/security/libpam_rssh.so", nil
}

const tailscaleSysctl = "/etc/sysctl.d/99-tailscale.conf"

func tailscale(h Host) ([]host.Resource, error) {
	if h.Config.Tailscale == nil {
		return nil, nil
	}
	settings := h.Config.Tailscale.Settings

	var rs []host.Resource
	if h.Facts.OSFamily == debian {
		distro, err := vendorDistro(h, "Tailscale")
		if err != nil {
			return nil, err
		}
		base := "https://pkgs.tailscale.com/stable/" + distro
		rs = append(
			rs,
			host.AptRepo{
				Name:          "tailscale",
				URIs:          []string{base},
				Suites:        []string{h.Facts.Release},
				Components:    []string{"main"},
				SigningKeyURL: base + "/" + h.Facts.Release + ".noarmor.gpg",
			},
			// The repository as added by Tailscale's installer.
			host.Absent{Path: "/etc/apt/sources.list.d/tailscale.list"},
		)
	}
	rs = append(
		rs,
		host.Package{Name: "tailscale"},
		host.Service{Name: "tailscaled", Enabled: true},
	)
	if settings["advertise-exit-node"] == "true" || settings["advertise-routes"] != "" {
		rs = append(
			rs,
			sysctl(
				tailscaleSysctl,
				map[string]string{"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1"},
			)...,
		)
	}
	rs = append(rs, host.TailscaleSet{Settings: settings})
	if len(settings) > 0 {
		rs = append(rs, host.Dir{Path: host.TailscaleRecords, Owner: "root", Group: "root", Mode: 0o700})
	}
	for _, name := range slices.Sorted(maps.Keys(settings)) {
		rs = append(rs, host.TailscaleRecord(name))
	}
	return rs, nil
}

const (
	dockerDaemonFile = "/etc/docker/daemon.json"
	dockerClientFile = "/root/.docker/config.json"
)

func docker(h Host) ([]host.Resource, error) {
	c := h.Config.Docker
	if c == nil {
		return nil, nil
	}

	var rs []host.Resource
	if h.Facts.OSFamily == debian {
		distro, err := vendorDistro(h, "Docker")
		if err != nil {
			return nil, err
		}
		base := "https://download.docker.com/linux/" + distro
		// Debian's packages start Docker when they're installed.
		rs = append(
			rs,
			host.AptRepo{
				Name:          "docker",
				URIs:          []string{base},
				Suites:        []string{h.Facts.Release},
				Components:    []string{"stable"},
				SigningKeyURL: base + "/gpg",
			},
		)
		rs = append(
			rs,
			recordedPackages(
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
		rs = append(rs, recordedPackages("docker", "docker-compose")...)
		rs = append(
			rs,
			host.Command{
				Name:      "start docker",
				Watch:     []string{host.Package{Name: "docker"}.ID()},
				ApplyArgv: []string{"systemctl", "enable", "--now", "docker"},
			},
		)
	}
	// JSON has no comments for a header, so the files are recorded instead.
	if c.Daemon != nil || len(c.Auths) > 0 {
		rs = append(rs, host.Dir{Path: host.WrittenDir, Owner: "root", Group: "root", Mode: 0o700})
	}
	if c.Daemon != nil {
		dc, err := dockerDaemonConfig(c.Daemon)
		if err != nil {
			return nil, fmt.Errorf("host %s: docker daemon config: %w", h.Name, err)
		}
		rs = append(rs, dc...)
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
	if len(c.Auths) > 0 {
		cc, err := dockerClientConfig(c.Auths)
		if err != nil {
			return nil, fmt.Errorf("host %s: docker client config: %w", h.Name, err)
		}
		rs = append(rs, cc...)
	}
	return rs, nil
}

// dockerDaemonConfig comes after Docker's installed, as dockerd validates it,
// and restarts Docker before anything else uses it, as containers and networks
// keep the defaults they were created with.
func dockerDaemonConfig(settings map[string]any) ([]host.Resource, error) {
	content, err := json.MarshalIndent(settings, "", "\t")
	if err != nil {
		return nil, err
	}
	file := host.File{
		Path:     dockerDaemonFile,
		Content:  string(content) + "\n",
		Owner:    "root",
		Group:    "root",
		Mode:     0o644,
		Validate: []string{"dockerd", "--validate", "--config-file", "%s"},
	}
	return []host.Resource{
		host.Dir{Path: filepath.Dir(dockerDaemonFile), Owner: "root", Group: "root", Mode: 0o755},
		file,
		host.WrittenRecord(file),
		host.Command{
			Name:      "restart docker",
			Watch:     []string{file.ID()},
			ApplyArgv: []string{"systemctl", "restart", "docker"},
		},
	}, nil
}

// dockerClientConfig gives root's Docker client the registries' credentials,
// as the agent runs compose as root. The whole file is credentials, so it's
// left out of diffs.
func dockerClientConfig(auths map[string]string) ([]host.Resource, error) {
	type auth struct {
		Auth string `json:"auth"`
	}
	type clientConfig struct {
		Auths map[string]auth `json:"auths"`
	}
	cc := clientConfig{Auths: map[string]auth{}}
	for name, a := range auths {
		cc.Auths[name] = auth{Auth: a}
	}
	content, err := json.MarshalIndent(cc, "", "\t")
	if err != nil {
		return nil, err
	}
	file := host.File{
		Path:    dockerClientFile,
		Content: string(content) + "\n",
		Owner:   "root",
		Group:   "root",
		Mode:    0o600,
		Hidden:  true,
	}
	return []host.Resource{
		host.Dir{Path: filepath.Dir(dockerClientFile), Owner: "root", Group: "root", Mode: 0o700},
		file,
		host.WrittenRecord(file),
	}, nil
}

// vendorDistro returns the distro to use in a vendor's apt repository URLs.
// Vendors publish for Debian and Ubuntu, but not for their derivatives.
func vendorDistro(h Host, vendor string) (string, error) {
	switch h.Facts.Distro {
	case "debian", "ubuntu":
		return h.Facts.Distro, nil
	}
	return "", fmt.Errorf(
		"host %s: %s only publishes packages for Debian and Ubuntu, not %q",
		h.Name,
		vendor,
		h.Facts.Distro,
	)
}

// certs writes the host's certificates, ahead of the stacks that mount them,
// and reloads or restarts the units that use them when they change.
func certs(h Host) ([]host.Resource, error) {
	var rs []host.Resource
	for _, c := range h.Config.IssuedCerts {
		var notify host.ResourceList
		for _, u := range c.Reload {
			notify = append(notify, host.ServiceAction{Name: u, Action: "reload"})
		}
		for _, u := range c.Restart {
			notify = append(notify, host.ServiceAction{Name: u, Action: "restart"})
		}
		files := []host.File{
			{Path: filepath.Join(c.Dir, config.CACertFile), Content: c.CACert, Mode: 0o644},
			{Path: filepath.Join(c.Dir, config.CertFile), Content: c.Cert, Mode: 0o644},
			{Path: filepath.Join(c.Dir, config.KeyFile), Content: c.Key, Mode: 0o600},
		}
		paths := make([]string, 0, len(files))
		for _, f := range files {
			paths = append(paths, f.Path)
		}
		rs = append(rs, host.CertRecord{Name: c.Name, Paths: paths}, host.Dir{Path: c.Dir, Owner: c.Owner, Group: c.Group})
		for _, f := range files {
			f.Owner, f.Group, f.Hidden, f.Notify = c.Owner, c.Group, true, notify
			rs = append(rs, f)
		}
	}
	return rs, nil
}

// certsCleanUp is unconditional, as the host's last certificate may just
// have gone.
func certsCleanUp(Host) ([]host.Resource, error) {
	return []host.Resource{host.CertRecords{}}, nil
}

// stacks deploys the host's compose stacks, after the volumes they mount.
// Each is recreated whenever its files change, and stacks no role declares
// any more are taken down. Volumes no role declares are only reported.
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
	// A parent's migrations are around all of its children's stacks, which
	// mount its volumes.
	var after []host.Resource
	for _, p := range h.Config.Parents {
		children := make([]string, 0, len(p.Children))
		for _, name := range p.Children {
			children = append(children, config.Stack{Name: name}.Dir())
		}
		for _, m := range p.Migrations {
			before := migration(m, host.PhaseBefore)
			before.Parent, before.Children = p.Name, children
			rs = append(rs, before)
			finish := migration(m, host.PhaseAfter)
			finish.Parent, finish.Children = p.Name, children
			after = append(after, finish)
		}
	}
	for _, s := range h.Config.Stacks {
		rs = append(rs, stack(s)...)
	}
	rs = append(rs, after...)
	// Networks are removed after the stacks that might use them.
	return append(
		rs,
		host.ComposeProjects{Path: config.StacksDir},
		host.DockerNetworks{},
		host.Migrations{},
		host.Volumes{Path: config.VolumesDir},
	), nil
}

func stack(s config.Stack) []host.Resource {
	dir := s.Dir()
	// Ahead of the stack's files, so a failure leaves the stack as it was.
	rs := make([]host.Resource, 0, 2*len(s.Migrations)+2*len(s.Files)+3)
	for _, m := range s.Migrations {
		r := migration(m, host.PhaseBefore)
		r.Stack = dir
		rs = append(rs, r)
	}
	rs = append(rs, host.Dir{Path: dir, Owner: "root", Group: "docker", Mode: 0o750})
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
	for _, path := range s.CertPaths {
		watch = append(watch, host.File{Path: path}.ID())
	}
	rs = append(rs, host.ComposeStack{Dir: dir, Watch: watch})
	for _, m := range s.Migrations {
		r := migration(m, host.PhaseAfter)
		r.Stack = dir
		rs = append(rs, r)
	}
	return rs
}

func migration(m config.Migration, phase string) host.Migration {
	return host.Migration{
		Name:   m.Name,
		Phase:  phase,
		On:     m.On,
		Secret: m.Secret,
		Before: m.Before,
		After:  m.After,
	}
}

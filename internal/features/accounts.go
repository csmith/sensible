package features

import (
	"cmp"
	_ "embed"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"chameth.com/sensible/internal/host"
)

func users(h Host) ([]host.Resource, error) {
	rs := make([]host.Resource, 0, len(h.Config.Users))
	for _, name := range slices.Sorted(maps.Keys(h.Config.Users)) {
		u := h.Config.Users[name]
		for _, p := range [][2]string{{"home", u.Home}, {"shell", u.Shell}} {
			if p[1] != "" && (!path.IsAbs(p[1]) || path.Clean(p[1]) != p[1]) {
				return nil, fmt.Errorf("users.%s.%s must be an absolute path, not %q", name, p[0], p[1])
			}
		}
		rs = append(
			rs,
			host.User{Name: name, Groups: u.Groups, Home: u.Home, Shell: u.Shell, Managed: true},
		)
	}
	return rs, nil
}

func usersCleanUp(Host) ([]host.Resource, error) {
	return []host.Resource{host.Users{}}, nil
}

func home(h Host, name string) string {
	if d := h.Config.Users[name].Home; d != "" {
		return d
	}
	if name == "root" {
		return "/root"
	}
	return "/home/" + name
}

const ohMyZshVersion = "17a2b4c3a5855524ad4772a17ada0dc474e2fdf3"

const ohMyZshPath = "/usr/share/oh-my-zsh"

const zshPath = "/usr/bin/zsh"

const agnoster = "agnoster"

func zsh(h Host) ([]host.Resource, error) {
	c := h.Config.Zsh
	if c == nil {
		return nil, nil
	}

	theme := cmp.Or(c.Theme, agnoster)
	if theme != agnoster && len(c.PromptColours) > 0 {
		return nil, fmt.Errorf("zsh.prompt_colours needs the %s theme, not %s", agnoster, theme)
	}

	plugins := c.Plugins
	if h.Facts.OSFamily == archLinux {
		plugins = append(slices.Clone(plugins), "archlinux")
	}

	rs := installPackages("zsh", "git")
	// Shared by every account, and owned by root so they can't change it.
	rs = append(
		rs,
		host.GitCheckout{Path: ohMyZshPath, Repo: "https://github.com/ohmyzsh/ohmyzsh.git", Commit: ohMyZshVersion},
	)
	for _, name := range c.Users {
		if s := h.Config.Users[name].Shell; s != "" && s != zshPath {
			return nil, fmt.Errorf("users.%s.shell is %s, but zsh.users sets it to %s", name, s, zshPath)
		}
		rs = append(rs, host.User{Name: name, Shell: zshPath})
	}
	for _, name := range c.Users {
		var b strings.Builder
		err := zshrcTemplate.Execute(
			&b,
			zshrc{
				Theme:        theme,
				Editor:       cmp.Or(c.Editor, "vim"),
				Plugins:      plugins,
				PromptColour: c.PromptColours[name],
			},
		)
		if err != nil {
			return nil, err
		}
		rs = append(
			rs,
			host.File{
				Path:    home(h, name) + "/.zshrc",
				Content: b.String(),
				Owner:   name,
				Mode:    0o644,
			},
		)
	}
	return rs, nil
}

type zshrc struct {
	Theme   string
	Editor  string
	Plugins []string
	// PromptColour colours the host segment of the prompt.
	PromptColour string
}

//go:embed zshrc.tmpl
var zshrcSource string

var zshrcTemplate = template.Must(
	template.New("zshrc").Funcs(template.FuncMap{"quote": shellQuote, "join": strings.Join}).Parse(zshrcSource),
)

var shellSafe = regexp.MustCompile(`^[\w@%+=:,./-]+$`)

func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func sudoers(h Host) ([]host.Resource, error) {
	if len(h.Config.Sudoers) == 0 {
		return nil, nil
	}
	rs := installPackages("sudo")
	for _, name := range slices.Sorted(maps.Keys(h.Config.Sudoers)) {
		rs = append(rs, sudoersFile(name, h.Config.Sudoers[name]))
	}
	return rs, nil
}

func loginMessages(h Host) ([]host.Resource, error) {
	if h.Config.QuietLogin == nil {
		return nil, nil
	}
	// pam_motd shows /etc/motd, and on Debian the output of /etc/update-motd.d,
	// and pam_lastlog shows when the account last logged in. Commenting them
	// out stops the messages without fighting the packages that provide them.
	return []host.Resource{
		host.CommentOut{Glob: "/etc/pam.d/*", Regexp: `^\s*session\s+.*pam_(motd|lastlog2?)\.so`},
	}, nil
}

var sshdValidate = []string{"sshd", "-t", "-f", "%s"}

func sshdService(h Host) string {
	if h.Facts.OSFamily == debian {
		return "ssh"
	}
	return "sshd"
}

func sshdPackage(h Host) string {
	if h.Facts.OSFamily == debian {
		return "openssh-server"
	}
	return "openssh"
}

const (
	sshdConfig       = "/etc/ssh/sshd_config"
	sshdDropIn       = "/etc/ssh/sshd_config.d/10-sensible.conf"
	sshdListenDropIn = "/etc/ssh/sshd_config.d/10-sensible-listen.conf"
)

// sshdListenSettings say where sshd listens, lowercased. They have their own
// file, as changing them means restarting the socket that starts sshd.
var sshdListenSettings = []string{"addressfamily", "listenaddress", "port"}

func sshd(h Host) ([]host.Resource, error) {
	c := h.Config.SSHD
	if c == nil {
		return nil, nil
	}
	svc := sshdService(h)
	reload := host.ServiceAction{Name: svc, Action: "reload"}

	var lines, listen []string
	for _, k := range slices.Sorted(maps.Keys(c.Settings)) {
		if err := sshdAdmitsSensible(k, c.Settings[k]); err != nil {
			return nil, err
		}
		if slices.Contains(sshdListenSettings, strings.ToLower(k)) {
			listen = append(listen, k+" "+c.Settings[k])
		} else {
			lines = append(lines, k+" "+c.Settings[k])
		}
	}

	rs := []host.Resource{
		host.Package{Name: sshdPackage(h)},
		// sshd uses the first value it finds for each setting, and the
		// distributions' sshd_config includes sshd_config.d before setting
		// anything itself.
		host.File{
			Path:     sshdDropIn,
			Content:  managedLines(lines),
			Owner:    "root",
			Group:    "root",
			Mode:     0o644,
			Validate: sshdValidate,
			Notify:   host.ResourceList{reload},
		},
		host.File{
			Path:     sshdListenDropIn,
			Content:  managedLines(listen),
			Owner:    "root",
			Group:    "root",
			Mode:     0o644,
			Validate: sshdValidate,
			Notify:   host.ResourceList{reload, sshdSocketRestart(h)},
		},
	}
	if h.Facts.OSFamily == archLinux {
		// pacman leaves the package's sshd_config as a .pacnew when the
		// installed one has been changed, and only the package's includes
		// sshd_config.d. Command has no Notify, so it reloads sshd itself.
		rs = append(
			rs,
			host.Command{
				Name:      "use the package's sshd_config",
				CheckArgv: []string{"test", "!", "-e", sshdConfig + ".pacnew"},
				ApplyArgv: []string{
					"sh",
					"-c",
					"set -eu\n" +
						"sshd -t -f " + sshdConfig + ".pacnew\n" +
						"install -o root -g root -m 0644 " + sshdConfig + ".pacnew " + sshdConfig + "\n" +
						"rm " + sshdConfig + ".pacnew\n" +
						"systemctl reload " + svc + "\n",
				},
			},
		)
	}
	rs = append(rs, host.Service{Name: svc, Enabled: true, Running: true})

	for _, name := range slices.Sorted(maps.Keys(c.AuthorizedKeys)) {
		rs = append(
			rs,
			host.Dir{Path: home(h, name) + "/.ssh", Owner: name, Mode: 0o700},
			host.File{
				Path:    home(h, name) + "/.ssh/authorized_keys",
				Content: managedLines(c.AuthorizedKeys[name]),
				Owner:   name,
				Mode:    0o600,
			},
		)
	}
	return rs, nil
}

// sshdAdmitsSensible rejects an access list that would shut the sensible
// account out, which the access drop-in's Match block can't undo.
func sshdAdmitsSensible(key, value string) error {
	var allow, users bool
	switch strings.ToLower(key) {
	case "allowusers":
		allow, users = true, true
	case "allowgroups":
		allow = true
	case "denyusers":
		users = true
	case "denygroups":
	default:
		return nil
	}
	// The account's primary group shares its name.
	matched := slices.ContainsFunc(
		strings.Fields(value),
		func(p string) bool {
			if users {
				p, _, _ = strings.Cut(p, "@")
			}
			return sshdPatternMatches(p, SensibleUser)
		},
	)
	switch {
	case allow && !matched:
		return fmt.Errorf("sshd.settings.%s must admit %s, or sensible can't reach the host", key, SensibleUser)
	case !allow && matched:
		return fmt.Errorf("sshd.settings.%s must not match %s, or sensible can't reach the host", key, SensibleUser)
	}
	return nil
}

// sshdPatternMatches matches s against an sshd pattern, where * matches any
// run of characters and ? any one.
func sshdPatternMatches(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	switch pattern[0] {
	case '*':
		for i := range len(s) + 1 {
			if sshdPatternMatches(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && sshdPatternMatches(pattern[1:], s[1:])
	default:
		return s != "" && s[0] == pattern[0] && sshdPatternMatches(pattern[1:], s[1:])
	}
}

// sshdSocketRestart is a handler for changes to where sshd listens. Where a
// socket starts sshd, as on Ubuntu, the socket holds the addresses, which a
// generator reads from sshd_config when systemd reloads.
func sshdSocketRestart(h Host) host.Command {
	socket := sshdService(h) + ".socket"
	return host.Command{
		Name:      "restart " + socket + " if active",
		CheckArgv: []string{"false"},
		ApplyArgv: []string{
			"sh",
			"-c",
			"set -eu\n" +
				"if systemctl is-active --quiet " + socket + "; then\n" +
				"\tsystemctl daemon-reload\n" +
				"\tsystemctl restart " + socket + "\n" +
				"fi\n",
		},
	}
}

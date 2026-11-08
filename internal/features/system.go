package features

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

func hostname(h Host) ([]host.Resource, error) {
	c := h.Config.Hostname
	if c == nil {
		return nil, nil
	}
	name := c.Name
	if name == "" {
		name = h.Name
	}
	// The kernel's limit.
	if len(name) > 64 || !hostnamePattern.MatchString(name) {
		return nil, fmt.Errorf("host %s: invalid hostname %q", h.Name, name)
	}

	rs := []host.Resource{
		host.File{Path: "/etc/hostname", Content: name + "\n", Owner: "root", Group: "root", Mode: 0o644},
		host.Command{
			Name:      "set hostname",
			CheckArgv: []string{"sh", "-c", `test "$(uname -n)" = "$1"`, "sh", name},
			ApplyArgv: []string{"hostnamectl", "hostname", "--static", "--transient", name},
		},
	}
	// Debian doesn't resolve the host's own name through nss-myhostname, as
	// Arch does, so it's mapped in /etc/hosts.
	if h.Facts.OSFamily == debian {
		line := "127.0.1.1\t" + name
		if short, _, ok := strings.Cut(name, "."); ok {
			line += " " + short
		}
		rs = append(rs, host.LineInFile{Path: "/etc/hosts", Regexp: `^127\.0\.1\.1\s`, Line: line})
	}
	return rs, nil
}

func timezone(h Host) ([]host.Resource, error) {
	c := h.Config.Timezone
	if c == nil {
		return nil, nil
	}
	if _, err := time.LoadLocation(c.Zone); err != nil || c.Zone == "" || c.Zone == "Local" {
		return nil, fmt.Errorf("host %s: invalid timezone %q", h.Name, c.Zone)
	}

	rs := []host.Resource{
		host.Package{Name: "tzdata"},
		host.Symlink{Path: "/etc/localtime", Target: "/usr/share/zoneinfo/" + c.Zone},
	}
	if h.Facts.OSFamily == debian {
		rs = append(rs, host.File{Path: "/etc/timezone", Content: c.Zone + "\n", Owner: "root", Group: "root", Mode: 0o644})
	}
	return rs, nil
}

func locale(h Host) ([]host.Resource, error) {
	c := h.Config.Locale
	if c == nil {
		return nil, nil
	}
	if c.Lang == "" {
		return nil, fmt.Errorf("host %s: locale needs a lang", h.Name)
	}

	var (
		genLines []string
		names    []string
	)
	for _, l := range append([]string{c.Lang}, c.Generate...) {
		charset, normalised, ok := parseLocale(l)
		if !ok {
			return nil, fmt.Errorf("host %s: locale %q should be written as language_TERRITORY.charset", h.Name, l)
		}
		line := l + " " + charset
		if !slices.Contains(genLines, line) {
			genLines = append(genLines, line)
			names = append(names, normalised)
		}
	}

	var rs []host.Resource
	confPath := "/etc/locale.conf"
	if h.Facts.OSFamily == debian {
		rs = installPackages("locales")
		confPath = "/etc/default/locale"
	}
	return append(
		rs,
		host.File{Path: "/etc/locale.gen", Content: managedLines(genLines), Owner: "root", Group: "root", Mode: 0o644},
		// Locales that are no longer listed are left until locale-gen next runs.
		host.Command{
			Name: "generate locales",
			CheckArgv: append(
				[]string{"sh", "-c", `l=$(locale -a) && for n; do printf '%s\n' "$l" | grep -qxF "$n" || exit 1; done`, "sh"},
				names...,
			),
			ApplyArgv: []string{"locale-gen"},
		},
		host.File{
			Path:    confPath,
			Content: managedLines([]string{"LANG=" + c.Lang}),
			Owner:   "root",
			Group:   "root",
			Mode:    0o644,
		},
	), nil
}

// parseLocale splits a locale such as "en_GB.UTF-8" or "de_DE.UTF-8@euro"
// into its charset and the name `locale -a` lists it as, e.g. "en_GB.utf8".
func parseLocale(l string) (charset, normalised string, ok bool) {
	lang, rest, ok := strings.Cut(l, ".")
	if !ok || lang == "" || strings.ContainsAny(lang, " @") {
		return "", "", false
	}
	charset, modifier, hasModifier := strings.Cut(rest, "@")
	if charset == "" || strings.ContainsAny(rest, " ") {
		return "", "", false
	}
	var b strings.Builder
	for _, r := range strings.ToLower(charset) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	normalised = lang + "." + b.String()
	if hasModifier {
		normalised += "@" + modifier
	}
	return charset, normalised, true
}

const timesyncdConfDir = "/etc/systemd/timesyncd.conf.d"

func ntp(h Host) ([]host.Resource, error) {
	c := h.Config.NTP
	if c == nil {
		return nil, nil
	}

	restart := host.ResourceList{host.ServiceAction{Name: "systemd-timesyncd", Action: "restart"}}
	var rs []host.Resource
	// Arch's systemd includes timesyncd; Debian packages it separately.
	if h.Facts.OSFamily == debian {
		rs = installPackages("systemd-timesyncd")
	}
	if len(c.Servers) > 0 {
		rs = append(
			rs,
			host.Dir{Path: timesyncdConfDir, Owner: "root", Group: "root", Mode: 0o755},
			host.File{
				Path:    timesyncdConfDir + "/sensible.conf",
				Content: managedLines([]string{"[Time]", "NTP=" + strings.Join(c.Servers, " ")}),
				Owner:   "root",
				Group:   "root",
				Mode:    0o644,
				Notify:  restart,
			},
		)
	}
	return append(
		rs,
		host.OwnedDir{Path: timesyncdConfDir, Header: managedMark, Notify: restart},
		host.Service{Name: "systemd-timesyncd", Enabled: true, Running: true},
	), nil
}

const jobUnitPrefix = "sensible-"

var jobName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// jobs runs each job, and the backup job, from a systemd timer. Units for jobs no role declares
// any more are removed.
func jobs(h Host) ([]host.Resource, error) {
	all := maps.Clone(h.Config.Jobs)
	if j, ok := backupJobConfig(h); ok {
		if _, ok := all[backupJob]; ok {
			return nil, fmt.Errorf("host %s: job %s is the backup job's name", h.Name, backupJob)
		}
		if all == nil {
			all = map[string]config.JobConfig{}
		}
		all[backupJob] = j
	}

	var files, timers []host.Resource
	var watch []string
	for _, name := range slices.Sorted(maps.Keys(all)) {
		j := all[name]
		switch {
		case !jobName.MatchString(name):
			return nil, fmt.Errorf("host %s: invalid job name %q; use lower case letters, digits, \"-\" and \"_\"", h.Name, name)
		case len(j.Command) == 0:
			return nil, fmt.Errorf("host %s: job %s needs a command", h.Name, name)
		case j.Schedule == "":
			return nil, fmt.Errorf("host %s: job %s needs a schedule", h.Name, name)
		default:
		}
		for _, f := range jobUnits(name, j) {
			files = append(files, f)
			watch = append(watch, f.ID())
		}
		timers = append(timers, host.Service{Name: jobUnitPrefix + name + ".timer", Enabled: true, Running: true})
	}

	rs := files
	if len(watch) > 0 {
		rs = append(rs, host.SystemdReload{Watch: watch})
	}
	return append(append(rs, timers...), host.SystemdUnits{Prefix: jobUnitPrefix}), nil
}

func jobUnits(name string, j config.JobConfig) []host.File {
	unit := jobUnitPrefix + name
	service := []string{
		"[Unit]",
		"Description=sensible job " + name,
		"",
		"[Service]",
		"Type=oneshot",
		"ExecStart=" + execLine(j.Command),
	}
	if j.User != "" {
		service = append(service, "User="+j.User)
	}
	timer := []string{
		"[Unit]",
		"Description=Run sensible job " + name,
		"",
		"[Timer]",
		"OnCalendar=" + j.Schedule,
		"Persistent=true",
		"",
		"[Install]",
		"WantedBy=timers.target",
	}
	return []host.File{
		{
			Path:    path.Join(host.UnitsDir, unit+".service"),
			Content: managedLines(service),
			Owner:   "root",
			Group:   "root",
			Mode:    0o644,
		},
		{
			Path:     path.Join(host.UnitsDir, unit+".timer"),
			Content:  managedLines(timer),
			Owner:    "root",
			Group:    "root",
			Mode:     0o644,
			Validate: []string{"systemd-analyze", "calendar", j.Schedule},
		},
	}
}

// execLine quotes argv for ExecStart, so systemd expands no specifiers or
// variables in it.
func execLine(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		arg = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$", "\n", `\n`).Replace(arg)
		quoted[i] = `"` + arg + `"`
	}
	return strings.Join(quoted, " ")
}

func leftovers(h Host) ([]host.Resource, error) {
	c := h.Config.Leftovers
	if c == nil {
		return nil, nil
	}
	var rs []host.Resource
	for _, kept := range []struct {
		name     string
		config   config.KeptConfig
		external bool
	}{
		{"ignore", c.Ignore, false},
		{"external", c.External, true},
	} {
		for _, p := range kept.config.Paths {
			if _, err := path.Match(p, ""); err != nil || !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
				return nil, fmt.Errorf("host %s: leftovers.%s.paths: %q must be an absolute path or glob", h.Name, kept.name, p)
			}
		}
		for _, p := range kept.config.Packages {
			if _, err := path.Match(p, ""); err != nil || p == "" || strings.ContainsAny(p, "/ ") {
				return nil, fmt.Errorf("host %s: leftovers.%s.packages: %q must be a package name or glob", h.Name, kept.name, p)
			}
		}
		if len(kept.config.Paths) > 0 || len(kept.config.Packages) > 0 {
			rs = append(
				rs,
				host.KeptLeftovers{Paths: kept.config.Paths, Packages: kept.config.Packages, External: kept.external},
			)
		}
	}
	return rs, nil
}

func remove(h Host) ([]host.Resource, error) {
	if h.Config.Remove == nil {
		return nil, nil
	}
	rs := make([]host.Resource, 0, len(h.Config.Remove.Paths))
	for _, p := range h.Config.Remove.Paths {
		resolved := p
		if rest, ok := strings.CutPrefix(p, "~"); ok {
			if name, sub, _ := strings.Cut(rest, "/"); name != "" && sub != "" {
				resolved = home(h, name) + "/" + sub
			}
		}
		if !path.IsAbs(resolved) || path.Clean(resolved) != resolved || resolved == "/" {
			return nil, fmt.Errorf("host %s: remove.paths: %q must be an absolute path or ~user/path", h.Name, p)
		}
		rs = append(rs, host.Absent{Path: resolved})
	}
	return rs, nil
}

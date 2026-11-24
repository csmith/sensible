package features

import (
	"cmp"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
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
		rs = append(rs, host.File{
			Path:    "/etc/timezone",
			Content: c.Zone + "\n",
			Owner:   "root",
			Group:   "root",
			Mode:    0o644,
		})
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
				[]string{
					"sh",
					"-c",
					`l=$(locale -a) && for n; do printf '%s\n' "$l" | grep -qxF "$n" || exit 1; done`,
					"sh",
				},
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

// ntp removes sensible's drop-in even once ntp is unset, so the servers go
// back to the distribution's.
func ntp(h Host) ([]host.Resource, error) {
	restart := host.ResourceList{host.ServiceAction{Name: "systemd-timesyncd", Action: "restart"}}
	cleanUp := host.OwnedDir{Path: timesyncdConfDir, Header: managedMark, Notify: restart}
	c := h.Config.NTP
	if c == nil {
		return []host.Resource{cleanUp}, nil
	}

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
	return append(rs, cleanUp, host.Service{Name: "systemd-timesyncd", Enabled: true}), nil
}

const (
	firewallRules = "/etc/sensible/firewall.nft"
	firewallUnit  = jobUnitPrefix + "firewall.service"
	firewallTable = "inet sensible"
	// tailscaleInterface is the interface tailscaled makes by default.
	tailscaleInterface = `"tailscale0"`
)

// firewall drops unsolicited incoming traffic other than to the allowed
// ports. It loads its own table from its own unit, as nftables.service
// flushes the whole ruleset, which would take Docker's and Tailscale's rules
// with it. Once it's turned off, the jobs' clean-up stops the unit, which
// deletes the table.
func firewall(h Host) ([]host.Resource, error) {
	if h.Config.Firewall == nil {
		return []host.Resource{host.Absent{Path: firewallRules}}, nil
	}
	tcp, udp, err := firewallPorts(h)
	if err != nil {
		return nil, err
	}

	load := "nft -f " + firewallRules
	unit := host.File{
		Path: path.Join(host.UnitsDir, firewallUnit),
		Content: managedLines(
			[]string{
				"[Unit]",
				"Description=sensible firewall",
				"DefaultDependencies=no",
				"Wants=network-pre.target",
				"Before=network-pre.target shutdown.target",
				"After=nftables.service",
				"Conflicts=shutdown.target",
				"",
				"[Service]",
				"Type=oneshot",
				"RemainAfterExit=yes",
				"ExecStart=" + load,
				"ExecReload=" + load,
				"ExecStop=-nft delete table " + firewallTable,
				"",
				"[Install]",
				"WantedBy=sysinit.target",
			},
		),
		Owner: "root",
		Group: "root",
		Mode:  0o644,
	}
	return append(
		recordedPackages("nftables"),
		host.Dir{Path: path.Dir(firewallRules), Owner: "root", Group: "root", Mode: 0o755},
		// Loading a ruleset is atomic, so one that's rejected leaves the
		// last one in place.
		host.File{
			Path:     firewallRules,
			Content:  firewallRuleset(tcp, udp),
			Owner:    "root",
			Group:    "root",
			Mode:     0o644,
			Validate: []string{"nft", "-c", "-f", "%s"},
			Notify:   host.ResourceList{host.ServiceAction{Name: firewallUnit, Action: "reload"}},
		},
		unit,
		host.Command{
			Name:      "load " + firewallUnit,
			Watch:     []string{unit.ID()},
			ApplyArgv: []string{"systemctl", "daemon-reload"},
		},
		host.Service{Name: firewallUnit, Enabled: true},
	), nil
}

// firewallRuleset replaces the firewall's table. Docker forwards traffic for
// published ports to containers rather than delivering it to the host, having
// changed its destination, so that's matched on the port it was sent to.
// Tailscale's interface is trusted, as its ACLs control who reaches the host.
func firewallRuleset(tcp, udp []string) string {
	allow := func(match string, ports []string) []string {
		if len(ports) == 0 {
			return nil
		}
		return []string{"\t\t" + match + " { " + strings.Join(ports, ", ") + " } accept"}
	}
	lines := []string{
		"table " + firewallTable,
		"delete table " + firewallTable,
		"table " + firewallTable + " {",
		"\tchain input {",
		"\t\ttype filter hook input priority filter - 10; policy drop;",
		"\t\tct state established,related accept",
		// Conntrack can't tell the directions of a socket connected to
		// itself apart, so marks some of its packets invalid.
		"\t\tiif lo accept",
		"\t\tct state invalid drop",
		"\t\tiifname " + tailscaleInterface + " accept",
		"\t\tmeta l4proto { icmp, ipv6-icmp } accept",
		// DHCP replies may not be tracked as replies to the requests.
		"\t\tudp sport 67 udp dport 68 accept",
		"\t\tip6 saddr fe80::/10 udp sport 547 udp dport 546 accept",
	}
	lines = append(lines, allow("tcp dport", tcp)...)
	lines = append(lines, allow("udp dport", udp)...)
	lines = append(
		lines,
		"\t}",
		"",
		"\tchain forward {",
		"\t\ttype filter hook forward priority filter - 10; policy accept;",
		"\t\tct state new ct status dnat jump published",
		"\t}",
		"",
		"\tchain published {",
		"\t\tiifname "+tailscaleInterface+" accept",
	)
	lines = append(lines, allow("meta l4proto tcp ct original proto-dst", tcp)...)
	lines = append(lines, allow("meta l4proto udp ct original proto-dst", udp)...)
	return managedLines(append(lines, "\t\tdrop", "\t}", "}"))
}

// firewallPorts are the allowed TCP and UDP ports and ranges, in order.
func firewallPorts(h Host) (tcp, udp []string, err error) {
	type portRange struct{ low, high int }
	ranges := map[string][]portRange{}

	for _, a := range h.Config.Firewall.Allow {
		ports, proto, _ := strings.Cut(a, "/")
		lowText, highText, isRange := strings.Cut(ports, "-")
		low, lowErr := strconv.Atoi(lowText)
		high, highErr := low, error(nil)
		if isRange {
			high, highErr = strconv.Atoi(highText)
		}
		valid := lowErr == nil && highErr == nil && low >= 1 && low <= high && high <= 65535
		if !valid || proto != "tcp" && proto != "udp" {
			return nil, nil, fmt.Errorf(
				"host %s: firewall.allow: %q should be like 443/tcp or 60000-61000/udp",
				h.Name,
				a,
			)
		}
		ranges[proto] = append(ranges[proto], portRange{low, high})
	}

	format := func(rs []portRange) []string {
		slices.SortFunc(rs, func(a, b portRange) int { return cmp.Or(a.low-b.low, a.high-b.high) })
		var out []string
		for _, r := range slices.Compact(rs) {
			if r.low == r.high {
				out = append(out, strconv.Itoa(r.low))
			} else {
				out = append(out, fmt.Sprintf("%d-%d", r.low, r.high))
			}
		}
		return out
	}
	return format(ranges["tcp"]), format(ranges["udp"]), nil
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
			return nil, fmt.Errorf(
				"host %s: invalid job name %q; use lower case letters, digits, \"-\" and \"_\"",
				h.Name,
				name,
			)
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
		timers = append(timers, host.Service{Name: jobUnitPrefix + name + ".timer", Enabled: true})
	}

	rs := files
	if len(watch) > 0 {
		rs = append(
			rs,
			host.Command{
				Name:      "reload systemd units",
				Watch:     watch,
				ApplyArgv: []string{"systemctl", "daemon-reload"},
			},
		)
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
				return nil, fmt.Errorf(
					"host %s: leftovers.%s.paths: %q must be an absolute path or glob",
					h.Name,
					kept.name,
					p,
				)
			}
		}
		for _, p := range kept.config.Packages {
			if _, err := path.Match(p, ""); err != nil || p == "" || strings.ContainsAny(p, "/ ") {
				return nil, fmt.Errorf(
					"host %s: leftovers.%s.packages: %q must be a package name or glob",
					h.Name,
					kept.name,
					p,
				)
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

package features

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

const (
	resticEnvFile = "/etc/sensible/restic.env"
	// resticWrapper runs restic with the host's repository and settings, for
	// the backup job and for restoring by hand.
	resticWrapper = "/usr/local/sbin/sensible-restic"
	backupScript  = "/usr/local/libexec/sensible-backup"
	backupJob     = "backup"
)

var (
	envName   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	keepFlags = []string{"last", "hourly", "daily", "weekly", "monthly", "yearly"}
)

// backups installs restic and the script the backup job runs. A host that
// stops backing up has the files removed, as they hold its credentials.
func backups(h Host) ([]host.Resource, error) {
	c := h.Config.Restic
	if c == nil {
		if len(h.Config.Backups) > 0 {
			return nil, fmt.Errorf("host %s has backups but no restic settings to keep them with", h.Name)
		}
		return []host.Resource{
			host.Absent{Path: resticEnvFile},
			host.Absent{Path: resticWrapper},
			host.Absent{Path: backupScript},
		}, nil
	}
	script, err := backupScriptContent(h)
	if err != nil {
		return nil, err
	}
	env, err := resticEnv(h.Name, c.Env)
	if err != nil {
		return nil, err
	}

	return append(
		recordedPackages("restic", "rclone"),
		host.Dir{Path: path.Dir(resticEnvFile), Owner: "root", Group: "root", Mode: 0o755},
		host.File{
			Path:    resticEnvFile,
			Content: env,
			Owner:   "root",
			Group:   "root",
			Mode:    0o600,
			Secrets: c.Secrets,
		},
		host.File{
			Path:    resticWrapper,
			Content: resticWrapperContent(c.Options),
			Owner:   "root",
			Group:   "root",
			Mode:    0o755,
		},
		host.Dir{Path: path.Dir(backupScript), Owner: "root", Group: "root", Mode: 0o755},
		host.File{
			Path:    backupScript,
			Content: script,
			Owner:   "root",
			Group:   "root",
			Mode:    0o755,
		},
	), nil
}

func backupJobConfig(h Host) (config.JobConfig, bool) {
	c := h.Config.Restic
	if c == nil {
		return config.JobConfig{}, false
	}
	schedule := c.Schedule
	if schedule == "" {
		schedule = "daily"
	}
	return config.JobConfig{
		Command:  config.Command{backupScript},
		Schedule: schedule,
	}, true
}

// backupScriptContent backs up each entry, continuing past failures, then
// forgets old snapshots and, on Sundays, prunes the repository.
func backupScriptContent(h Host) (string, error) {
	c := h.Config.Restic
	run := func(args ...string) string {
		return shellLine(append([]string{resticWrapper}, args...)) + " || status=1"
	}
	lines := []string{"#!/bin/sh", strings.TrimSuffix(managedHeader, "\n"), "status=0"}

	for _, name := range slices.Sorted(maps.Keys(h.Config.Backups)) {
		b := h.Config.Backups[name]
		hostTag := []string{"backup", "--host", h.Name, "--tag", name}
		switch {
		case !jobName.MatchString(name):
			return "", fmt.Errorf(
				"host %s: invalid backup name %q; use lower case letters, digits, \"-\" and \"_\"",
				h.Name,
				name,
			)
		case (b.Path == "") == (len(b.Command) == 0):
			return "", fmt.Errorf("host %s: backup %s needs exactly one of path and command", h.Name, name)
		case b.Path != "" && !path.IsAbs(b.Path):
			return "", fmt.Errorf("host %s: backup %s: path %q isn't absolute", h.Name, name, b.Path)
		case b.Path != "":
			lines = append(lines, echo("Backing up "+name), run(append(hostTag, "--", b.Path)...))
		default:
			// Unlike piping the command's output to restic, a command that fails
			// leaves no snapshot behind.
			lines = append(
				lines,
				echo("Backing up "+name),
				run(append(append(hostTag, "--stdin-filename", name, "--stdin-from-command", "--"), b.Command...)...),
			)
		}
	}

	if len(c.Keep) == 0 {
		return "", fmt.Errorf("host %s: restic.keep needs at least one count, or backups are never forgotten", h.Name)
	}
	forget := []string{"forget", "--host", h.Name}
	for _, flag := range keepFlags {
		if n, ok := c.Keep[flag]; ok {
			if n < 1 {
				return "", fmt.Errorf("host %s: restic.keep.%s must be at least 1", h.Name, flag)
			}
			forget = append(forget, "--keep-"+flag, strconv.Itoa(n))
		}
	}
	for _, flag := range slices.Sorted(maps.Keys(c.Keep)) {
		if !slices.Contains(keepFlags, flag) {
			return "", fmt.Errorf(
				"host %s: unknown restic.keep %q; expected one of %s",
				h.Name,
				flag,
				strings.Join(keepFlags, ", "),
			)
		}
	}

	return strings.Join(
		append(
			lines,
			echo("Forgetting old snapshots"),
			run(forget...),
			`if [ "$(date +%u)" = 7 ]; then`,
			"\t"+echo("Pruning the repository"),
			"\t"+run("prune"),
			"fi",
			`exit "$status"`,
		),
		"\n",
	) + "\n", nil
}

func resticWrapperContent(options map[string]string) string {
	argv := make([]string, 0, 1+2*len(options))
	argv = append(argv, "restic")
	for _, k := range slices.Sorted(maps.Keys(options)) {
		argv = append(argv, "-o", k+"="+options[k])
	}
	return strings.Join(
		[]string{
			"#!/bin/sh",
			strings.TrimSuffix(managedHeader, "\n"),
			"set -a",
			". " + resticEnvFile,
			"set +a",
			"exec " + shellLine(argv) + ` "$@"`,
		},
		"\n",
	) + "\n"
}

func resticEnv(hostName string, env map[string]string) (string, error) {
	// Without a home directory, as under systemd, restic would run without a
	// cache, fetching far more from the repository.
	env = maps.Clone(env)
	if _, ok := env["RESTIC_CACHE_DIR"]; !ok {
		env["RESTIC_CACHE_DIR"] = "/var/cache/restic"
	}
	var lines []string
	for _, name := range slices.Sorted(maps.Keys(env)) {
		if !envName.MatchString(name) {
			return "", fmt.Errorf("host %s: invalid restic.environment name %q", hostName, name)
		}
		lines = append(lines, name+"="+shellQuote(env[name]))
	}
	return managedLines(lines), nil
}

func echo(message string) string {
	return "echo " + shellQuote(message)
}

func shellLine(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = shellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

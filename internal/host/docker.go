package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// ComposeFile is the name of a stack's compose file in its directory.
const ComposeFile = "docker-compose.yml"

// Container config hashes aren't compared: tools that recreate containers
// with a different version of compose's libraries hash the same config
// differently. Instead, a stack is in sync if every service has its
// containers running, and recreated whenever its files change.
func (r ComposeStack) Check(ctx context.Context, sys Sys) (Change, error) {
	if r.filesChanged(ctx) {
		return drift("recreate, as its files change\n"), nil
	}
	diff, err := r.containerDiff(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	return Change{InSync: diff == "", Diff: diff}, nil
}

func (r ComposeStack) Apply(ctx context.Context, sys Sys) error {
	mode := "--no-recreate"
	if r.filesChanged(ctx) {
		mode = "--force-recreate"
	}
	_, err := runOK(ctx, sys, r.compose("up", "--detach", mode, "--remove-orphans"))
	return err
}

func (r ComposeStack) filesChanged(ctx context.Context) bool {
	modified := state(ctx).modified
	return slices.ContainsFunc(r.Watch, func(id string) bool { return modified[id] })
}

func (r ComposeStack) containerDiff(ctx context.Context, sys Sys) (string, error) {
	res, err := runOK(ctx, sys, r.compose("config", "--format", "json"))
	if err != nil {
		return "", err
	}
	var project struct {
		Name     string `json:"name"`
		Services map[string]struct {
			Scale  *int `json:"scale"`
			Deploy *struct {
				Replicas *int `json:"replicas"`
			} `json:"deploy"`
			DependsOn map[string]struct {
				Condition string `json:"condition"`
			} `json:"depends_on"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &project); err != nil {
		return "", fmt.Errorf("parsing %s's config: %w", r.Dir, err)
	}
	containers, err := listContainers(ctx, sys)
	if err != nil {
		return "", err
	}

	// Services others wait on to complete are satisfied by a clean exit, or
	// by having no container, as pruning removes exited containers. If what
	// waits on them isn't running, it's started and they run first.
	completes := map[string]bool{}
	for _, s := range project.Services {
		for dep, d := range s.DependsOn {
			if d.Condition == "service_completed_successfully" {
				completes[dep] = true
			}
		}
	}
	running, existing := map[string]int{}, map[string]int{}
	for _, c := range containers {
		if c.project != project.Name || c.oneOff {
			continue
		}
		existing[c.service]++
		if c.up() || completes[c.service] && c.succeeded() {
			running[c.service]++
		}
	}

	var diff strings.Builder
	for _, name := range slices.Sorted(maps.Keys(project.Services)) {
		s := project.Services[name]
		want := 1
		switch {
		case s.Scale != nil:
			want = *s.Scale
		case s.Deploy != nil && s.Deploy.Replicas != nil:
			want = *s.Deploy.Replicas
		}
		switch {
		case want == 0 && existing[name] > 0:
			diff.WriteString("remove " + name + ", which has no replicas\n")
		case completes[name] && existing[name] == 0:
		case running[name] < want:
			fmt.Fprintf(&diff, "start %s (%d of %d running)\n", name, running[name], want)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(existing)) {
		if _, ok := project.Services[name]; !ok {
			diff.WriteString("remove " + name + ", which is no longer in the stack\n")
		}
	}
	return diff.String(), nil
}

func (r ComposeStack) compose(args ...string) Cmd {
	return argv(append([]string{"docker", "compose", "--file", filepath.Join(r.Dir, ComposeFile)}, args...)...)
}

type composeContainer struct {
	project, service string
	oneOff           bool
	state, status    string
}

// up counts restarting and paused containers too, as `up` wouldn't change
// them.
func (c composeContainer) up() bool {
	return c.state == "running" || c.state == "restarting" || c.state == "paused"
}

// succeeded reports whether the container exited with 0. docker ps only
// shows the exit code in its status, e.g. "Exited (0) 5 minutes ago".
func (c composeContainer) succeeded() bool {
	return c.state == "exited" && strings.HasPrefix(c.status, "Exited (0)")
}

// containerFormat prints the fields of composeContainer, tab-separated.
const containerFormat = `{{.Label "com.docker.compose.project"}}` +
	"\t" + `{{.Label "com.docker.compose.service"}}` +
	"\t" + `{{.Label "com.docker.compose.oneoff"}}` +
	"\t" + `{{.State}}` +
	"\t" + `{{.Status}}`

// listContainers lists the host's containers once per run, until something
// changes.
func listContainers(ctx context.Context, sys Sys) ([]composeContainer, error) {
	st := state(ctx)
	if st.containers != nil {
		return st.containers, nil
	}
	res, err := runOK(ctx, sys, argv("docker", "ps", "--all", "--format", containerFormat))
	if err != nil {
		return nil, err
	}
	containers := []composeContainer{}
	for line := range strings.Lines(res.Stdout) {
		fields := strings.Split(strings.TrimRight(line, "\n"), "\t")
		if len(fields) != 5 || fields[0] == "" {
			continue
		}
		containers = append(
			containers,
			composeContainer{
				project: fields[0],
				service: fields[1],
				oneOff:  fields[2] == "True",
				state:   fields[3],
				status:  fields[4],
			},
		)
	}
	st.containers = containers
	return containers, nil
}

func (r ComposeProjects) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := undeclaredIn(sys, state(ctx).declared, r.Path, false)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, path := range extra {
		diff.WriteString("take down and remove " + path + "\n")
	}
	return Change{InSync: len(extra) == 0, Diff: diff.String()}, nil
}

func (r ComposeProjects) Apply(ctx context.Context, sys Sys) error {
	extra, err := undeclaredIn(sys, state(ctx).declared, r.Path, false)
	if err != nil {
		return err
	}
	for _, path := range extra {
		info, err := sys.Lstat(path)
		if err != nil {
			return err
		}
		// By name, so it works even if the compose file is broken or gone.
		if info.IsDir() {
			down := argv("docker", "compose", "--project-name", filepath.Base(path), "down", "--remove-orphans")
			if _, err := runOK(ctx, sys, down); err != nil {
				return err
			}
		}
		if err := sys.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

// networkLabel marks the networks sensible created, which it may remove.
const networkLabel = "sensible.managed=true"

func (r DockerNetwork) Check(ctx context.Context, sys Sys) (Change, error) {
	existing, ok, err := r.inspect(ctx, sys)
	if err != nil || !ok {
		return drift("create network\n"), err
	}
	var warnings []string
	if existing.EnableIPv6 != r.IPv6 {
		warnings = append(warnings, fmt.Sprintf("IPv6 is %s rather than %s", onOff(existing.EnableIPv6), onOff(r.IPv6)))
	}
	var subnets []string
	for _, c := range existing.IPAM.Config {
		subnets = append(subnets, c.Subnet)
	}
	// Docker picks a subnet for any family none is given for, so only the
	// families with declared subnets are compared.
	for _, ipv6 := range []bool{false, true} {
		want := subnetsIn(r.Subnets, ipv6)
		if have := subnetsIn(subnets, ipv6); len(want) > 0 && !slices.Equal(have, want) {
			warnings = append(
				warnings,
				fmt.Sprintf("subnets are %s rather than %s", listOrNone(have), strings.Join(want, ", ")),
			)
		}
	}
	if len(warnings) == 0 {
		return Change{InSync: true}, nil
	}
	return Change{
		InSync:  true,
		Warning: strings.Join(warnings, "\n") + "\nremove the network by hand for it to be recreated\n",
	}, nil
}

func (r DockerNetwork) Apply(ctx context.Context, sys Sys) error {
	args := []string{"docker", "network", "create", "--label", networkLabel}
	if r.IPv6 {
		args = append(args, "--ipv6")
	}
	for _, s := range r.Subnets {
		args = append(args, "--subnet", s)
	}
	_, err := runOK(ctx, sys, argv(append(args, r.Name)...))
	return err
}

type networkInfo struct {
	EnableIPv6 bool `json:"EnableIPv6"`
	IPAM       struct {
		Config []struct {
			Subnet string `json:"Subnet"`
		} `json:"Config"`
	} `json:"IPAM"`
}

func (r DockerNetwork) inspect(ctx context.Context, sys Sys) (networkInfo, bool, error) {
	names, err := listNetworks(ctx, sys, "name=^"+r.Name+"$")
	if err != nil || !slices.Contains(names, r.Name) {
		return networkInfo{}, false, err
	}
	res, err := runOK(ctx, sys, argv("docker", "network", "inspect", r.Name))
	if err != nil {
		return networkInfo{}, false, err
	}
	var info []networkInfo
	if err := json.Unmarshal([]byte(res.Stdout), &info); err != nil {
		return networkInfo{}, false, fmt.Errorf("parsing network %s: %w", r.Name, err)
	}
	if len(info) != 1 {
		return networkInfo{}, false, fmt.Errorf("expected one network called %s, found %d", r.Name, len(info))
	}
	return info[0], true, nil
}

// listNetworks returns the names of the networks matching filter. Before
// Docker is installed, that's none, but the check can't be relied on yet.
func listNetworks(ctx context.Context, sys Sys, filter string) ([]string, error) {
	res, err := runOK(ctx, sys, argv("docker", "network", "ls", "--filter", filter, "--format", "{{.Name}}"))
	if err != nil {
		return nil, notYetIfMissing(err)
	}
	return strings.Fields(res.Stdout), nil
}

func (r DockerNetworks) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.undeclared(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, name := range extra {
		diff.WriteString("remove network " + name + "\n")
	}
	return Change{InSync: len(extra) == 0, Diff: diff.String()}, nil
}

func (r DockerNetworks) Apply(ctx context.Context, sys Sys) error {
	extra, err := r.undeclared(ctx, sys)
	if err != nil {
		return err
	}
	for _, name := range extra {
		if _, err := runOK(ctx, sys, argv("docker", "network", "rm", name)); err != nil {
			return err
		}
	}
	return nil
}

// undeclared lists sensible's networks that aren't declared. A host without
// Docker has none.
func (r DockerNetworks) undeclared(ctx context.Context, sys Sys) ([]string, error) {
	names, err := listNetworks(ctx, sys, "label="+networkLabel)
	if errors.Is(err, exec.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	declared := state(ctx).networks
	return slices.DeleteFunc(names, func(n string) bool { return declared[n] }), nil
}

// subnetsIn returns the subnets of one address family, sorted. Subnets that
// don't parse count as IPv4.
func subnetsIn(subnets []string, ipv6 bool) []string {
	var out []string
	for _, s := range subnets {
		p, err := netip.ParsePrefix(s)
		if (err == nil && p.Addr().Is6()) == ipv6 {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func onOff(b bool) string {
	return map[bool]string{true: "on", false: "off"}[b]
}

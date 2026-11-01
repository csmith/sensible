package host

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
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
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &project); err != nil {
		return "", fmt.Errorf("parsing %s's config: %w", r.Dir, err)
	}
	containers, err := listContainers(ctx, sys)
	if err != nil {
		return "", err
	}

	running, existing := map[string]int{}, map[string]int{}
	for _, c := range containers {
		if c.project != project.Name || c.oneOff {
			continue
		}
		existing[c.service]++
		if c.up() {
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
	state            string
}

// up counts restarting and paused containers too, as `up` wouldn't change
// them.
func (c composeContainer) up() bool {
	return c.state == "running" || c.state == "restarting" || c.state == "paused"
}

// containerFormat prints the fields of composeContainer, tab-separated.
const containerFormat = `{{.Label "com.docker.compose.project"}}` +
	"\t" + `{{.Label "com.docker.compose.service"}}` +
	"\t" + `{{.Label "com.docker.compose.oneoff"}}` +
	"\t" + `{{.State}}`

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
		if len(fields) != 4 || fields[0] == "" {
			continue
		}
		containers = append(
			containers,
			composeContainer{project: fields[0], service: fields[1], oneOff: fields[2] == "True", state: fields[3]},
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

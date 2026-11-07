package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/host"
)

var pruneResources = host.ResourceList{host.Package{Name: "zsh"}, host.Volumes{Path: "/srv/volumes"}}

func TestPrune_asksBeforeRemovingEachLeftover(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	answers := map[string]bool{
		"Remove /srv/volumes/old from acidburn? [y/N] ":   true,
		"Remove /srv/volumes/older from acidburn? [y/N] ": false,
	}
	f.runner.Confirm = func(prompt string) (bool, error) {
		f.confirmed = append(f.confirmed, prompt)
		return answers[prompt], nil
	}
	agent := &fakeAgent{leftovers: map[string][]string{"volumes:/srv/volumes": {"/srv/volumes/old", "/srv/volumes/older"}}}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Len(t, f.confirmed, 2)
	assert.Equal(t, []string{"/srv/volumes/old"}, agent.removed)
	assert.Contains(t, f.out.String(), "  ✓ acidburn: /srv/volumes/old\n  - acidburn: /srv/volumes/older  kept\n")
}

func TestPrune_skipsHostsWithChangesToApply(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	agent := &fakeAgent{
		leftovers: map[string][]string{"volumes:/srv/volumes": {"/srv/volumes/old"}},
	}
	agent.status = func(r host.Resource) host.Status {
		if r.ID() == "package:zsh" {
			return host.StatusDrifted
		}
		return host.StatusInSync
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Empty(t, f.confirmed)
	assert.NotContains(t, agent.messages(), "Prune")
	assert.Contains(t, f.out.String(), "1 change to apply first")
}

func TestPrune_reportsFailedRemoval(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	agent := &fakeAgent{
		leftovers:     map[string][]string{"volumes:/srv/volumes": {"/srv/volumes/old"}},
		removeFailure: "/srv/volumes/old",
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.ErrorIs(t, err, errFailed)
	assert.Contains(t, f.out.String(), "✗ acidburn: /srv/volumes/old: busy")
}

func TestPrune_nothingToPrune(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", &fakeAgent{})})

	require.NoError(t, err)
	assert.Empty(t, f.confirmed)
	assert.Contains(t, f.out.String(), "Nothing to prune\n")
}

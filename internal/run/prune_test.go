package run

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/host"
)

var pruneResources = host.ResourceList{
	host.Package{Name: "zsh"},
	host.Volumes{Path: "/srv/volumes"},
}

func TestPrune_asksBeforeRemovingEachLeftover(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	answers := map[string]string{
		"Remove /srv/volumes/old from acidburn? [y/N/p] ":   "y",
		"Remove /srv/volumes/older from acidburn? [y/N/p] ": "n",
	}
	f.runner.Ask = func(prompt string) (string, error) {
		f.confirmed = append(f.confirmed, prompt)
		return answers[prompt], nil
	}
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/old", "/srv/volumes/older"},
		},
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Len(t, f.confirmed, 2)
	assert.Equal(t, []string{"/srv/volumes/old"}, agent.removed)
	assert.Contains(t, f.out.String(), "  ✓ acidburn: /srv/volumes/old\n  - acidburn: /srv/volumes/older  kept\n")
}

func TestPrune_ignoreAnswerRecordsTheLeftover(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	var ignored []string
	f.runner.Compile = func(target, host.Facts) (compiled, error) {
		return compiled{
			resources: pruneResources,
			ignored: map[string][]string{
				"volumes:/srv/volumes": {"/srv/volumes/kept"},
			},
			ignore: func(id, item string) error {
				ignored = append(ignored, id+" "+item)
				return nil
			},
		}, nil
	}
	f.runner.Ask = func(prompt string) (string, error) {
		f.confirmed = append(f.confirmed, prompt)
		return "i", nil
	}
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/old"},
		},
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Equal(t, []string{"Remove /srv/volumes/old from acidburn? [y/N/i/p] "}, f.confirmed)
	assert.Equal(t, []string{"volumes:/srv/volumes /srv/volumes/old"}, ignored)
	assert.Empty(t, agent.removed)
	assert.Equal(
		t,
		map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/kept"},
		},
		agent.ignored,
	)
	assert.Contains(t, f.out.String(), "  - acidburn: /srv/volumes/old  ignored\n")
}

func TestPrune_previewShowsAPathThenAsksAgain(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	answers := []string{"p", "preview", "y"}
	f.runner.Ask = func(prompt string) (string, error) {
		f.confirmed = append(f.confirmed, prompt)
		answer := answers[0]
		answers = answers[1:]
		return answer, nil
	}
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/old"},
		},
		previews: map[string]host.Previewed{
			"/srv/volumes/old": {
				Lines: []string{"data/", "data/\x1b[2Jfile"},
				Cut:   "3 more entries",
			},
		},
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Equal(t, slices.Repeat([]string{"Remove /srv/volumes/old from acidburn? [y/N/p] "}, 3), f.confirmed)
	assert.Equal(t, []string{"/srv/volumes/old"}, agent.removed)
	preview := "    data/\n    data/\\x1b[2Jfile\n    … 3 more entries\n"
	assert.Equal(t, 2, strings.Count(f.out.String(), preview))
}

func TestPrune_reportsFailedPreviewThenAsksAgain(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	answers := []string{"p", "n"}
	f.runner.Ask = func(prompt string) (string, error) {
		answer := answers[0]
		answers = answers[1:]
		return answer, nil
	}
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/old"},
		},
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Empty(t, answers)
	assert.Contains(t, f.out.String(), "✗ acidburn: /srv/volumes/old: not found")
	assert.Contains(t, f.out.String(), "- acidburn: /srv/volumes/old  kept")
}

func TestPrune_offersNoPreviewOfLeftoversThatArentPaths(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	f.runner.Ask = func(prompt string) (string, error) {
		f.confirmed = append(f.confirmed, prompt)
		return "p", nil
	}
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"user bob"},
		},
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Equal(t, []string{"Remove user bob from acidburn? [y/N] "}, f.confirmed)
	assert.NotContains(t, agent.messages(), "Preview")
}

func TestPrune_keepsSecretsWhoseVolumeIsIgnored(t *testing.T) {
	f := newRunnerFixture(t, nil)
	f.runner.Compile = func(target, host.Facts) (compiled, error) {
		return compiled{
			resources: pruneResources,
			ignored: map[string][]string{
				"volumes:/srv/volumes": {"/srv/volumes/app"},
			},
			unusedSecrets: []savedSecrets{
				{
					stack: "app",
					names: []string{"db"},
					drop:  func() error { return nil },
				},
			},
		}, nil
	}

	err := f.runner.Prune(t.Context(), []target{
		f.target("acidburn", &fakeAgent{}),
	})

	require.NoError(t, err)
	assert.Empty(t, f.confirmed)
	assert.Contains(t, f.out.String(), "Nothing to prune\n")
}

func TestPrune_skipsHostsWithChangesToApply(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/old"},
		},
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
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/old"},
		},
		removeFailure: "/srv/volumes/old",
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.ErrorIs(t, err, errFailed)
	assert.Contains(t, f.out.String(), "✗ acidburn: /srv/volumes/old: busy")
}

func TestPrune_nothingToPrune(t *testing.T) {
	f := newRunnerFixture(t, pruneResources)

	err := f.runner.Prune(t.Context(), []target{
		f.target("acidburn", &fakeAgent{}),
	})

	require.NoError(t, err)
	assert.Empty(t, f.confirmed)
	assert.Contains(t, f.out.String(), "Nothing to prune\n")
}

// withUnusedSecrets has the fixture's hosts report saved values for the
// stacks, returning the stacks whose values were dropped.
func withUnusedSecrets(f *runnerFixture, stacks ...string) *[]string {
	var dropped []string
	f.runner.Compile = func(target, host.Facts) (compiled, error) {
		c := compiled{resources: pruneResources}
		for _, s := range stacks {
			c.unusedSecrets = append(
				c.unusedSecrets,
				savedSecrets{
					stack: s,
					names: []string{"db", "token"},
					drop: func() error {
						dropped = append(dropped, s)
						return nil
					},
				},
			)
		}
		return c, nil
	}
	return &dropped
}

func TestPrune_offersSecretsOnceTheirVolumesAreRemoved(t *testing.T) {
	f := newRunnerFixture(t, nil)
	dropped := withUnusedSecrets(f, "app", "kept", "gone")
	answers := map[string]string{
		"Remove /srv/volumes/app from acidburn? [y/N/p] ":                     "y",
		"Remove /srv/volumes/kept from acidburn? [y/N/p] ":                    "n",
		"Remove generated secrets for app (db, token) from acidburn? [y/N] ":  "y",
		"Remove generated secrets for gone (db, token) from acidburn? [y/N] ": "y",
	}
	f.runner.Ask = func(prompt string) (string, error) {
		f.confirmed = append(f.confirmed, prompt)
		return answers[prompt], nil
	}
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/app", "/srv/volumes/kept"},
		},
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{
			"Remove /srv/volumes/app from acidburn? [y/N/p] ",
			"Remove /srv/volumes/kept from acidburn? [y/N/p] ",
			"Remove generated secrets for app (db, token) from acidburn? [y/N] ",
			"Remove generated secrets for gone (db, token) from acidburn? [y/N] ",
		},
		f.confirmed,
	)
	assert.Equal(t, []string{"app", "gone"}, *dropped)
	assert.Contains(t, f.out.String(), "- generated secrets for kept (db, token)  once /srv/volumes/kept is removed\n")
	assert.Contains(
		t,
		f.out.String(),
		"- acidburn: generated secrets for kept (db, token)  kept with /srv/volumes/kept\n",
	)
}

func TestPrune_keepsSecretsWhenTheirVolumeRemovalFails(t *testing.T) {
	f := newRunnerFixture(t, nil)
	dropped := withUnusedSecrets(f, "app")
	agent := &fakeAgent{
		leftovers: map[string][]string{
			"volumes:/srv/volumes": {"/srv/volumes/app"},
		},
		removeFailure: "/srv/volumes/app",
	}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.ErrorIs(t, err, errFailed)
	assert.Equal(t, []string{"Remove /srv/volumes/app from acidburn? [y/N/p] "}, f.confirmed)
	assert.Empty(t, *dropped)
}

func TestPrune_offersNoSecretsWhenLeftoversCantBeListed(t *testing.T) {
	f := newRunnerFixture(t, nil)
	dropped := withUnusedSecrets(f, "app")
	agent := &fakeAgent{listFailure: "volumes:/srv/volumes"}

	err := f.runner.Prune(t.Context(), []target{f.target("acidburn", agent)})

	require.ErrorIs(t, err, errFailed)
	assert.Empty(t, f.confirmed)
	assert.Empty(t, *dropped)
	assert.NotContains(t, f.out.String(), "generated secrets")
}

func TestPrune_warnsAboutSecretsOfStacksStillThere(t *testing.T) {
	f := newRunnerFixture(t, nil)
	dropped := false
	f.runner.Compile = func(target, host.Facts) (compiled, error) {
		return compiled{
			resources: pruneResources,
			unusedSecrets: []savedSecrets{{
				stack: "app",
				names: []string{"old"},
				inUse: true,
				drop: func() error {
					dropped = true
					return nil
				},
			}},
		}, nil
	}
	f.runner.Ask = func(prompt string) (string, error) {
		f.confirmed = append(f.confirmed, prompt)
		return "y", nil
	}
	err := f.runner.Prune(t.Context(), []target{
		f.target("acidburn", &fakeAgent{}),
	})

	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{
			"Remove generated secrets app no longer uses (old) from acidburn? " +
				"Data in its volumes may still use them. [y/N] ",
		},
		f.confirmed,
	)
	assert.True(t, dropped)
	assert.Contains(
		t,
		f.out.String(),
		"- generated secrets app no longer uses (old)  data in its volumes may still use them\n",
	)
}

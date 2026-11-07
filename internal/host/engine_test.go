package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResource is a resource whose state each test controls.
type fakeResource struct {
	id       string
	inSync   bool
	needs    *fakeResource
	checkErr error
	applyErr error
	notify   ResourceList
	log      *[]string

	applied bool
}

func (r *fakeResource) ID() string             { return r.id }
func (r *fakeResource) Notifies() ResourceList { return r.notify }

func (r *fakeResource) Check(context.Context, Sys) (Change, error) {
	if r.checkErr != nil {
		return Change{}, r.checkErr
	}
	if r.needs != nil && !r.needs.applied {
		return Change{}, ErrNotYetCheckable
	}
	return Change{InSync: r.inSync || r.applied, Diff: "change " + r.id}, nil
}

func (r *fakeResource) Apply(context.Context, Sys) error {
	*r.log = append(*r.log, r.id)
	if r.applyErr != nil {
		return r.applyErr
	}
	r.applied = true
	return nil
}

func newTestEngine() *engine {
	return &engine{log: io.Discard}
}

func collectChecked(t *testing.T, list ResourceList) ([]Checked, bool) {
	t.Helper()
	var got []Checked
	failedAt, err := newTestEngine().check(
		context.Background(),
		list,
		func(c Checked) error {
			got = append(got, c)
			return nil
		},
	)
	require.NoError(t, err)
	return got, failedAt >= 0
}

func collectApplied(t *testing.T, list ResourceList) ([]Applied, bool) {
	t.Helper()
	var got []Applied
	failed, err := newTestEngine().apply(
		context.Background(),
		list,
		-1,
		func(msg any) error {
			if a, ok := msg.(Applied); ok {
				got = append(got, a)
			}
			return nil
		},
	)
	require.NoError(t, err)
	return got, failed
}

func statuses[T Checked | Applied](results []T) []string {
	var out []string
	for _, r := range results {
		switch r := any(r).(type) {
		case Checked:
			out = append(out, r.ID+" "+string(r.Status))
		case Applied:
			out = append(out, r.ID+" "+string(r.Status))
		}
	}
	return out
}

func TestEngineCheck_Statuses(t *testing.T) {
	var log []string
	repo := &fakeResource{id: "repo", log: &log}

	got, failed := collectChecked(
		t,
		ResourceList{
			&fakeResource{id: "early", needs: &fakeResource{}, log: &log},
			&fakeResource{id: "ok", inSync: true, log: &log},
			repo,
			&fakeResource{id: "pkg", needs: repo, log: &log},
			&fakeResource{id: "broken", checkErr: errors.New("boom"), log: &log},
			&fakeResource{id: "after", log: &log},
		},
	)

	assert.True(t, failed)
	assert.Equal(
		t,
		[]string{"early failed", "ok in-sync", "repo drifted", "pkg deferred", "broken failed", "after drifted"},
		statuses(got),
	)
	assert.Equal(t, "change repo", got[2].Diff)
	assert.Equal(t, "boom", got[4].Error)
	assert.Empty(t, log, "check mustn't apply anything")
}

func TestEngineCheck_SkipsCleanUpAfterFailure(t *testing.T) {
	var log []string
	got, _ := collectChecked(
		t,
		ResourceList{
			&fakeResource{id: "broken", checkErr: errors.New("boom"), log: &log},
			OwnedDir{Path: "/etc/sudoers.d"},
			ComposeProjects{Path: "/srv/compose"},
		},
	)

	assert.Equal(
		t,
		[]string{"broken failed", "owned-dir:/etc/sudoers.d skipped", "compose-projects:/srv/compose skipped"},
		statuses(got),
	)
}

func TestEngine_ComposeStackSeesItsFilesChange(t *testing.T) {
	var log []string
	stack := ComposeStack{Dir: "/srv/compose/web", Watch: []string{"conf", "env"}}
	repo := &fakeResource{id: "repo", log: &log}
	got, _ := collectChecked(
		t,
		ResourceList{
			repo,
			&fakeResource{id: "conf", inSync: true, log: &log},
			&fakeResource{id: "env", needs: repo, log: &log},
			stack,
		},
	)
	assert.Equal(t, "env deferred", statuses(got)[2])
	assert.Equal(t, "recreate, as its files change\n", got[3].Diff)

	sys := newTestSys(t)
	sys.on("docker compose *", "", 0)
	e := newTestEngine()
	e.sys = sys
	_, err := e.apply(
		context.Background(),
		ResourceList{&fakeResource{id: "conf", inSync: true, log: &log}, &fakeResource{id: "env", log: &log}, stack},
		-1,
		func(any) error { return nil },
	)
	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{"docker compose --file /srv/compose/web/docker-compose.yml up --detach --force-recreate --remove-orphans"},
		sys.ran,
	)
}

func TestEngineApply_AppliesDeferredAndRunsHandlersOnce(t *testing.T) {
	var log []string
	reload := &fakeResource{id: "reload", log: &log}
	repo := &fakeResource{id: "repo", log: &log, notify: ResourceList{reload}}
	never := &fakeResource{id: "never", log: &log}
	reloadAgain := &fakeResource{id: "reload", log: &log}

	got, failed := collectApplied(
		t,
		ResourceList{
			&fakeResource{id: "quiet", inSync: true, log: &log, notify: ResourceList{never}},
			repo,
			&fakeResource{id: "pkg", needs: repo, log: &log, notify: ResourceList{reloadAgain}},
		},
	)

	assert.False(t, failed)
	assert.Equal(t, []string{"quiet in-sync", "repo changed", "pkg changed", "reload changed"}, statuses(got))
	assert.True(t, got[3].Handler)
	assert.Equal(t, "change pkg", got[2].Diff)
	assert.Equal(t, []string{"repo", "pkg", "reload"}, log)
}

func TestEngineApply_AnnouncesEachChangeBeforeMakingIt(t *testing.T) {
	var log, sent []string
	reload := &fakeResource{id: "reload", log: &log}
	_, err := newTestEngine().apply(
		context.Background(),
		ResourceList{
			&fakeResource{id: "quiet", inSync: true, log: &log},
			&fakeResource{id: "config", log: &log, notify: ResourceList{reload}},
		},
		-1,
		func(msg any) error {
			switch m := msg.(type) {
			case Applying:
				sent = append(sent, fmt.Sprintf("applying %s handler=%t after %v", m.ID, m.Handler, log))
			case Applied:
				sent = append(sent, "applied "+m.ID)
			}
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{
			"applied quiet",
			"applying config handler=false after []",
			"applied config",
			"applying reload handler=true after [config]",
			"applied reload",
		},
		sent,
	)
}

func TestEngineApply_FailureSkipsRestButRunsDueHandlers(t *testing.T) {
	var log []string
	reload := &fakeResource{id: "reload", log: &log}
	restart := &fakeResource{id: "restart", log: &log}

	got, failed := collectApplied(
		t,
		ResourceList{
			&fakeResource{id: "config", log: &log, notify: ResourceList{reload}},
			&fakeResource{id: "bad", applyErr: errors.New("boom"), log: &log, notify: ResourceList{restart}},
			&fakeResource{id: "later", log: &log},
			OwnedDir{Path: "/etc/sudoers.d"},
		},
	)

	assert.True(t, failed)
	assert.Equal(
		t,
		[]string{"config changed", "bad failed", "later skipped", "owned-dir:/etc/sudoers.d skipped", "reload changed"},
		statuses(got),
	)
	assert.Equal(t, "boom", got[1].Error)
	assert.Equal(t, []string{"config", "bad", "reload"}, log)
}

func TestEngineApply_NotYetCheckableFailsDuringApply(t *testing.T) {
	var log []string
	got, failed := collectApplied(t, ResourceList{&fakeResource{id: "pkg", needs: &fakeResource{}, log: &log}})

	assert.True(t, failed)
	assert.Equal(t, StatusFailed, got[0].Status)
}

func TestEngineApply_DuplicateIDsAreHandledByPosition(t *testing.T) {
	var log []string
	got, _ := collectApplied(
		t,
		ResourceList{
			&fakeResource{id: "user:chris", inSync: true, log: &log},
			&fakeResource{id: "user:chris", log: &log},
		},
	)

	assert.Equal(t, []string{"user:chris in-sync", "user:chris changed"}, statuses(got))
}

func TestEngineApply_LostConnectionStopsAfterCurrentResource(t *testing.T) {
	var log []string
	reload := &fakeResource{id: "reload", log: &log}
	lost := errors.New("broken pipe")

	failed, err := newTestEngine().apply(
		context.Background(),
		ResourceList{
			&fakeResource{id: "config", log: &log, notify: ResourceList{reload}},
			&fakeResource{id: "next", log: &log},
		},
		-1,
		func(any) error { return lost },
	)

	require.ErrorIs(t, err, lost)
	assert.False(t, failed)
	assert.Equal(t, []string{"config", "reload"}, log)
}

func TestEngine_OwnedDirKeepsAptRepoFiles(t *testing.T) {
	sys := newDebianSys(t)
	sys.urls["https://pkgs.example.com/key.gpg"] = "\x99binary"
	sys.write(AptSourcesDir+"/example.sources", "")
	sys.write(AptSourcesDir+"/stray.list", "")
	sys.write(AptKeyringsDir+"/example.asc", "")
	sys.write(AptKeyringsDir+"/stray.gpg", "")
	e := newTestEngine()
	e.sys = sys

	_, err := e.apply(
		context.Background(),
		ResourceList{
			AptRepo{
				Name:          "example",
				URIs:          []string{"https://pkgs.example.com/debian"},
				Suites:        []string{"trixie"},
				SigningKeyURL: "https://pkgs.example.com/key.gpg",
			},
			OwnedDir{Path: AptSourcesDir},
			OwnedDir{Path: AptKeyringsDir},
		},
		-1,
		func(any) error { return nil },
	)

	require.NoError(t, err)
	names, err := sys.ReadDir(AptSourcesDir)
	require.NoError(t, err)
	assert.Equal(t, []string{"example.sources"}, names)
	// The key isn't armored, so the old armored copy goes too.
	names, err = sys.ReadDir(AptKeyringsDir)
	require.NoError(t, err)
	assert.Equal(t, []string{"example.gpg"}, names)
}

func TestEngine_OwnedDirSeesFilesDeclaredEarlier(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/keep", "x\n")
	sys.write("/etc/sudoers.d/stray", "")
	e := newTestEngine()
	e.sys = sys

	var got []Applied
	_, err := e.apply(
		context.Background(),
		ResourceList{
			File{Path: "/etc/sudoers.d/keep", Content: "x\n"},
			OwnedDir{Path: "/etc/sudoers.d"},
		},
		-1,
		func(msg any) error {
			if a, ok := msg.(Applied); ok {
				got = append(got, a)
			}
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"file:/etc/sudoers.d/keep in-sync", "owned-dir:/etc/sudoers.d changed"}, statuses(got))
	assert.True(t, sys.exists("/etc/sudoers.d/keep"))
	assert.False(t, sys.exists("/etc/sudoers.d/stray"))
}

func TestEngine_ApplySkipsCleanUpsAfterFailedCheck(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/stray", "")
	sys.write("/etc/early.d/stray", "")
	e := newTestEngine()
	e.sys = sys
	var log []string
	flaky := &fakeResource{id: "flaky", checkErr: errors.New("timed out"), log: &log}
	list := ResourceList{OwnedDir{Path: "/etc/early.d"}, flaky, OwnedDir{Path: "/etc/sudoers.d"}}

	failedAt, err := e.check(context.Background(), list, func(Checked) error { return nil })
	require.NoError(t, err)
	require.Equal(t, 1, failedAt)

	flaky.checkErr = nil
	var got []Applied
	failed, err := e.apply(
		context.Background(),
		list,
		failedAt,
		func(msg any) error {
			if a, ok := msg.(Applied); ok {
				got = append(got, a)
			}
			return nil
		},
	)

	require.NoError(t, err)
	assert.False(t, failed)
	assert.Equal(
		t,
		[]string{"owned-dir:/etc/early.d changed", "flaky changed", "owned-dir:/etc/sudoers.d skipped"},
		statuses(got),
	)
	assert.False(t, sys.exists("/etc/early.d/stray"), "the check showed this clean-up, so it runs")
	assert.True(t, sys.exists("/etc/sudoers.d/stray"))
}

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

func newTestEngine(t *testing.T) *engine {
	return &engine{sys: newTestSys(t), log: io.Discard}
}

func collectChecked(t *testing.T, list ResourceList) ([]Checked, bool) {
	t.Helper()
	var got []Checked
	failedAt, err := newTestEngine(t).check(
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
	failed, err := newTestEngine(t).apply(
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
	e := newTestEngine(t)
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
	_, err := newTestEngine(t).apply(
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

	failed, err := newTestEngine(t).apply(
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

func TestEngine_DisownedAptSourcesKeepsWhatApplyDoesNotDeclare(t *testing.T) {
	sys := newDebianSys(t)
	sys.urls["https://pkgs.example.com/key.gpg"] = "\x99binary"
	sys.write(AptSourcesDir+"/debian.sources", "Types: deb\nSigned-By: /etc/apt/keyrings/debian.gpg\n")
	sys.write(AptKeyringsDir+"/debian.gpg", "")
	sys.write(AptKeyringsDir+"/example.asc", "")
	list := ResourceList{
		AptRepo{
			Name:          "example",
			URIs:          []string{"https://pkgs.example.com/debian"},
			Suites:        []string{"trixie"},
			SigningKeyURL: "https://pkgs.example.com/key.gpg",
		},
		DisownedAptSources{},
	}
	e := newTestEngine(t)
	e.sys = sys

	_, err := e.apply(context.Background(), list, -1, func(any) error { return nil })
	require.NoError(t, err)

	names, err := sys.ReadDir(AptSourcesDir)
	require.NoError(t, err)
	assert.Equal(t, []string{"debian.sources", "example.sources"}, names)
	names, err = sys.ReadDir(AptKeyringsDir)
	require.NoError(t, err)
	assert.Equal(t, []string{"debian.gpg", "example.asc", "example.gpg"}, names)

	// The key isn't armored, so the old armored copy is left over. The
	// distribution's key is kept while its source refers to it.
	leftovers := func() []string {
		var found []Leftovers
		_, err := e.leftovers(
			context.Background(),
			list,
			func(l Leftovers) error {
				found = append(found, l)
				return nil
			},
		)
		require.NoError(t, err)
		require.Len(t, found, 1)
		return found[0].Items
	}
	assert.Equal(t, []string{AptSourcesDir + "/debian.sources", AptKeyringsDir + "/example.asc"}, leftovers())

	require.NoError(t, e.remove(context.Background(), list, "disowned-apt-sources", AptSourcesDir+"/debian.sources"))
	assert.False(t, sys.exists(AptSourcesDir+"/debian.sources"))
	assert.Equal(t, []string{AptKeyringsDir + "/debian.gpg", AptKeyringsDir + "/example.asc"}, leftovers())
}

func TestEngine_IgnoredLeftoversAreNeitherWarnedAboutNorListed(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/README", "")
	sys.write("/etc/sudoers.d/stray", "")
	sys.write("/etc/early.d/README", "")
	e := newTestEngine(t)
	e.sys = sys
	// The same path under another resource is still a leftover.
	e.ignored = map[string][]string{
		"owned-dir:/etc/sudoers.d": {"/etc/sudoers.d/README"},
		"owned-dir:/etc/other.d":   {"/etc/early.d/README"},
	}
	list := ResourceList{
		OwnedDir{Path: "/etc/sudoers.d", Header: "# managed"},
		OwnedDir{Path: "/etc/early.d", Header: "# managed"},
	}

	var checked []Checked
	_, err := e.check(
		context.Background(),
		list,
		func(c Checked) error {
			checked = append(checked, c)
			return nil
		},
	)
	require.NoError(t, err)
	require.Len(t, checked, 2)
	assert.Contains(t, checked[0].Warning, "/etc/sudoers.d/stray")
	assert.NotContains(t, checked[0].Warning, "README")
	assert.Contains(t, checked[1].Warning, "/etc/early.d/README")

	var found []Leftovers
	_, err = e.leftovers(
		context.Background(),
		list,
		func(l Leftovers) error {
			found = append(found, l)
			return nil
		},
	)
	require.NoError(t, err)
	assert.Equal(
		t,
		[]Leftovers{
			{ID: "owned-dir:/etc/sudoers.d", Items: []string{"/etc/sudoers.d/stray"}},
			{ID: "owned-dir:/etc/early.d", Items: []string{"/etc/early.d/README"}},
		},
		found,
	)
}

func TestEngine_KeptLeftoversAreNeitherWarnedAboutNorListed(t *testing.T) {
	for _, tt := range []struct {
		name    string
		sys     func(*testing.T) *testSys
		ignored string
	}{
		{"arch", newArchSys, "vi*"},
		{"debian", newDebianSys, "pam-*"},
	} {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := tt.sys(t)
				sys.write("/etc/sudoers.d/README", "")
				sys.write("/etc/sudoers.d/stray", "")
				sys.write("/opt/tool-1", "")
				sys.write("/opt/other", "")
				e := newTestEngine(t)
				e.sys = sys
				list := ResourceList{
					KeptLeftovers{Paths: []string{"/etc/sudoers.d/README"}, Packages: []string{tt.ignored}},
					KeptLeftovers{Paths: []string{"/opt/tool-*", "/opt/missing"}, Packages: []string{"zsh", "nope*"}, External: true},
					OwnedDir{Path: "/etc/sudoers.d", Header: "# managed"},
					Disowned{Name: "opt", Paths: []string{"/opt/*"}},
					DisownedPackages{},
				}

				var warnings []string
				_, err := e.check(
					context.Background(),
					list,
					func(c Checked) error {
						assert.Equal(t, StatusInSync, c.Status, c.ID)
						warnings = append(warnings, c.Warning)
						return nil
					},
				)
				require.NoError(t, err)
				assert.Equal(
					t,
					[]string{
						"",
						"/opt/missing\npackage nope*\nmissing, but expected from outside sensible\n",
					},
					warnings[:2],
				)
				assert.Contains(t, warnings[2], "/etc/sudoers.d/stray")
				assert.NotContains(t, warnings[2], "README")
				assert.Contains(t, warnings[3], "/opt/other")
				assert.NotContains(t, warnings[3], "tool")
				assert.Empty(t, warnings[4])

				var found []Leftovers
				_, err = e.leftovers(
					context.Background(),
					list,
					func(l Leftovers) error {
						found = append(found, l)
						return nil
					},
				)
				require.NoError(t, err)
				assert.Equal(
					t,
					[]Leftovers{
						{ID: "owned-dir:/etc/sudoers.d", Items: []string{"/etc/sudoers.d/stray"}},
						{ID: "disowned:opt", Items: []string{"/opt/other"}},
					},
					found,
				)
			},
		)
	}
}

func TestEngine_OwnedDirSeesFilesDeclaredEarlier(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/etc/sudoers.d/keep", "x\n")
	sys.write("/etc/sudoers.d/stray", "")
	e := newTestEngine(t)
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
	e := newTestEngine(t)
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

// run checks then applies list as a session would, reading what's owed from
// sys before each, and returns both phases' results.
func run(t *testing.T, sys *testSys, list ResourceList) ([]Checked, []Applied) {
	t.Helper()
	e := &engine{sys: sys, log: io.Discard}
	readOwed := func() {
		owed, err := readOwed(sys)
		require.NoError(t, err)
		e.owed = owed
	}
	readOwed()
	var checked []Checked
	failedAt, err := e.check(
		context.Background(),
		list,
		func(c Checked) error {
			checked = append(checked, c)
			return nil
		},
	)
	require.NoError(t, err)

	readOwed()
	var applied []Applied
	_, err = e.apply(
		context.Background(),
		list,
		failedAt,
		func(msg any) error {
			if a, ok := msg.(Applied); ok {
				applied = append(applied, a)
			}
			return nil
		},
	)
	require.NoError(t, err)
	return checked, applied
}

func TestEngine_TriggerIsOwedPastAFailure(t *testing.T) {
	sys := newTestSys(t)
	sys.on("systemctl restart docker", "", 0)
	var log []string
	bad := &fakeResource{id: "bad", applyErr: errors.New("boom"), log: &log}
	daemon := File{Path: "/etc/docker/daemon.json", Content: "{}\n"}
	sys.write(daemon.Path, "{\"debug\": true}\n")
	list := ResourceList{
		daemon,
		bad,
		Command{Name: "restart docker", Watch: []string{daemon.ID()}, ApplyArgv: []string{"systemctl", "restart", "docker"}},
	}

	_, applied := run(t, sys, list)
	assert.Equal(
		t,
		[]string{"file:/etc/docker/daemon.json changed", "bad failed", "command:restart docker skipped"},
		statuses(applied),
	)
	assert.Empty(t, sys.ran)

	bad.applyErr = nil
	checked, applied := run(t, sys, list)
	assert.Equal(t, "run systemctl restart docker, owed from an earlier change\n", checked[2].Diff)
	assert.Equal(t, "command:restart docker changed", statuses(applied)[2])
	assert.Equal(t, []string{"systemctl restart docker"}, sys.ran)

	checked, _ = run(t, sys, list)
	assert.Equal(t, StatusInSync, checked[2].Status, "it's no longer owed once it's applied")
}

func TestEngine_TriggerIsStillOwedWhenItFails(t *testing.T) {
	sys := newTestSys(t)
	sys.on("systemctl enable --now docker", "no docker.service", 1)
	var log []string
	pkg := &fakeResource{id: "package:docker", log: &log}
	list := ResourceList{
		pkg,
		Command{
			Name:      "start docker",
			Watch:     []string{pkg.ID()},
			ApplyArgv: []string{"systemctl", "enable", "--now", "docker"},
		},
	}

	_, applied := run(t, sys, list)
	assert.Equal(t, []string{"package:docker changed", "command:start docker failed"}, statuses(applied))

	sys.on("systemctl enable --now docker", "", 0)
	checked, applied := run(t, sys, list)
	assert.Equal(t, "run systemctl enable --now docker, owed from an earlier change\n", checked[1].Diff)
	assert.Equal(t, []string{"package:docker in-sync", "command:start docker changed"}, statuses(applied))
}

func TestEngine_StackIsRecreatedAfterAFailedRecreate(t *testing.T) {
	sys := newTestSys(t)
	sys.on("docker compose *", "pull access denied", 1)
	compose := File{Path: "/srv/compose/web/docker-compose.yml", Content: "services: {}\n"}
	list := ResourceList{
		Dir{Path: "/srv/compose/web"},
		compose,
		ComposeStack{Dir: "/srv/compose/web", Watch: []string{compose.ID()}},
	}

	_, applied := run(t, sys, list)
	assert.Equal(t, "compose:/srv/compose/web failed", statuses(applied)[2])

	sys.ran = nil
	sys.on("docker compose *", "", 0)
	checked, _ := run(t, sys, list)
	assert.Equal(t, "recreate, owed from an earlier change\n", checked[2].Diff)
	assert.Equal(
		t,
		[]string{"docker compose --file /srv/compose/web/docker-compose.yml up --detach --force-recreate --remove-orphans"},
		sys.ran,
	)
}

func TestEngine_FailedHandlerIsRetried(t *testing.T) {
	sys := newTestSys(t)
	var log []string
	reload := &fakeResource{id: "reload", applyErr: errors.New("boom"), log: &log}
	config := &fakeResource{id: "config", log: &log, notify: ResourceList{reload}}
	list := ResourceList{config, &fakeResource{id: "other", inSync: true, log: &log}}

	_, applied := run(t, sys, list)
	assert.Equal(t, []string{"config changed", "other in-sync", "reload failed"}, statuses(applied))

	reload.applyErr = nil
	checked, applied := run(t, sys, list)
	assert.Equal(t, []string{"config drifted", "other in-sync"}, statuses(checked))
	assert.Equal(t, "changed in an earlier run whose handlers didn't run\n", checked[0].Diff)
	assert.Equal(t, []string{"config in-sync", "other in-sync", "reload changed"}, statuses(applied))

	checked, applied = run(t, sys, list)
	assert.Equal(t, []string{"config in-sync", "other in-sync"}, statuses(checked))
	assert.Equal(t, []string{"config in-sync", "other in-sync"}, statuses(applied))
	assert.Equal(t, []string{"config", "reload", "reload"}, log)
}

func TestEngine_OwedHandlerDoesNotTriggerWatchers(t *testing.T) {
	sys := newTestSys(t)
	var log []string
	reload := &fakeResource{id: "reload", log: &log}
	config := &fakeResource{id: "config", inSync: true, log: &log, notify: ResourceList{reload}}
	require.NoError(t, newOwedJournal().owe(sys, nil, []string{"reload"}))

	checked, _ := run(
		t,
		sys,
		ResourceList{
			config,
			Command{Name: "restart web", Watch: []string{"config"}, ApplyArgv: []string{"systemctl", "restart", "web"}},
		},
	)

	assert.Equal(t, []string{"config drifted", "command:restart web in-sync"}, statuses(checked))
	assert.Equal(t, []string{"reload"}, log)
}

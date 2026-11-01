package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const composeArgs = "docker compose --file /srv/compose/web/docker-compose.yml "

func webConfig(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "web-config.json"))
	require.NoError(t, err)
	return string(b)
}

func TestComposeStack_InSyncWhenEveryServiceRuns(t *testing.T) {
	sys := newTestSys(t)
	sys.on(composeArgs+"config --format json", webConfig(t), 0)
	sys.on(
		"docker ps *",
		"web\tapp\tFalse\trunning\n"+
			"web\tworker\tFalse\trunning\n"+
			"web\tworker\tFalse\trestarting\n"+
			"web\tmanual\tFalse\tpaused\n"+
			"web\tapp\tTrue\texited\n"+
			"other\tgone\tFalse\texited\n"+
			"\t\t\trunning\n",
		0,
	)

	change, err := ComposeStack{Dir: "/srv/compose/web"}.Check(context.Background(), sys)

	require.NoError(t, err)
	assert.True(t, change.InSync, change.Diff)
}

func TestComposeStack_StartsWhatIsDown(t *testing.T) {
	sys := newTestSys(t)
	sys.on(composeArgs+"config --format json", webConfig(t), 0)
	sys.on(
		"docker ps *",
		"web\tapp\tFalse\texited\n"+
			"web\tworker\tFalse\trunning\n"+
			"web\toff\tFalse\texited\n"+
			"web\tremoved\tFalse\trunning\n",
		0,
	)
	sys.on(composeArgs+"up --detach --no-recreate --remove-orphans", "", 0)
	r := ComposeStack{Dir: "/srv/compose/web", Watch: []string{"file:/srv/compose/web/docker-compose.yml"}}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(
		t,
		"start app (0 of 1 running)\n"+
			"start manual (0 of 1 running)\n"+
			"remove off, which has no replicas\n"+
			"start worker (1 of 2 running)\n"+
			"remove removed, which is no longer in the stack\n",
		change.Diff,
	)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Contains(t, sys.ran, composeArgs+"up --detach --no-recreate --remove-orphans")
}

func TestComposeStack_RecreatesWhenFilesChange(t *testing.T) {
	sys := newTestSys(t)
	sys.on(composeArgs+"up --detach --force-recreate --remove-orphans", "", 0)
	st := newRunState()
	st.modified["file:/srv/compose/web/.env"] = true
	ctx := withRunState(context.Background(), st)
	r := ComposeStack{
		Dir:   "/srv/compose/web",
		Watch: []string{"file:/srv/compose/web/docker-compose.yml", "file:/srv/compose/web/.env"},
	}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "recreate, as its files change\n", change.Diff)

	require.NoError(t, r.Apply(ctx, sys))
	assert.Equal(t, []string{composeArgs + "up --detach --force-recreate --remove-orphans"}, sys.ran)
}

func TestComposeStack_ListsContainersOncePerRun(t *testing.T) {
	sys := newTestSys(t)
	sys.on("docker compose *", `{"name": "x", "services": {}}`, 0)
	sys.on("docker ps *", "", 0)
	ctx := withRunState(context.Background(), newRunState())

	for _, dir := range []string{"/srv/compose/a", "/srv/compose/b"} {
		_, err := ComposeStack{Dir: dir}.Check(ctx, sys)
		require.NoError(t, err)
	}

	assert.Equal(
		t,
		[]string{
			"docker compose --file /srv/compose/a/docker-compose.yml config --format json",
			"docker ps --all --format " + containerFormat,
			"docker compose --file /srv/compose/b/docker-compose.yml config --format json",
		},
		sys.ran,
	)
}

func TestComposeProjects_TakesDownUndeclaredStacks(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/srv/compose/keep/docker-compose.yml", "")
	sys.write("/srv/compose/old/docker-compose.yml", "")
	sys.write("/srv/compose/stray", "")
	sys.on("docker compose --project-name old down --remove-orphans", "", 0)
	st := newRunState()
	st.declare(ComposeStack{Dir: "/srv/compose/keep"})
	ctx := withRunState(context.Background(), st)
	r := ComposeProjects{Path: "/srv/compose"}

	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "take down and remove /srv/compose/old\ntake down and remove /srv/compose/stray\n", change.Diff)

	require.NoError(t, r.Apply(ctx, sys))
	assert.Equal(t, []string{"docker compose --project-name old down --remove-orphans"}, sys.ran)
	assert.True(t, sys.exists("/srv/compose/keep"))
	assert.False(t, sys.exists("/srv/compose/old"))
	assert.False(t, sys.exists("/srv/compose/stray"))
}

func TestComposeProjects_FailedDownKeepsFiles(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/srv/compose/old/docker-compose.yml", "")
	sys.on("docker compose *", "", 1)

	err := ComposeProjects{Path: "/srv/compose"}.Apply(context.Background(), sys)

	require.Error(t, err)
	assert.True(t, sys.exists("/srv/compose/old/docker-compose.yml"))
}

func TestComposeProjects_NothingToDoWithoutStacksDir(t *testing.T) {
	change, err := ComposeProjects{Path: "/srv/compose"}.Check(context.Background(), newTestSys(t))

	require.NoError(t, err)
	assert.True(t, change.InSync)
}

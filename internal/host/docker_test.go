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
	return readTestdata(t, "web-config.json")
}

func TestComposeStack_InSyncWhenEveryServiceRuns(t *testing.T) {
	sys := newTestSys(t)
	sys.on(composeArgs+"config --format json", webConfig(t), 0)
	sys.on(
		"docker ps *",
		"web\tapp\tFalse\trunning\tUp 2 hours\n"+
			"web\tworker\tFalse\trunning\tUp 2 hours\n"+
			"web\tworker\tFalse\trestarting\tRestarting (1) 2 seconds ago\n"+
			"web\tmanual\tFalse\tpaused\tUp 2 hours (Paused)\n"+
			"web\tmigrate\tFalse\texited\tExited (0) 2 hours ago\n"+
			"web\tapp\tTrue\texited\tExited (1) 2 hours ago\n"+
			"other\tgone\tFalse\texited\tExited (0) 2 hours ago\n"+
			"\t\t\trunning\tUp 2 hours\n",
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
		"web\tapp\tFalse\texited\tExited (0) 2 hours ago\n"+
			"web\tworker\tFalse\trunning\tUp 2 hours\n"+
			"web\toff\tFalse\texited\tExited (0) 2 hours ago\n"+
			"web\tmigrate\tFalse\texited\tExited (1) 2 hours ago\n"+
			"web\tremoved\tFalse\trunning\tUp 2 hours\n",
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
			"start migrate (0 of 1 running)\n"+
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

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(b)
}

const networkLs = "docker network ls --filter "

func TestDockerNetwork_Creates(t *testing.T) {
	sys := newTestSys(t)
	sys.on(networkLs+"name=^six$ --format {{.Name}}", "sixth\n", 0)
	sys.on("docker network create *", "", 0)
	r := DockerNetwork{Name: "six", Subnets: []string{"fd00:dead:beef::/48"}, IPv6: true}

	change, err := r.Check(context.Background(), sys)
	require.NoError(t, err)
	assert.Equal(t, "create network\n", change.Diff)

	require.NoError(t, r.Apply(context.Background(), sys))
	assert.Equal(
		t,
		"docker network create --label sensible.managed=true --ipv6 --subnet fd00:dead:beef::/48 six",
		sys.ran[len(sys.ran)-1],
	)
}

func TestDockerNetwork_ComparesDeclaredFamilies(t *testing.T) {
	tests := []struct {
		name    string
		network DockerNetwork
		warning string
	}{
		{"matching IPv6 subnet", DockerNetwork{Subnets: []string{"fd00:dead:beef::/48"}, IPv6: true}, ""},
		{"no subnets declared", DockerNetwork{IPv6: true}, ""},
		{
			"different IPv4 subnet",
			DockerNetwork{Subnets: []string{"fd00:dead:beef::/48", "10.0.0.0/8"}, IPv6: true},
			"subnets are 172.18.0.0/16 rather than 10.0.0.0/8\n",
		},
		{
			"IPv6 off",
			DockerNetwork{Subnets: []string{"10.0.0.0/8"}},
			"IPv6 is on rather than off\nsubnets are 172.18.0.0/16 rather than 10.0.0.0/8\n",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				sys := newTestSys(t)
				sys.on(networkLs+"name=^six$ --format {{.Name}}", "six\n", 0)
				sys.on("docker network inspect six", readTestdata(t, "network-six.json"), 0)
				tt.network.Name = "six"

				change, err := tt.network.Check(context.Background(), sys)

				require.NoError(t, err)
				assert.True(t, change.InSync)
				if tt.warning == "" {
					assert.Empty(t, change.Warning)
				} else {
					assert.Equal(t, tt.warning+"remove the network by hand for it to be recreated\n", change.Warning)
				}
			},
		)
	}
}

func TestDockerNetwork_NotYetCheckableWithoutDocker(t *testing.T) {
	_, err := DockerNetwork{Name: "web"}.Check(context.Background(), newTestSys(t))

	assert.ErrorIs(t, err, ErrNotYetCheckable)
}

func TestDockerNetworks_RemovesUndeclared(t *testing.T) {
	sys := newTestSys(t)
	sys.on(networkLs+"label=sensible.managed=true --format {{.Name}}", "web\nold\n", 0)
	sys.on("docker network rm old", "", 0)
	st := newRunState()
	st.declare(DockerNetwork{Name: "web"})
	ctx := withRunState(context.Background(), st)

	change, err := DockerNetworks{}.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "remove network old\n", change.Diff)

	require.NoError(t, DockerNetworks{}.Apply(ctx, sys))
	assert.Equal(t, "docker network rm old", sys.ran[len(sys.ran)-1])
}

func TestDockerNetworks_NothingWithoutDocker(t *testing.T) {
	change, err := DockerNetworks{}.Check(context.Background(), newTestSys(t))

	require.NoError(t, err)
	assert.True(t, change.InSync)
}

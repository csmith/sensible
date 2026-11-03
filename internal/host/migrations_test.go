package host

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMigration(phase, on string) Migration {
	return Migration{
		Stack:  "/srv/compose/web",
		Name:   "major",
		Phase:  phase,
		On:     on,
		Before: []string{"dump"},
		After:  []string{"restore"},
	}
}

// migrate checks and applies both phases of a migration, as an apply
// would, returning each phase's diff or error.
func migrate(t *testing.T, sys Sys, on string) (before, after string, err error) {
	t.Helper()
	ctx := withRunState(context.Background(), newRunState())
	for i, phase := range []string{PhaseBefore, PhaseAfter} {
		r := testMigration(phase, on)
		change, cerr := r.Check(ctx, sys)
		require.NoError(t, cerr)
		if !change.InSync {
			if err = r.Apply(ctx, sys); err != nil {
				return before, after, err
			}
		}
		if i == 0 {
			before = change.Diff
		} else {
			after = change.Diff
		}
	}
	return before, after, nil
}

func TestMigration_FirstSeenRecordsWithoutRunning(t *testing.T) {
	sys := newTestSys(t)

	before, after, err := migrate(t, sys, "database-16")
	require.NoError(t, err)
	assert.Equal(t, "record database-16\n", before)
	assert.Empty(t, after)
	assert.Empty(t, sys.ran)

	before, after, err = migrate(t, sys, "database-16")
	require.NoError(t, err)
	assert.Empty(t, before+after)
}

func TestMigration_RunsAroundAChange(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/srv/compose/web/.env", "DB_PASSWORD='pw'\nUSER='app'\n")
	var cmds []Cmd
	for _, name := range []string{"dump", "restore"} {
		sys.commands[name] = func(c Cmd) Result {
			cmds = append(cmds, c)
			assert.True(t, sys.exists(c.Env["MIGRATION_DIR"]), "%s's MIGRATION_DIR exists", name)
			return Result{}
		}
	}
	_, _, err := migrate(t, sys, "database-16")
	require.NoError(t, err)

	ctx := withRunState(context.Background(), newRunState())
	change, err := testMigration(PhaseBefore, "database-17").Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "migrate database-16 → database-17\n", change.Diff)
	change, err = testMigration(PhaseAfter, "database-17").Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "finish migrating database-16 → database-17\n", change.Diff, "the plan shows both phases")

	_, _, err = migrate(t, sys, "database-17")
	require.NoError(t, err)
	assert.Equal(t, []string{"dump", "restore"}, sys.ran)
	require.Len(t, cmds, 2)
	work := "/var/lib/sensible/migrations/web/major/work"
	for _, c := range cmds {
		assert.Equal(t, "/srv/compose/web", c.Dir)
		assert.Equal(t, map[string]string{"DB_PASSWORD": "pw", "USER": "app", "MIGRATION_DIR": work}, c.Env)
	}
	assert.False(t, sys.exists(work), "MIGRATION_DIR is removed once after succeeds")

	before, after, err := migrate(t, sys, "database-17")
	require.NoError(t, err)
	assert.Empty(t, before+after)
}

func TestMigration_FailedAfterIsRetriedAlone(t *testing.T) {
	sys := newTestSys(t)
	_, _, err := migrate(t, sys, "a")
	require.NoError(t, err)
	sys.on("dump", "", 0)
	sys.on("restore", "not ready", 1)

	_, _, err = migrate(t, sys, "b")
	require.ErrorContains(t, err, "migration major: after: restore exited with status 1: not ready")
	assert.True(t, sys.exists("/var/lib/sensible/migrations/web/major/work"), "the dump is kept")

	sys.ran = nil
	sys.on("restore", "", 0)
	before, after, err := migrate(t, sys, "b")
	require.NoError(t, err)
	assert.Empty(t, before)
	assert.Equal(t, "finish migrating a → b\n", after)
	assert.Equal(t, []string{"restore"}, sys.ran)
}

func TestMigration_FailedBeforeIsRetried(t *testing.T) {
	sys := newTestSys(t)
	_, _, err := migrate(t, sys, "a")
	require.NoError(t, err)
	sys.on("dump", "disk full", 1)

	_, _, err = migrate(t, sys, "b")
	require.ErrorContains(t, err, "migration major: before: dump exited with status 1")

	sys.ran = nil
	sys.on("dump", "", 0)
	sys.on("restore", "", 0)
	before, _, err := migrate(t, sys, "b")
	require.NoError(t, err)
	assert.Equal(t, "migrate a → b\n", before)
	assert.Equal(t, []string{"dump", "restore"}, sys.ran)
}

func TestMigration_SecretIsntShownOrKept(t *testing.T) {
	sys := newTestSys(t)
	r := testMigration(PhaseBefore, "hunter2")
	r.Secret = true

	change := checkApply(t, sys, r)
	assert.Equal(t, "record (secret)\n", change.Diff)
	assert.NotContains(t, sys.read("/var/lib/sensible/migrations/web/major/record.json"), "hunter2")
}

func TestMigrations_ForgetsUndeclared(t *testing.T) {
	sys := newTestSys(t)
	for _, path := range []string{"web/major", "web/gone", "old/major"} {
		sys.write("/var/lib/sensible/migrations/"+path+"/record.json", "{}\n")
	}
	st := newRunState()
	st.declare(testMigration(PhaseBefore, "x"))
	ctx := withRunState(context.Background(), st)

	change, err := Migrations{}.Check(ctx, sys)
	require.NoError(t, err)
	assert.Equal(t, "forget migration old\nforget migration web/gone\n", change.Diff)

	require.NoError(t, Migrations{}.Apply(ctx, sys))
	assert.True(t, sys.exists("/var/lib/sensible/migrations/web/major/record.json"))
	assert.False(t, sys.exists("/var/lib/sensible/migrations/web/gone"))
	assert.False(t, sys.exists("/var/lib/sensible/migrations/old"))
}

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

func backupHost() Host {
	h := testHost(archLinux)
	h.Config.Restic = &config.ResticConfig{
		Options:  map[string]string{"rclone.args": "serve restic --stdio"},
		Keep:     map[string]int{"weekly": 10, "daily": 7},
		Schedule: "*-*-* 03:30",
		Env:      map[string]string{"RESTIC_REPOSITORY": "rclone:b2:backups", "RESTIC_PASSWORD": "it's secret"},
		Secrets:  []string{"it's secret"},
	}
	h.Config.Backups = map[string]config.BackupConfig{
		"web-data": {Path: "/srv/volumes/web/data"},
		"web-db":   {Command: config.Command{"docker", "compose", "exec", "-T", "db", "pg_dumpall", "-U", "postgres"}},
	}
	return h
}

func TestResources_backups(t *testing.T) {
	rs, err := Resources(backupHost())
	require.NoError(t, err)

	env, ok := find[host.File](rs, "file:"+resticEnvFile)
	require.True(t, ok)
	assert.Equal(
		t,
		managedHeader+"RESTIC_CACHE_DIR=/var/cache/restic\n"+
			"RESTIC_PASSWORD='it'\"'\"'s secret'\n"+
			"RESTIC_REPOSITORY=rclone:b2:backups\n",
		env.Content,
	)
	assert.Equal(t, 0o600, int(env.Mode))
	assert.Equal(t, []string{"it's secret"}, env.Secrets)

	wrapper, ok := find[host.File](rs, "file:"+resticWrapper)
	require.True(t, ok)
	assert.Contains(t, wrapper.Content, "\n. "+resticEnvFile+"\n")
	assert.Contains(t, wrapper.Content, "\nexec restic -o 'rclone.args=serve restic --stdio' \"$@\"\n")

	script, ok := find[host.File](rs, "file:"+backupScript)
	require.True(t, ok)
	assert.Equal(
		t,
		"#!/bin/sh\n"+managedHeader+"status=0\n"+
			"echo 'Backing up web-data'\n"+
			"/usr/local/sbin/sensible-restic backup --host testhost --tag web-data -- /srv/volumes/web/data || status=1\n"+
			"echo 'Backing up web-db'\n"+
			"/usr/local/sbin/sensible-restic backup --host testhost --tag web-db --stdin-filename web-db --stdin-from-command"+
			" -- docker compose exec -T db pg_dumpall -U postgres || status=1\n"+
			"echo 'Forgetting old snapshots'\n"+
			"/usr/local/sbin/sensible-restic forget --host testhost --keep-daily 7 --keep-weekly 10 || status=1\n"+
			"if [ \"$(date +%u)\" = 7 ]; then\n"+
			"\techo 'Pruning the repository'\n"+
			"\t/usr/local/sbin/sensible-restic prune || status=1\n"+
			"fi\n"+
			"exit \"$status\"\n",
		script.Content,
	)

	timer, ok := find[host.File](rs, "file:/etc/systemd/system/sensible-backup.timer")
	require.True(t, ok)
	assert.Contains(t, timer.Content, "\nOnCalendar=*-*-* 03:30\n")
	service, ok := find[host.File](rs, "file:/etc/systemd/system/sensible-backup.service")
	require.True(t, ok)
	assert.Contains(t, service.Content, "\nExecStart=\""+backupScript+"\"\n")

	got := ids(rs)
	assert.Less(t, indexAfter(got, "file:"+backupScript, -1), indexAfter(got, "service:sensible-backup.timer", -1))
}

func TestResources_noBackups(t *testing.T) {
	rs, err := Resources(testHost(archLinux))
	require.NoError(t, err)

	for _, path := range []string{resticEnvFile, resticWrapper, backupScript} {
		_, ok := find[host.Absent](rs, "absent:"+path)
		assert.True(t, ok, path)
	}
	assert.NotContains(t, ids(rs), "service:sensible-backup.timer")
}

func TestResources_backupErrors(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Host)
		want   string
	}{
		{"backups without restic", func(h *Host) { h.Config.Restic = nil }, "no restic settings"},
		{
			"path and command",
			func(h *Host) {
				h.Config.Backups["x"] = config.BackupConfig{Path: "/x", Command: config.Command{"true"}}
			},
			"exactly one of path and command",
		},
		{"neither", func(h *Host) { h.Config.Backups["x"] = config.BackupConfig{} }, "exactly one of path and command"},
		{"relative path", func(h *Host) { h.Config.Backups["x"] = config.BackupConfig{Path: "x"} }, "isn't absolute"},
		{
			"invalid name",
			func(h *Host) { h.Config.Backups["X y"] = config.BackupConfig{Path: "/x"} },
			"invalid backup name",
		},
		{"no keep", func(h *Host) { h.Config.Restic.Keep = nil }, "never forgotten"},
		{
			"unknown keep",
			func(h *Host) { h.Config.Restic.Keep["fortnightly"] = 1 },
			`unknown restic.keep "fortnightly"`,
		},
		{"zero keep", func(h *Host) { h.Config.Restic.Keep["daily"] = 0 }, "must be at least 1"},
		{
			"invalid env name",
			func(h *Host) { h.Config.Restic.Env["A-B"] = "x" },
			`invalid restic.environment name "A-B"`,
		},
		{
			"job named backup",
			func(h *Host) {
				h.Config.Jobs["backup"] = config.JobConfig{Command: config.Command{"true"}, Schedule: "daily"}
			},
			"backup job's name",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				h := backupHost()
				tt.modify(&h)
				_, err := Resources(h)
				assert.ErrorContains(t, err, tt.want)
			},
		)
	}
}

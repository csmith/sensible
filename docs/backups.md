# Backups

`backups` names what to back up with [restic](https://restic.net), and
`restic` says where to. A host with `backups` needs `restic`.

```yaml
# roles/base/role.yml
restic:
  repository: rclone:b2:example-backups
  password: !age ...
  environment:
    RCLONE_CONFIG_B2_TYPE: b2
    RCLONE_CONFIG_B2_ACCOUNT: !age ...
    RCLONE_CONFIG_B2_KEY: !age ...
  options:
    rclone.connections: "8"
  keep:
    daily: 7
    weekly: 4
    monthly: 6
  schedule: "*-*-* 02:00"
```

```yaml
# roles/app/role.yml
backups:
  app-data:
    path: !volume data
  app-db:
    command: [docker, compose, -p, app, exec, -T, db, pg_dumpall, --clean, -U, app]
```

Each backup is a `path`, backed up as it is, or a `command`, whose output is
backed up as a file named after the backup. A command that fails leaves no
snapshot behind. Commands need restic 0.17 or later on the host. Names are
lower case letters, digits, `-` and `_`.

`repository` and `password` are restic's. `environment` is added to restic's,
such as credentials for the repository, and `options` are its `-o` options.
`keep` gives the counts for `forget`'s `--keep-*` flags, such as `daily` and
`last`, and needs at least one, or nothing would ever be forgotten.
`schedule` is a systemd calendar expression, and defaults to `daily`.

restic and rclone are installed, and the backup runs as the `backup`
[job](system.md#jobs). It backs up each entry
in turn, continuing past failures, tags each snapshot with the backup's name
and the host, forgets old snapshots by the `keep` counts, and prunes the
repository on Sundays. restic's cache is kept in `/var/cache/restic`, unless
`environment` sets `RESTIC_CACHE_DIR`.

The host gets `/usr/local/sbin/sensible-restic`, which runs restic with the
host's repository and settings, for restoring and inspecting snapshots by
hand:

```sh
sudo sensible-restic snapshots
sudo sensible-restic restore latest --tag app-data --target /tmp/restore
```

The credentials are in `/etc/sensible/restic.env`, readable only by root. A
host that stops backing up has them removed.

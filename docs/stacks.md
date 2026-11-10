# Compose stacks

A role with a `docker-compose.yml`, in the role or one of its
[partials](partials.md), is a stack: a Docker Compose project deployed to
`/srv/compose/<stack>` on each host that has the role. The stack's name is the
role's, with `/` replaced by `-` for child roles, and it's also the project's
name, so the compose file's `name` must match or be left out. The host needs
the [`docker`](software.md#docker) module.

```text
roles/app/
  role.yml             Volumes, extra files, environment and the usual settings
  docker-compose.yml   The compose file
  app.conf             Copied alongside it, if listed in compose.files
```

A stack is brought up with `docker compose up` and is in sync when every
service has its containers running. Whenever one of its files changes, the
whole stack is recreated. Stacks nothing declares any more are taken down and
their directories removed; their volumes are kept, and warned about for prune.

## Tags in the compose file

The compose file is written to the host with its comments kept and these tags
replaced:

- `!param name` is a role parameter's value.
- `!age` and `!generated name` are secrets. See [Secrets](secrets.md).
- `!volume name` is the path of one of the role's volumes, below.
- `!cert name/tls.crt` is the path of a certificate's file. See
  [Certificates](certificates.md).
- `!vhost example.com` is a domain name the host serves. See [DNS](dns.md).

`{host}` and `{stack}` work too, as in the rest of the role.

```yaml
# roles/app/docker-compose.yml
services:
  app:
    image: ghcr.io/example/app:1.2
    environment:
      APP_HOST: !vhost app.example.com
      DB_PASSWORD: !generated db_password
      WORKERS: !param workers
    volumes:
      - !volume data:/data
      - !cert app/tls.crt:/tls/cert.pem:ro
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: !generated db_password
    volumes:
      - !volume database:/var/lib/postgresql/data
```

## Volumes

`compose.volumes` declares directories for the stack's data, made at
`/srv/volumes/<stack>/<name>`, each with an optional `owner`, `group` and
`mode`. sensible manages the directory but never what's in it. A compose file
mounts one with `!volume name`, followed by the rest of the mount, and a child
role mounts its parent's with `!volume ../name`.

```yaml
# roles/app/role.yml
compose:
  volumes:
    data:
    database: {owner: 999, group: 999, mode: 0700}
```

Bind mounts of anything else under `/srv/compose`, such as `./data`, are
rejected, as sensible removes what it doesn't put there. Volume directories
nothing declares any more are warned about, and prune offers to remove them.

## Files and environment

`compose.files` lists files and directories in the role to copy into the
stack's directory, for the compose file to mount. Each is a path, or a
mapping with `path`, `owner`, `group` and `mode`; files default to root:docker
0640. A file ending in `.age` is decrypted and written without the suffix.

`compose.env` is written as the stack's `.env`, so the compose file can use
its variables. Values can be plain or secrets, and can hold the tags above.
Partials can set `compose.env` too, and the role can only change what they set
with `!replace`.

```yaml
# roles/app/role.yml
compose:
  files:
    - app.conf
    - {path: certs, owner: app, mode: 0600}
  env:
    APP_VERSION: "1.2"
    SMTP_PASSWORD: !age ...
```

## Migrations

`migrations` run commands around a stack's recreate when a value changes,
such as a database's major version or a password. Each has `on`, the value to
watch, and `before`, `after` or both. The first time a host sees a migration
it only records the value, as there's nothing to migrate from, so a migration
has to be deployed before the change it handles.

```yaml
# roles/app/role.yml
migrations:
  postgres-major:
    on: "17"
    before: [sh, -c, "docker compose exec -T db pg_dumpall -U app > $MIGRATION_DIR/dump.sql"]
    after: [sh, -c, "docker compose exec -T db psql -U app < $MIGRATION_DIR/dump.sql"]
```

`before` runs ahead of the stack's files being changed, so a failure leaves
the stack as it was, and the stack is then recreated. `after` runs once it's
up, and is retried on its own if it fails. Both run in the stack's directory
with the variables from its `.env`, and `$MIGRATION_DIR` is a directory kept
from the start of `before` until `after` succeeds. `on` can be an `!age` or
`!generated` secret, which is then hidden from plans and records, but the
commands can't hold secrets; they read them from `compose.env`'s variables
instead. Names are letters, digits, `-`, `_` and `.`.

Migrations can come from partials as well, and the records of migrations
nothing declares any more are forgotten.

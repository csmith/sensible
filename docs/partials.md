# Partials

A partial is a piece of configuration several roles share: a database
service and its backup, say, or a proxy in front of whatever the role runs.
It lives in `partials/<name>/`, and roles include it with arguments.

```text
partials/<name>/partial.yml          Settings, with the partial's parameters
partials/<name>/docker-compose.yml   A compose fragment (optional)
partials/<name>/files/               Sources for the partial's files (optional)
```

## Writing a partial

`partial.yml` declares parameters under `params`, with defaults, and uses them
as `{placeholders}` anywhere in the partial's files, keys included. `~` is a
parameter without a default. `{host}` and `{stack}` are always available, and
`{{` and `}}` stand for single braces.

```yaml
# partials/postgres/partial.yml
params:
  service: postgres
  volume: database
  image: postgres:17
  user: ~
  password: ~

compose:
  volumes:
    "{volume}": {owner: 999, group: 999, mode: 0700}

backups:
  "{stack}-postgres":
    command: [docker, compose, -p, "{stack}", exec, -T, "{service}", pg_dumpall, --clean, -U, "{user}"]
```

```yaml
# partials/postgres/docker-compose.yml
services:
  "{service}":
    image: "{image}"
    restart: always
    environment:
      POSTGRES_USER: "{user}"
      POSTGRES_PASSWORD: "{password}"
    volumes:
      - !volume "{volume}:/var/lib/postgresql/data"
```

A value that's exactly a placeholder takes the argument as it is, whatever
its type, and a placeholder whose argument is null drops the key or list item
it's in. Within a longer string, the argument must be a string, number or
bool.

A partial's settings are the same as a role's, with a few limits: it can set
`compose.volumes` and `compose.env` but not `compose.files` or `children`, it
takes values from placeholders rather than `!param`, and a `!vhost` in it
can't hold a placeholder. Pass the `!vhost` as an argument instead.

## Including a partial

A role lists the partials it includes, with their arguments, under
`partials`. Arguments can be plain values, `!param` values, or tags such as
`!generated`, `!volume` and `!vhost`, and can use `{host}` and `{stack}`.

```yaml
# roles/web/role.yml
params:
  db_user: web

partials:
  - partial: postgres
    service: db
    user: !param db_user
    password: !generated db_password
  - {partial: tailscale-proxy, hostname: !vhost app.example.com, upstream: "http://app:8080"}
```

A role that includes a partial with a compose fragment becomes a stack, even
without a `docker-compose.yml` of its own. The role's compose file is merged
over its partials', so it can add to a service a partial defines:

```yaml
# roles/web/docker-compose.yml
services:
  app:
    image: app
  db:
    restart: !replace unless-stopped
    tmpfs: [/tmp]
```

Partials sit beneath the role: `role.yml` and the role's compose file can only
change what a partial set by tagging the value `!replace`, and setting it
differently without that is an error. Comments in both are kept in the
rendered compose file.

## Partials in partials

A partial can include others, passing its own placeholders on as arguments.
Partials that include each other are rejected.

```yaml
# partials/postgres/partial.yml
params:
  service: db
  password: ~
partials:
  - {partial: password-migration, service: "{service}", password: "{password}"}
```

The arguments to a partial's `compose.volumes` must be the same on every
host, so they can't come from role parameters or use `{host}`.

# Configuration

sensible reads a directory of YAML. A host picks roles, roles say what to
configure, and the roles a host has are merged into one configuration for it.

## Layout

```text
sensible.yml              Settings: secret recipients, DNS, OIDC and CAs
hosts.d/*.yml             Hosts and the roles they have
hosts.d/<host>.state.yml  Written by sensible: credentials, host keys and other state
ca.state.yml              Written by sensible: the certificate authorities
dns.state.yml             Written by sensible: the DNS names it manages
roles/<name>/role.yml     What a role configures
roles/<name>/role.debian.yml, role.arch.yml
                          Additions for one OS (optional)
roles/<name>/docker-compose.yml
                          Makes the role a Compose stack (optional)
roles/<name>/files/       Sources for the role's files (optional)
roles/<name>/<child>/     Child roles (optional)
partials/<name>/          Pieces of configuration shared between roles
```

Files and directories starting with `.` are ignored. Anything else that
sensible doesn't expect, such as a stray file in `roles/`, is an error, so
typos in file names are caught.

## sensible.yml

Everything in `sensible.yml` is optional. It holds the settings that aren't
about one host: `secrets` ([Secrets](secrets.md)), `dns` ([DNS](dns.md)),
`oidc` ([OIDC](oidc.md)) and `cas` ([Certificates](certificates.md)).

## Hosts

Every `.yml` file in `hosts.d` is merged into one inventory. A host can be
spread across files, but no two files may set the same value differently, so
the order they're read in never matters.

```yaml
# hosts.d/web1.yml
web1:
  address: web1.example.com:2222
  dns_name: web1.example.com
  host_keys:
    - ssh-ed25519 AAAA...
  roles:
    base:
    zsh:
      prompt_colours:
        chris: yellow
```

- `address` is where to reach the host, optionally with a port. The machine
  sensible runs on is reached over loopback instead, so it can leave this out.
- `dns_name` gets the host A and AAAA records. See [DNS](dns.md).
- `host_keys` are the host's SSH public keys, which connections must match.
  Bootstrap saves the key it accepts, so this is only written by hand to pin
  a key in advance.
- `roles` are the host's roles, each with the parameters the host sets.

Bootstrap writes the host's credentials to `hosts.d/<host>.state.yml`, and
later runs add other state to it: generated secrets, issued certificates,
ignored leftovers, and the OIDC clients sensible manages for the host. It's
rewritten whole, so comments in it aren't kept, and it has the same shape as
a hand-written host file.

## Roles

A role's `role.yml` holds the settings it configures, grouped by module.
Each module is documented on its own page:

- [Accounts and access](accounts.md): `users`, `sudoers`, `sshd`, `pam_rssh`
  and `zsh`
- [Software](software.md): `packages`, `apt_repos`, `pacman_repos`, `aur`,
  `docker` and `tailscale`
- [System](system.md): `hostname`, `timezone`, `locale`, `ntp`, `quiet_login`,
  `vim`, `services`, `jobs`, `firewall` and `remove`
- [Files](files.md): `files`, `directories` and `leftovers`
- [Compose stacks](stacks.md): the role's `docker-compose.yml`, `compose` and
  `migrations`
- [Backups](backups.md): `backups` and `restic`
- [Certificates](certificates.md): `certs`
- [OIDC](oidc.md): `oidc_clients` and `oidc_apis`

A module named without settings is still turned on:

```yaml
# roles/editor/role.yml
vim:
```

### Parameters

A role declares its parameters, with defaults, under `params`, and uses them
with `!param`. A host sets them under the role in `hosts.d`:

```yaml
# roles/zsh/role.yml
params:
  users: [chris, root]
  prompt_colours:
    chris: white
    root: red

zsh:
  users: !param users
  editor: nvim
  prompt_colours: !param prompt_colours
```

```yaml
# hosts.d/web1.yml
web1:
  roles:
    zsh:
      prompt_colours:
        chris: yellow
```

A mapping the host sets is merged over the default, so `root` keeps its
colour above. A list the host sets replaces the default. Setting a parameter
the role doesn't declare is an error, and a `!param` whose value is null drops
the key or list item it's in.

### OS variants

`role.debian.yml` and `role.arch.yml` are merged over `role.yml` on hosts of
that family, which covers Ubuntu under `debian`. They're for the parts that
differ, such as package names:

```yaml
# roles/zsh/role.arch.yml
aur:
  packages: [autojump-rs-bin]
```

```yaml
# roles/zsh/role.debian.yml
packages:
  install: [autojump]
```

### Children

A role can group others, which live in directories inside it and are listed
under `children`. A host with the parent gets every child, without
parameters, and can't list a child it already has through its parent. Roles
nest one level deep.

```yaml
# roles/media/role.yml
children: [jellyfin, sonarr]
```

A child is named `parent/child`, so its stack is `parent-child`, and it can
mount the parent's volumes. See [Compose stacks](stacks.md).

### Placeholders

A role's own files can use `{host}`, the host's name in `hosts.d`, and
`{stack}`, the role's stack name, e.g. `TASK_QUEUE: queue-{host}`. Write
`{{host}}` for the text itself. Quote a value that's only a placeholder, or
YAML reads it as a mapping.

### Sources

A role's `files/` directory holds the sources of its `files` entries and the
logos of its OIDC clients. A partial's `files/` does the same for the
partial's.

## Partials

Settings and compose fragments that several roles share go in `partials/`,
which roles include with arguments. See [Partials](partials.md).

## Merging

A host's roles are merged in name order, but the order never matters: two
roles setting the same value differently is an error, which names both.
Mappings merge key by key, and lists concatenate, with duplicates dropped
where they'd be meaningless. The exceptions are commands, such as a job's,
which are single values. The same goes for a role over its partials, and for
the files in `hosts.d`.

To replace a value rather than merge with it, tag it `!replace`:

```yaml
# roles/web/role.yml
partials:
  - {partial: postgres}

compose:
  env:
    POSTGRES_ARGS: !replace "-c shared_buffers=1GB"
```

An OS variant isn't checked against `role.yml`: it's merged over it, so a
value it sets wins.

## Tags

sensible adds a few YAML tags. Each is described where it's used:

| Tag          | Use                                                                 |
|--------------|---------------------------------------------------------------------|
| `!param`     | A role parameter's value                                            |
| `!replace`   | Replace what's beneath instead of merging                           |
| `!age`       | An encrypted secret ([Secrets](secrets.md))                         |
| `!generated` | A random value made once per host ([Secrets](secrets.md))           |
| `!volume`    | The path of a volume ([Compose stacks](stacks.md))                  |
| `!cert`      | The path of a certificate's file ([Certificates](certificates.md))  |
| `!vhost`     | Domain names that a host serves ([DNS](dns.md))                     |

`!generated` and `!cert` only work in a stack's compose file, its
`compose.env`, a migration's `on` and an OIDC client's `secret`, where
they're resolved. Anywhere else they'd be read as text.

# sensible

sensible configures Linux hosts from a directory of YAML: packages, users,
system settings, Docker Compose stacks, backups, certificates and so on. It
connects over SSH, runs a small agent on each host, shows you what would change,
and applies it once you confirm. Debian, Ubuntu and Arch hosts are supported.

## Installing

Building needs Go. The build embeds agent binaries for amd64 and arm64.

```sh
make
sudo make install
```

## Configuring

sensible reads its configuration from the working directory, or from `--config`
or `SENSIBLE_CONFIG`.

```text
sensible.yml              Settings such as secret recipients and DNS
hosts.d/*.yml             Hosts and the roles they have
roles/<name>/role.yml     What a role configures
roles/<name>/role.debian.yml, role.arch.yml
                          Additions for one OS (optional)
roles/<name>/docker-compose.yml
                          Makes the role a Compose stack (optional)
roles/<name>/files/       Sources for the role's files (optional)
partials/<name>/          Pieces of configuration shared between roles
```

A host picks its roles, and can set their parameters:

```yaml
# hosts.d/web1.yml
web1:
  address: web1.example.com
  roles:
    base:
    zsh:
      prompt_colours:
        chris: yellow
```

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

A role's files can use `{host}`, the host's name in `hosts.d`, and `{stack}`,
the role's stack name, e.g. `TASK_QUEUE: queue-{host}`. Write `{{host}}` for
the text itself.

### Files

`files` writes files as given. Each has an absolute `path`, and either
`content` or a `source` in the `files` directory of the role or partial that
declares it, which may be binary. A source ending in `.age` is an age file from
`sensible secret encrypt --raw`, and is decrypted. `content` can be an `!age`
value. `owner`, `group` and `mode` default to root, root and 0644, or 0640 when
the file is encrypted, and missing parent directories are created as root:root
0755. Two roles can't write the same path.

```yaml
# roles/zram/role.yml
packages:
  install: [zram-generator]

files:
  - path: /etc/systemd/zram-generator.conf
    content: |
      [zram0]
  - path: /usr/local/bin/tool
    source: tool
    mode: 0755
```

Once nothing declares a file, prune offers to remove it, unless it's been
changed since it was written.

### Services

`services` sets systemd units' states. `enabled` enables and starts a unit,
`disabled` disables and stops it, and `masked` stops and masks it, even if
it isn't installed yet. Stopping a unit also stops the units, such as sockets,
that would start it again. Two roles can't give a unit different states.
Removing a unit from `services` leaves it as it is.

```yaml
# roles/pi/role.yml
services:
  bluetooth.service: enabled
  fwupd-refresh.timer: enabled
  smartd.service: masked
```

### Leftovers

Apply warns about what sensible finds but didn't put there, such as files in
directories it manages or packages installed by hand, and prune offers to
remove them. `leftovers` acknowledges those expected on many hosts. What's
under `ignore` is never warned about or pruned. What's under `external` is
managed some other way: it's never pruned, but apply warns if it's missing.
Paths are absolute, and paths and package names can be globs.

```yaml
# roles/base/role.yml
leftovers:
  ignore:
    paths: [/etc/sudoers.d/README]
  external:
    paths: [/usr/local/bin/tool]
    packages: [tool-git]
```

### DNS

A host with a `dns_name` gets A and AAAA records for its addresses. With
`dns.vhosts`, each vhost gets those records for every host serving it, with
`{host}` replaced by the host's `dns_name`. The provider must be set, with its
settings under its name. MyDNSHost is supported.

```yaml
# sensible.yml
dns:
  provider: mydnshost
  mydnshost:
    auth_user: !age ...   # From `sensible secret encrypt`
    auth_key: !age ...
  vhosts:
    - type: CNAME
      content: "{host}"
```

### OIDC clients

`oidc_clients` sets up clients, by client ID, in the OIDC provider. Each needs
`callback_urls`. A confidential client's `secret` is a `!generated` value of
the role's stack, which the stack can use too, and it's the only secret the
client keeps. Public clients have no secret, and always use PKCE. `name`
defaults to the client ID, and without `groups` any user can sign in. The
provider must be set, with its settings under its name. Pocket ID is
supported, with an admin's API key.

```yaml
# sensible.yml
oidc:
  provider: pocketid
  pocketid:
    url: https://id.example.com
    api_key: !age ...   # From `sensible secret encrypt`
```

```yaml
# roles/grafana/role.yml
oidc_clients:
  grafana:
    name: Grafana
    callback_urls: [https://grafana.example.com/login/generic_oauth]
    logout_callback_urls: [https://grafana.example.com/login]
    pkce: true
    groups: [admins]
    secret: !generated oidc_secret

compose:
  env:
    OIDC_CLIENT_SECRET: !generated oidc_secret
```

A client that's already there is taken over. Once nothing declares a client,
prune offers to delete it. To move a client to another host, apply
both hosts together.

## Using

```sh
sensible bootstrap web1 --user root   # Set up a new host for management
sensible apply web1                   # Show the changes for a host and apply them
sensible apply                        # The same, for all hosts
sensible apply web1 --update-packages # Update all its packages first
sensible prune web1                   # Offer to remove what a host has left over
sensible render web1                  # Show everything a host should have
```

The machine sensible runs on is managed like any other host, over SSH to
loopback. Bootstrap it without `--user`: it only needs sudo, and installs sshd
if it's missing.

`--update-packages` runs `pacman -Syu` or `apt-get full-upgrade` before
anything else, which fixes installs failing with a 404 from a stale package
index. It never reboots, but says when a host needs to.

Prune asks about each leftover. Answering `i` keeps it and stops apply and
prune mentioning it again, by adding it under `ignored` in the host's
`hosts.d/<host>.state.yml`. Delete the entry there to see it again. For
leftovers expected on many hosts, see [Leftovers](#leftovers).

Run `sensible -h` for the other commands and flags.

## Licence

See [LICENCE](LICENCE).

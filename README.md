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

A stack's compose file and `compose.env` can use `!generated <name>`, a random
value that's made once per host and saved in its state. Every use of the name
in the stack gets the same value. `!generated <name> <length>` asks for at
least that many characters, rather than the default 26, and every use must give
the same length. A saved value that's too short is an error, not regenerated, so
use a new name to get a longer one.

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

### Directories

`directories` makes directories, before any files are written. Each has an
absolute `path`, and `owner`, `group` and `mode` default to root, root and
0755. Missing parents are created as root:root 0755. Roles can declare the
same directory only with the same ownership and mode.

```yaml
# roles/app/role.yml
directories:
  - path: /srv/app
  - path: /srv/app/uploads
    owner: www-data
    mode: 0750
```

Once nothing declares a directory, prune offers to remove it, but only while
it's empty.

### Apt repos

`apt_repos` adds apt sources on Debian and Ubuntu hosts, each written to
`/etc/apt/sources.list.d/<name>.sources`. `{distro}` and `{release}` are
replaced by the host's distribution and codename, e.g. `debian` and `trixie`.
Each repo needs either a `signing_key_url` to download its key from, or a
`signing_key` already on the host, such as one from a keyring package.

Sources in `sources.list.d` that nothing declares are leftovers, and so is
`/etc/apt/sources.list` if it lists repos and the host has any `apt_repos`. To
manage the distribution's own sources, declare them under the same names:

```yaml
# roles/debian/role.yml
apt_repos:
  debian:
    uris: [http://deb.debian.org/debian]
    suites: ["{release}", "{release}-updates"]
    components: [main]
    signing_key: /usr/share/keyrings/debian-archive-keyring.gpg
  debian-security:
    uris: [http://deb.debian.org/debian-security]
    suites: ["{release}-security"]
    components: [main]
    signing_key: /usr/share/keyrings/debian-archive-keyring.gpg
```

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

### Certificates

`certs` issues certificates from a CA listed in `sensible.yml`'s `cas`, which
sensible creates and keeps. Each is a `server` certificate for some DNS names,
a `client` certificate with a common name, or both. Its `ca.crt`, `tls.crt` and
`tls.key` go in `/srv/certs/<name>`, or `dir`. A certificate is renewed when an
apply finds it's within 90 days of expiring.

A stack that mounts a file with `!cert <name>/<file>` is recreated when it
changes. Units in `reload` or `restart` are reloaded or restarted. Anything
else using the files, including a stack that mounts them by path, isn't told.

```yaml
# sensible.yml
cas: [internal]
```

```yaml
# roles/db/role.yml
certs:
  db:
    ca: internal
    server: [db.example.com]
    dir: /etc/postgresql/tls
    owner: postgres
    restart: [postgresql.service]
```

### Firewall

`firewall` drops incoming connections, other than to the ports in `allow`,
with nftables. It covers containers' published ports too, by the port they're
published on. Replies, loopback, ICMP and anything over Tailscale are always
allowed. SSH isn't, so allow its port if sensible reaches the host some other
way. Removing `firewall` turns it off.

```yaml
# roles/web/role.yml
firewall:
  allow: [80/tcp, 443/tcp, 443/udp, 60000-61000/udp]
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
the role's stack, which the stack can use too, or an `!age` secret, and it's
the only secret the client keeps. Public clients have no secret, and always use PKCE. `name`
defaults to the client ID, and without `groups` any user can sign in. With
`skip_consent: true`, signed-in users go straight back to the client instead
of being asked to approve it first, which needs Pocket ID 2.10 or later.
`launch_url` is where the provider's app list sends users, and `logo` and
`dark_logo` are images in the `files` directory of the role or partial that
declares the client. Without them, the client keeps what it has. The provider
must be set, with its settings under its name. Pocket ID is supported, with an
admin's API key.

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
    skip_consent: true
    groups: [admins]
    secret: !generated oidc_secret
    launch_url: https://grafana.example.com
    logo: grafana.svg   # roles/grafana/files/grafana.svg

compose:
  env:
    OIDC_CLIENT_SECRET: !generated oidc_secret
```

`oidc_apis` sets up APIs, the services clients get access tokens for, by
their identifier, which is usually the service's URL. `name` defaults to the
identifier, and each permission's `name` to its key. `clients` are the IDs of
the confidential clients that may get tokens for the API as themselves, with
`grant_type=client_credentials` and the identifier as `resource`, each with
the permissions it's granted, which are the token's scopes. Other access to
the API, including on behalf of users, is removed. A client can be one that
another role or host declares, or one that's only in the provider. APIs need
Pocket ID 2.14 or later.

```yaml
# roles/pocketbase/role.yml
oidc_apis:
  https://pb.example.com:
    name: PocketBase
    permissions:
      records.read: {name: Read records}
      records.write: {name: Write records, description: Create and change records}
    clients:
      grafana: [records.read]
      backup: []
```

A client or API that's already there is taken over. Once nothing declares
one, prune offers to delete it. To move one to another host, apply both hosts
together.

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

Prune asks about each leftover. Answering `p` shows what's at a path before
asking again. Answering `i` keeps it and stops apply and prune mentioning it
again, by adding it under `ignored` in the host's `hosts.d/<host>.state.yml`.
Delete the entry there to see it again. For leftovers expected on many hosts,
see [Leftovers](#leftovers).

Run `sensible -h` for the other commands and flags.

## Licence

See [LICENCE](LICENCE).

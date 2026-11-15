# Software

## Packages

`packages` installs and removes packages with the host's package manager.
`remove` is applied before `install`, so a package can be replaced by one
that conflicts with it.

```yaml
# roles/base/role.yml
packages:
  install: [htop, kitty-terminfo]
  remove: [nano]
```

Packages sensible installs are recorded as its own, so once nothing declares
one, apply warns about it and prune offers to remove it. A few that modules
need for themselves, such as `sudo`, aren't recorded, so they're never
offered.

If another package manager is running, such as unattended-upgrades on a
freshly booted host, sensible waits up to five minutes for it to finish.

On Arch, a package that isn't in pacman's sync database can't be installed
until the database is refreshed, which `--update-packages` does. See
[Running sensible](running.md#apply).

## Apt repositories

`apt_repos` adds apt sources on Debian and Ubuntu hosts, each written to
`/etc/apt/sources.list.d/<name>.sources`. `{distro}` and `{release}` are
replaced by the host's distribution and codename, e.g. `debian` and `trixie`.
Each repo needs either a `signing_key_url` to download its key from, which is
saved under `/etc/apt/keyrings`, or a `signing_key` already on the host, such
as one from a keyring package.

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

Some modules add their own repositories, such as Docker's and Tailscale's.
Those vendors publish for Debian and Ubuntu but not their derivatives, so the
modules refuse other distributions.

## AUR

`aur` installs packages from the Arch User Repository, and is an error on
other hosts. Packages are built with paru, as an `aur` system account that
may run pacman without a password. paru itself is built from the AUR the
first time, and rebuilt if it stops working, as it does when pacman's library
changes version.

```yaml
# roles/zsh/role.arch.yml
aur:
  packages: [autojump-rs-bin]
```

Once nothing needs AUR packages, apply warns about the `aur` account, and
prune offers to remove it along with its home, and paru with the other
packages nothing declares.

## Docker

`docker` installs Docker and Compose: from Docker's repository on Debian and
Ubuntu, and from the distribution on Arch, where it's also started the first
time it's installed. Compose stacks need it; see [Compose stacks](stacks.md).

```yaml
# roles/docker/role.yml
docker:
  users: [chris]
  networks:
    proxy:
      subnets: [10.90.0.0/24, fd00:90::/64]
      ipv6: true
  registries:
    ghcr.io:
      username: chris
      password: !age ...
  daemon:
    log-driver: journald
```

- `users` are added to the `docker` group, and anyone else in it is removed,
  other than users given the group under `users`.
- `networks` are created before any stack, so stacks can share them as
  external networks. Subnets are in CIDR form, and an IPv6 subnet needs
  `ipv6: true`. A network that exists with different settings is left alone
  with a warning, as recreating it would disconnect every container; remove
  it by hand to have it recreated. Networks sensible created that nothing
  declares are removed.
- `registries` are the credentials root's Docker client pulls with, by
  registry host, written to `/root/.docker/config.json`.
- `daemon` is the content of `/etc/docker/daemon.json`, using Docker's own
  option names. Without it, the file is left alone. dockerd checks it before
  it's replaced, and changing it restarts Docker.

## Tailscale

`tailscale` installs Tailscale, from its repository on Debian and Ubuntu,
enables `tailscaled`, and applies `settings` with `tailscale set`. The host
must already be logged in, with `tailscale up`, or the settings fail.
Advertising an exit node or routes also turns on IP forwarding.

```yaml
# roles/base/role.yml
tailscale:
  settings:
    ssh: "true"
    advertise-exit-node: "true"
```

Settings are flag names without `--`. Those sensible knows how to read back
are only set when they differ; others are set on every apply.

`tailscale set` leaves flags it isn't given as they are, so removing a
setting, or `tailscale`, doesn't undo it: the host keeps advertising an exit
node, say. Apply warns about settings sensible set that nothing declares any
more, and prune offers to reset each to Tailscale's default. Prune can't
reset a flag whose default sensible doesn't know; set it by hand, then ignore
it.

# Getting started

## Installing

Building needs Go, at the version in `go.mod` or newer. The build embeds
agent binaries for amd64 and arm64, which `make` generates; a plain `go build`
skips that step.

```sh
make
sudo make install   # Installs sensible and its shell completions under /usr/local
```

## A first configuration

sensible reads its configuration from the working directory, or from
`--config` or `SENSIBLE_CONFIG`. A minimal one has a host and a role:

```yaml
# hosts.d/web1.yml
web1:
  address: web1.example.com
  roles:
    base:
```

```yaml
# roles/base/role.yml
users:
  chris:

sudoers:
  chris:
    - chris ALL=(ALL:ALL) ALL

packages:
  install: [htop]

timezone:
  zone: Europe/London
```

See [Configuration](configuration.md) for how the directory is laid out and
how roles are merged.

## Secrets

Anything secret is encrypted with [age](https://age-encryption.org) before
it's written to the configuration, including the credentials sensible makes
for itself when it bootstraps a host. `sensible.yml` says who can read them:

```yaml
# sensible.yml
secrets:
  recipients: [age1...]
  identity_command: [op, read, "op://Private/sensible/identity"]
```

See [Secrets](secrets.md).

## Bootstrapping a host

Bootstrap connects as an account that already works on the host, sets up the
`sensible` account and agent, and saves the new credentials:

```sh
sensible bootstrap web1 --user root
```

The machine sensible runs on is managed like any other host, over SSH to
loopback. Bootstrap it without `--user`: it only needs sudo, and installs sshd
if it's missing.

## Applying

Apply shows what would change on each host, and makes the changes once you
confirm:

```sh
sensible apply web1
sensible apply          # Every host
```

See [Running sensible](running.md) for the other commands, and what a run
does.

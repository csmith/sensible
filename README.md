# sensible

> [!CAUTION]
> This code was written entirely by LLMs and hasn't been reviewed by a
> human. I think it's worth releasing because it does something useful,
> and I use it regularly myself. It works for how I use it, but I offer
> no guarantees beyond that.

sensible configures Linux hosts from a directory of YAML: packages, users,
system settings, Docker Compose stacks, backups, certificates and so on. It
connects over SSH, runs a small agent on each host, shows you what would change,
and applies it once you confirm. Debian, Ubuntu and Arch hosts are supported.

## Quick start

```sh
make && sudo make install
```

```yaml
# hosts.d/web1.yml
web1:
  address: web1.example.com
  roles:
    base:
```

```yaml
# roles/base/role.yml
packages:
  install: [htop]

timezone:
  zone: Europe/London
```

```sh
sensible bootstrap web1 --user root   # Set up the host for management
sensible apply web1                   # Show the changes and apply them
```

See [Getting started](docs/getting-started.md) for the rest of the setup,
including secrets.

## Documentation

- [Getting started](docs/getting-started.md): installing, a first
  configuration, bootstrapping and applying
- [Configuration](docs/configuration.md): the configuration directory, hosts,
  roles, parameters and how they merge
- [Partials](docs/partials.md): configuration shared between roles
- [Secrets](docs/secrets.md): encrypting values, and values generated per host
- [Running sensible](docs/running.md): the commands, and what a run does

Each area a role can configure has a page of its own:

- [Accounts and access](docs/accounts.md): users, sudo, sshd and zsh
- [Software](docs/software.md): packages, apt repositories, the AUR, Docker
  and Tailscale
- [System](docs/system.md): hostname, time, locale, services, jobs and the
  firewall
- [Files](docs/files.md): files, directories and leftovers
- [Compose stacks](docs/stacks.md): Docker Compose projects, their volumes and
  migrations
- [Backups](docs/backups.md): restic backups
- [Certificates](docs/certificates.md): an internal CA and the certificates it
  issues
- [DNS](docs/dns.md): records for hosts and the names they serve
- [OIDC](docs/oidc.md): clients and APIs in an OIDC provider

## Licence

See [LICENCE](LICENCE).

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

## Using

```sh
sensible bootstrap web1 --user root   # Set up a new host for management
sensible apply web1                   # Show the changes for a host and apply them
sensible apply                        # The same, for all hosts
sensible prune web1                   # Offer to remove what a host has left over
sensible render web1                  # Show everything a host should have
```

The machine sensible runs on is managed like any other host, over SSH to
loopback. Bootstrap it without `--user`: it only needs sudo, and installs sshd
if it's missing.

Prune asks about each leftover. Answering `i` keeps it and stops apply and
prune mentioning it again, by adding it under `ignored` in the host's
`hosts.d/<host>.state.yml`. Delete the entry there to see it again.

Run `sensible -h` for the other commands and flags.

## Licence

See [LICENCE](LICENCE).

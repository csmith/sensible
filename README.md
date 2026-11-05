# sensible

sensible configures Linux hosts from a directory of YAML: packages, users,
system settings, Docker Compose stacks, backups, certificates and so on. It
connects over SSH, runs a small agent on each host, shows you what would change,
and applies it once you confirm. Debian and Arch hosts are supported.

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
  prompt_colours: !param prompt_colours
```

## Using

```sh
sensible bootstrap web1 --user root   # Set up a new host for management
sensible apply web1                   # Show the changes for a host and apply them
sensible apply                        # The same, for all hosts
sensible render web1                  # Show everything a host should have
```

The machine sensible runs on is managed like any other host, over SSH to
loopback. Bootstrap it without `--user`: it only needs sudo, and installs sshd
if it's missing.

Run `sensible -h` for the other commands and flags.

## Licence

See [LICENCE](LICENCE).

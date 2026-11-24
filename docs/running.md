# Running sensible

```sh
sensible bootstrap web1 --user root   # Set up a new host for management
sensible apply web1                   # Show the changes for a host and apply them
sensible apply                        # The same, for all hosts
sensible apply web1 --update-packages # Update all its packages first
sensible prune web1                   # Offer to remove what a host has left over
sensible render web1                  # Show everything a host should have
sensible facts web1                   # Show what the agent reports about a host
```

Run `sensible -h` for every command and flag. Flags can go anywhere on the
command line, and each can also be set as an environment variable with the
`SENSIBLE_` prefix, e.g. `SENSIBLE_CONFIG` for `--config`. `--debug` shows
what the agents say on stderr.

## How a run works

The controller, the `sensible` command, connects to each host over SSH as the
`sensible` account, whose forced command runs the agent under sudo. The agent
is the same binary, run as `sensible agent`; if the one on the host isn't the
build the controller carries, it's upgraded first. The agent reports the
host's facts, such as its OS family and release, and the controller turns the
host's configuration and facts into an ordered list of resources: files,
packages, services, stacks and so on.

The agent checks each resource and reports what would change, which is shown
as the plan:

```text
> Resolving changes on web1
  ~ file /etc/ssh/sshd_config.d/10-sensible.conf
    --- /etc/ssh/sshd_config.d/10-sensible.conf
    +++ /etc/ssh/sshd_config.d/10-sensible.conf
    @@ -2,3 +2,4 @@
    +MaxAuthTries 4
    ↻ then reload ssh
  ? package tailscale  deferred
  ! volumes /srv/volumes
    /srv/volumes/old-stack
    no role declares these; run `sensible prune` to remove them once they're not needed
  ✓ 41 unchanged
```

- `~` is a change, with a diff of what it does. `↻ then` shows a handler the
  change triggers, such as reloading a service, which runs once after the
  host's other changes.
- `?` is deferred: it depends on an earlier change, such as a package from a
  repository that isn't added yet, so it's checked again during apply.
- `!` is a warning about something apply won't change, such as leftovers for
  prune, something `leftovers.external` expects that's missing, or a host that
  needs a reboot.
- `✗` is a resource that couldn't be checked. The rest of the host's plan is
  still shown, but clean-ups that remove what nothing declares are skipped, as
  they can't tell what's declared.

Once confirmed, or straight away with `--yes`, the hosts are applied in
parallel, stopping at the first failure on each. Changes that aren't bound to
one host, such as DNS records and OIDC clients, are planned from every host's
configuration, so they're only applied when every host in the run could be
planned. A handler that fails, or a stack whose files changed but which
couldn't be recreated, is remembered on the host and done on the next apply.

Every file sensible writes starts with `# Managed by sensible.`, where the
format allows a comment, so it can tell its own files from others. The agent
keeps its own records under `/var/lib/sensible`, and logs what it does to
syslog as `sensible-agent`.

## Bootstrap

```sh
sensible bootstrap web1 --user root
sensible bootstrap web1 --user chris --host-key SHA256:...
sensible bootstrap web1 --rotate
```

Bootstrap connects as `--user`, root or an account with sudo, using the SSH
agent's keys or a password it asks for. On the host it creates the `sensible`
system account, installs the agent at `/usr/local/libexec/sensible-agent`,
and writes the sshd and sudoers configuration that lets the account run it,
and nothing else. It then connects the normal way to prove that works, and
saves the account's key and sudo password, encrypted, in
`hosts.d/<host>.state.yml`.

A host with no `host_keys` yet is asked about the key it presents, for
checking against the provider's console. `--host-key` gives the expected
SHA256 fingerprint instead, for scripts. The accepted key is saved to the
state file, and every later connection must match it.

`--rotate` replaces a host's credentials. Without `--user`, it works through
the host's existing access: it authorizes the new key alongside the old one,
sets the new password, connects with them, saves them, and only then drops
the old key. A host whose access has broken can be bootstrapped again with
`--user --rotate`, as the setup is repeatable.

New credentials are saved as `pending_ssh_key` and `pending_sudo_password`
before the host is given them, so a bootstrap that stops part way doesn't
lock sensible out. Connections try them when the current ones are rejected,
and save them as current once they work.

The machine sensible runs on is bootstrapped without `--user`, with sudo
directly. It installs and starts sshd if it's missing, as that's how it's
reached afterwards, over loopback. A host counts as this machine when its
name in `hosts.d` is the machine's hostname.

## Apply

`sensible apply [hosts...]` plans the named hosts, or every host, and applies
the plan once confirmed. It exits with an error if anything failed.

`--update-packages` runs `pacman -Syu` or `apt-get full-upgrade` before
anything else, which fixes installs failing with a 404 from a stale package
index. It never reboots, but says when a host needs to.

## Prune

Apply warns about what sensible finds but didn't put there, such as files in
directories it manages, and about what it put there that nothing declares any
more, such as packages it installed, a stack's volumes or an account.
Prune lists those leftovers and asks about each:

```text
Remove /srv/volumes/old-stack from web1? [y/N/i/p]
```

Answering `p` shows what's at a path before asking again. Answering `i`
keeps it and stops apply and prune mentioning it again, by adding it under
`ignored` in the host's `hosts.d/<host>.state.yml`. Delete the entry there to
see it again. For leftovers expected on many hosts, see
[`leftovers`](files.md#leftovers).

A host with changes still to apply is skipped, as its leftovers may change
once they're applied. Generated secrets a stack no longer uses are offered
too, and those of a stack the host no longer has once its volumes are gone.

## Render and facts

`sensible render [hosts...]` prints everything a host should have, as apply
would make it, without changing anything: each file with its content and
ownership, and every other resource on a line. `--json` prints the resources
as JSON instead.

Render connects to the hosts for their facts. `--facts <file>` reads them
from a file as `sensible facts` prints them, so a configuration can be
rendered without reaching the hosts, or without the age identity, in which
case secrets are shown as placeholders:

```sh
sensible facts > facts.json
sensible render --facts facts.json web1
```

## Shell completion

`make install` installs completions for bash and zsh, which complete
commands, flags, host names and the paths `secret show` takes.

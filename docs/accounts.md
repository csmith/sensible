# Accounts and access

## The sensible account

Bootstrap creates a `sensible` system account on each host, whose home,
`/var/lib/sensible`, is owned by root, and whose shell is `/bin/sh`. Its SSH
key, in `/etc/ssh/authorized_keys/sensible`, is restricted to a forced command
that runs the agent through sudo, and `/etc/sudoers.d/sensible` allows that
command alone. sshd takes no other keys or certificates for the account, even
if its global settings name an `AuthorizedKeysCommand` or `TrustedUserCAKeys`.
Apply keeps all of this in place, so nothing else can remove it, and the
`sshd` module rejects settings that would shut the account out.

Logins that don't go through sshd's keys, such as Tailscale SSH, aren't
covered by this, so they shouldn't be allowed to log in as `sensible`.

## Users

`users` manages accounts. Each may have `groups`, which it's added to but
never removed from, a `home`, which defaults to `/home/<name>` or `/root`,
and a `shell`. New accounts get a home directory; changing `home` doesn't move
an existing one, and an empty `shell` leaves the account's alone.

```yaml
# roles/base/role.yml
users:
  chris:
    groups: [docker, wheel]
    shell: /usr/bin/zsh
  deploy:
    home: /srv/deploy
```

Accounts sensible creates are marked as its own. Once nothing declares one,
apply warns about it, and prune offers to remove it, along with its home if
it owns it.

## Sudoers

`sudoers` writes files in `/etc/sudoers.d`, each a list of lines, validated
with `visudo` before they're put in place. Roles can add lines to the same
file.

```yaml
# roles/base/role.yml
sudoers:
  chris:
    - chris ALL=(ALL:ALL) ALL
```

A file in `/etc/sudoers.d` that sensible wrote and nothing declares any more
is removed. Files from elsewhere are warned about, and left for prune.

## SSH daemon

`sshd` installs and enables sshd, and writes its `settings` to a drop-in in
`/etc/ssh/sshd_config.d`, which the distributions' `sshd_config` includes
before setting anything itself, so they take precedence. The configuration
is checked with `sshd -t` before it replaces the old one, and sshd is reloaded
when it changes. Where sshd listens is kept in a drop-in of its own, as
changing it restarts the socket that starts sshd on hosts that have one.

```yaml
# roles/sshd/role.yml
sshd:
  settings:
    PermitRootLogin: "no"
    PasswordAuthentication: "no"
    Port: 22
  authorized_keys:
    chris:
      - ssh-ed25519 AAAA...
```

`authorized_keys` writes each user's `~/.ssh/authorized_keys` as given,
replacing whatever was there. `AllowUsers`, `AllowGroups`, `DenyUsers` and
`DenyGroups` must admit the `sensible` account, or sensible couldn't reach the
host, so settings that wouldn't are rejected.

On Arch, pacman leaves the package's `sshd_config` as a `.pacnew` when the
installed one has been changed. Only the package's includes `sshd_config.d`,
so sensible installs the `.pacnew` in its place.

## Sudo with SSH keys

`pam_rssh` lets sudo authenticate with a key in the user's forwarded SSH
agent instead of a password. The keys that may go in `/etc/sudoers.keys`, and
sudo is told to keep `SSH_AUTH_SOCK`.

```yaml
# roles/base/role.yml
pam_rssh:
  keys:
    - ssh-ed25519 AAAA...
```

On Debian and Ubuntu, the module is installed from pam_rssh's release
packages, for the releases and architectures it publishes them for. On Arch,
it's built from the AUR. Removing `pam_rssh` takes the line out of PAM's sudo
configuration, so sudo goes back to asking for a password.

## Zsh

`zsh` makes zsh the shell of its `users` and writes each one's `.zshrc`, with
oh-my-zsh checked out at `/usr/share/oh-my-zsh` for them to share. `theme`
defaults to agnoster, `editor` sets `$EDITOR` and defaults to vim, and
`prompt_colours` colours the host segment of each user's prompt, which only
agnoster has. On Arch, the `archlinux` plugin is always on.

```yaml
# roles/zsh/role.yml
zsh:
  users: [chris, root]
  plugins: [git, docker]
  editor: nvim
  prompt_colours:
    root: red
```

The `.zshrc` is overwritten on every change, so users put their own settings
in `~/.zshrc.local`, which it sources. A user's `shell` under `users` can't
disagree with `zsh.users`. Once a user leaves `zsh.users`, the `.zshrc`
sensible wrote is left for prune.

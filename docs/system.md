# System

## Hostname, time and locale

`hostname` sets the host's name, which defaults to its name in `hosts.d`. On
Debian and Ubuntu it's also mapped in `/etc/hosts`, as they don't resolve the
host's own name otherwise.

`timezone` sets the system time zone from a tz database name. `locale` sets
`LANG`, and generates it along with any locales under `generate`. Locales no
longer listed stay until `locale-gen` next runs.

`ntp` enables systemd-timesyncd. `servers` replace the distribution's default
servers, and leaving it empty keeps them.

```yaml
# roles/base/role.yml
hostname:

timezone:
  zone: Europe/London

locale:
  lang: en_GB.UTF-8
  generate: [en_US.UTF-8]

ntp:
  servers: [time.cloudflare.com]
```

## Login messages and vim

`quiet_login` hides the message of the day and the last login notice, by
commenting out the PAM modules that show them. Removing it doesn't restore
the lines.

`vim` installs vim. On Arch, where the package doesn't provide them, it also
links `vi`, `view` and the other traditional names to it.

```yaml
# roles/base/role.yml
quiet_login:
vim:
```

## Services

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

## Jobs

`jobs` runs commands on a schedule, each from a systemd timer. `command` is
the program and its arguments, `schedule` is a systemd calendar expression,
as for `OnCalendar`, and `user` runs it as someone other than root. A job
that was missed while the host was off runs when it comes back.

```yaml
# roles/app/role.yml
jobs:
  renew:
    command: [/usr/local/bin/renew, --quiet]
    schedule: "*-*-* 03:00"
    user: app
```

Names are lower case letters, digits, `-` and `_`, and the units are
`sensible-<name>.service` and `.timer`. Units with that prefix that nothing
declares any more are stopped and removed. `backup` is the backup job's name;
see [Backups](backups.md).

## Firewall

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

The rules are loaded from a unit of sensible's own, into a table of its own,
so they leave Docker's and Tailscale's rules alone. A ruleset is checked
before it's loaded, and loading is atomic, so one that's rejected leaves the
last one in place.

## Removing paths

`remove` removes paths, recursively, on every apply. Each is absolute, or
`~user/...` for a path in a user's home.

```yaml
# roles/base/role.yml
remove:
  paths: [/etc/motd, ~chris/.bash_logout]
```

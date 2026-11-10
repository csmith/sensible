# Certificates

`certs` issues certificates from a CA listed in `sensible.yml`'s `cas`, which
sensible creates and keeps. Each is a `server` certificate for some DNS names,
a `client` certificate with a common name, or both. Its `ca.crt`, `tls.crt` and
`tls.key` go in `/srv/certs/<name>`, or `dir`. A certificate is renewed when an
apply finds it's within 90 days of expiring.

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

`owner` and `group` apply to the files and to `dir`, and the key is readable
only by the owner. Units in `reload` or `restart` are reloaded or restarted
when the files change. A stack that mounts a file with `!cert <name>/<file>`
is recreated when it changes. Anything else using the files, including a stack
that mounts them by path, isn't told.

```yaml
# roles/db/docker-compose.yml
services:
  db:
    volumes:
      - !cert db/tls.crt:/tls/server.crt:ro
      - !cert db/tls.key:/tls/server.key:ro
```

Certificates last a year, and the CAs ten. A CA is created the first time a
certificate names it, and saved to `ca.state.yml` in the configuration
directory, with its key encrypted. Issued certificates are saved to the host's
state file, so other hosts can't read their keys, and reissued when their
config changes. Names, of CAs and certificates, are letters, digits, `-` and
`_`.

When a CA is too close to expiry to issue certificates that would last, apply
says so. Remove it from `ca.state.yml` to create a new one; every certificate
it signed is then reissued.

Files in `dir` that a certificate no longer needs are removed, but nothing
else in it is. The files of a certificate nothing declares any more are
removed, and so is their directory once it's empty.

# Secrets

Secrets are encrypted with [age](https://age-encryption.org) wherever they
appear in the configuration, including the state files sensible writes. A
plain value where a secret is expected is rejected.

## Settings

```yaml
# sensible.yml
secrets:
  recipients: [age1...]
  identity_command: [op, read, "op://Private/sensible/identity"]
```

`recipients` are the age public keys secrets are encrypted to.
`identity_command` prints the age identity that decrypts them. It runs once
per command, the first time a secret is needed, and gets no terminal, so
anything it needs to ask must be asked some other way, such as a desktop
prompt.

## Encrypting a value

`sensible secret encrypt` reads a value, from the terminal without echoing
it, or from a pipe, and prints it as an `!age` block to paste into the
configuration:

```sh
$ sensible secret encrypt
Value to encrypt:
!age |
  -----BEGIN AGE ENCRYPTED FILE-----
  ...
  -----END AGE ENCRYPTED FILE-----
```

```yaml
restic:
  password: !age |
    -----BEGIN AGE ENCRYPTED FILE-----
    ...
    -----END AGE ENCRYPTED FILE-----
```

`--raw` prints a plain armored age file instead, and keeps piped input
exactly, for a whole file to be encrypted. A file whose name ends in `.age`,
in a role's `files/` or among a stack's `compose.files`, is decrypted when
it's written to the host, without the suffix.

```sh
sensible secret encrypt --raw < app.conf > roles/app/app.conf.age
```

## Where secrets go

An `!age` value works wherever a setting is a secret, such as `restic.password`
or a DNS provider's key, and in some places that take either plain text or a
secret: a file's `content`, `restic.environment`, a stack's compose file and
`compose.env`, a migration's `on` and an OIDC client's `secret`. Files whose
content is secret are written with mode 0640 unless told otherwise, and
secrets are replaced with placeholders in, or left out of, the diffs apply
shows.

## Reading a secret back

`sensible secret show <file>` lists the `!age` values in a configuration file,
and `sensible secret show <file> <path>` decrypts one. Given a whole-file
secret, such as a stack's `.age` file, `sensible secret show <file>` decrypts
the file. Relative files are in the configuration directory.

```sh
$ sensible secret show sensible.yml
dns.mydnshost.auth_user
dns.mydnshost.auth_key
$ sensible secret show sensible.yml dns.mydnshost.auth_key
$ sensible secret show roles/app/app.env.age
```

## Generated values

A stack's compose file and `compose.env`, a migration's `on` and an OIDC
client's `secret` can use `!generated <name>`, a random value that's made once
per host and saved, encrypted, in `hosts.d/<host>.state.yml`. Every use of the
name in the stack gets the same value, so a database password can be given to
both the database and the app that uses it.

```yaml
# roles/app/docker-compose.yml
services:
  db:
    environment:
      POSTGRES_PASSWORD: !generated db_password
  app:
    environment:
      DATABASE_PASSWORD: !generated db_password
```

Values are 26 characters. `!generated <name> <length>` asks for at least that
many, and every use must give the same length. A saved value that's too short
is an error, not regenerated, so use a new name to get a longer one. Values
a stack no longer uses, and those of stacks a host no longer has, are offered
for removal by `sensible prune`.

## Rendering without the identity

`sensible render --facts <file>` works without the identity: secrets it can't
decrypt are shown as placeholders derived from the ciphertext, and unsaved
generated values as `<generated:name>`. See [Running sensible](running.md).

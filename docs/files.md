# Files

## Files

`files` writes files as given. Each has an absolute `path`, and either
`content` or a `source` in the `files` directory of the role or partial that
declares it, which may be binary. A source ending in `.age` is an age file from
`sensible secret encrypt --raw`, and is decrypted. `content` can be an `!age`
value. `owner`, `group` and `mode` default to root, root and 0644, or 0640 when
the file is encrypted, and missing parent directories are created as root:root
0755. Two roles can't write the same path.

```yaml
# roles/zram/role.yml
packages:
  install: [zram-generator]

files:
  - path: /etc/systemd/zram-generator.conf
    content: |
      [zram0]
  - path: /usr/local/bin/tool
    source: tool
    mode: 0755
```

Once nothing declares a file, prune offers to remove it, unless it's been
changed since it was written.

## Directories

`directories` makes directories, before any files are written. Each has an
absolute `path`, and `owner`, `group` and `mode` default to root, root and
0755. Missing parents are created as root:root 0755. Roles can declare the
same directory only with the same ownership and mode.

```yaml
# roles/app/role.yml
directories:
  - path: /srv/app
  - path: /srv/app/uploads
    owner: www-data
    mode: 0750
```

Once nothing declares a directory, prune offers to remove it, but only while
it's empty.

## Leftovers

Apply warns about what sensible finds but didn't put there, such as files in
directories it manages, and about what it put there that nothing declares any
more, and prune offers to remove them. See
[Running sensible](running.md#prune). `leftovers` acknowledges those expected
on many hosts. What's under `ignore` is never warned about or pruned. What's
under `external` is managed some other way: it's never pruned, but apply
warns if it's missing. Paths are absolute, and paths and package names can be
globs.

```yaml
# roles/base/role.yml
leftovers:
  ignore:
    paths: [/etc/sudoers.d/README]
  external:
    paths: [/usr/local/bin/tool]
    packages: [tool-git]
```

For a leftover on one host, answer `i` when prune asks about it instead.

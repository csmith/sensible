# DNS

sensible can keep the records for its hosts, and for the names they serve, in
a DNS provider. The provider is set in `sensible.yml`, with its settings under
its name. MyDNSHost is supported.

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

## Host names

A host with a `dns_name` in `hosts.d` gets A and AAAA records for the default
addresses its agent reports. Records of a family the host reports no address
for are left alone, as are TTLs.

```yaml
# hosts.d/web1.yml
web1:
  address: 203.0.113.10
  dns_name: web1.example.com
```

## Virtual hosts

A role marks the domain names that a host serves with `!vhost`, in its files, its
compose file, its parameters' defaults or the arguments it gives partials. The
tag is replaced by its text, so it goes where the name would be written
anyway. Several names are separated by commas or spaces.

```yaml
# roles/app/docker-compose.yml
services:
  proxy:
    environment:
      HOSTNAME: !vhost app.example.com
```

```yaml
# hosts.d/web1.yml
web1:
  dns_name: web1.example.com
  roles:
    blog:
      domain: !vhost "blog.example.com, www.blog.example.com"
```

With `dns.vhosts`, each vhost gets those records for every host serving it,
with `{host}` replaced by the host's `dns_name`, and its other A, AAAA and
CNAME records are removed. A host that serves vhosts needs a `dns_name`, and a
vhost can't be a host's `dns_name`, as both would set its address records.

A vhost in a zone the account doesn't have, or can't change, is left alone
with a warning. A host name in one is an error.

## When changes are made

DNS changes are planned from every host's configuration once the hosts in the
run have been planned, and shown with the rest of the plan. They're applied
after the hosts, and only if every host in the run could be planned, as one
that couldn't may have changed what the records should be.

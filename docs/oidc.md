# OIDC

sensible can register the OIDC clients and APIs its hosts' services need with
an OIDC provider, so a role deploying a service also sets up its login. The
provider is set in `sensible.yml`, with its settings under its name. Pocket
ID is supported, with an admin's API key. Its `url` must be `https://`, or
`http://` only to a loopback address, so the key isn't sent in the clear.
sensible won't follow a redirect from it, so `url` must be where the API is
served rather than an address that redirects there.

```yaml
# sensible.yml
oidc:
  provider: pocketid
  pocketid:
    url: https://id.example.com
    api_key: !age ...   # From `sensible secret encrypt`
```

## Clients

`oidc_clients` sets up clients, by client ID, with the URLs users sign in
through in `callback_urls`. A confidential client's `secret` is a `!generated`
value of the role's stack, which the stack can use too, or an `!age` secret,
and it's the only secret the client keeps. A client that can't keep a secret,
such as a desktop app or a single-page web app, is marked `public: true`
instead. Public clients have no secret, always use PKCE, and need
`callback_urls`, as they can't use client credentials. `name` defaults to the
client ID, and without `groups` any user can sign in. With `skip_consent: true`, signed-in users go straight back
to the client instead of being asked to approve it first, which needs Pocket
ID 2.10 or later. `launch_url` is where the provider's app list sends users,
and `logo` and `dark_logo` are images in the `files` directory of the role or
partial that declares the client. Without them, the client keeps what it has.

```yaml
# roles/grafana/role.yml
oidc_clients:
  grafana:
    name: Grafana
    callback_urls: [https://grafana.example.com/login/generic_oauth]
    logout_callback_urls: [https://grafana.example.com/login]
    pkce: true
    skip_consent: true
    groups: [admins]
    secret: !generated oidc_secret
    launch_url: https://grafana.example.com
    logo: grafana.svg   # roles/grafana/files/grafana.svg

compose:
  env:
    OIDC_CLIENT_SECRET: !generated oidc_secret
```

```yaml
# roles/workstation/role.yml
oidc_clients:
  notes-desktop:
    name: Notes
    public: true
    callback_urls: [http://127.0.0.1/callback]
```

A confidential client without `callback_urls` can't sign anyone in, so it
can't have `logout_callback_urls` or a `launch_url`. It only gets tokens as
itself, with client credentials, for the [APIs](#apis) that grant it access.
That suits a daemon or script calling an API, which may run outside any stack
and so need an `!age` secret.

```yaml
# roles/pocketbase/role.yml
oidc_clients:
  backup:
    secret: !age ...

oidc_apis:
  https://pb.example.com:
    clients:
      backup: []
```

Several hosts can declare the same client, such as a service with an instance
on each. The client gets every host's `callback_urls` and
`logout_callback_urls`, and its other settings must be the same on each host,
so its secret has to be `!age`, as `!generated` values differ between hosts.
The hosts that declare a client, and those sensible managed it for, must be
applied together, or the client isn't changed.

## APIs

`oidc_apis` sets up APIs, the services clients get access tokens for, by their
identifier, which is usually the service's URL. `name` defaults to the
identifier, and each permission's `name` to its key. `clients` are the IDs of
the confidential clients that may get tokens for the API as themselves, with
`grant_type=client_credentials` and the identifier as `resource`. `users` are
the IDs of the clients, public or confidential, that may get tokens for it on
behalf of the users who sign in to them, by sending the identifier as
`resource` when they sign in. Each client is listed with the permissions it's
granted, which are the token's scopes, and other access to the API is removed.
A client can be one that another role or host declares, or one that's only in
the provider. APIs need Pocket ID 2.14 or later.

```yaml
# roles/pocketbase/role.yml
oidc_apis:
  https://pb.example.com:
    name: PocketBase
    permissions:
      records.read: {name: Read records}
      records.write: {name: Write records, description: Create and change records}
    clients:
      grafana: [records.read]
      backup: []
    users:
      notes: [records.read, records.write]
```

## Ownership

A client or API that's already in the provider is taken over, and the host's
state file records that sensible manages it. Once nothing declares one, prune
offers to delete it. To move one to another host, apply both hosts together.

Like DNS, OIDC changes are shown with the plan and applied after the hosts,
only if every host in the run could be planned.

# Accounts and access

Every endpoint requires a signed-in session or an API token. This page covers
what the roles mean, how tokens work, and how to put an identity provider in
front — plus what the previous build did, because that is the reason several of
these decisions look the way they do.

## What this replaced

There was no authentication at all. `actor()` read `X-Forwarded-User` from the
request and otherwise called everyone `local`, on the stated assumption that the
app always sits behind an identity-aware proxy.

`X-Forwarded-User` is a request header. Anything that could open a connection to
the API could set it and be anybody:

```
$ curl http://host:8080/api/v1/scopes          # the whole inventory
$ curl -H 'X-Forwarded-User: admin' http://host:8080/api/v1/users
```

Five `created_by` columns and every audit record stored that claim as though it
were a fact. "Who started this run" was a string the caller chose.

Both of those now answer `401`.

## First run

A fresh install starts with one account:

```
admin / pinkglasses
```

It is created on the first boot that finds an empty database, and the creation is
conditional on the table being empty *in the insert itself*, so two api replicas
starting together cannot both create it.

This is a deliberate trade, and it is the weakest thing on this page. A published
credential is the pattern behind Mirai and a long line of breaches, and what this
database holds is exactly what an attacker would want. Three things are meant to
keep it honest, and all three should stay:

1. **Created only on an empty database.** Delete the account and it does not come
   back; rename it and the seed does not recreate the old name.
2. **The API says so at every start**, not just the first, for as long as the
   password still works.
3. **The UI carries a banner** on every page until it is changed — and it is not
   dismissible, because a banner you can click away is one you stop seeing while
   the thing it warns about stays true.

The check behind (2) and (3) verifies the published password against the stored
hash rather than reading a flag, so it cannot drift: change the password and the
warnings stop; set it back and they return.

`pinkglasses` is 11 characters, one short of the 12-character minimum. That is on
purpose — the default cannot be re-entered as its own replacement.

### Starting without a published password

```bash
ASM_DEFAULT_ADMIN_PASSWORD=$(openssl rand -base64 24)   # before first boot
ASM_DEFAULT_ADMIN_PASSWORD=-                            # create no account at all
```

With `-`, the first visit shows a form that creates the first administrator
instead, which is the better path if you are exposing this to anyone.

Either way the first administrator inherits every scope created before there were
accounts. Those record `created_by = 'local'`, which names nobody.

### Locked out

The account is never recreated, so a forgotten password has no in-app recovery.
`go run ./tools/pwhash 'new password'` prints an argon2id hash to write into
`app_user.password_hash` directly.

## Roles

Three, ordered. Each adds to the one below rather than replacing it.

| Role | Adds |
|---|---|
| **viewer** | Reads everything: inventory, findings, runs, search, worker list, VPN config *names*. Changes nothing. |
| **operator** | Companies, targets, wordlists, alert channels — and **starting scans**. |
| **admin** | Accounts, API tokens, worker enrollment and scaling, VPN configurations. |

Two boundaries are worth explaining because they are the whole design:

**Starting a run is where reading becomes acting.** A scan sends packets at
somebody else's infrastructure. Everything a viewer can do is look at what has
already been collected; the first thing an operator can do is cause traffic.

**Adding a VPN configuration and enrolling a worker are admin** because both hand
out credentials — one for a network that is not ours, one for the control plane
itself. A viewer can see that a tunnel called `vps-wireguard` exists and what
address it last exited from; the body is sealed and is returned by no endpoint
at any role.

Roles are enforced per route group, and the whole of `/api/v1` is inside
`requireAuth` with exactly three exceptions: `auth/status`, `auth/setup`,
`auth/login`.

### The test that keeps it that way

`TestEveryRouteRequiresAuth` walks the live router and fails if any route answers
anything but `401` to an unauthenticated request. A new endpoint fails the build
until it is either placed inside the authenticated group or added to the public
list with a written reason.

This is deliberate. Authentication does not come back off because somebody
deletes it — it comes back off because somebody adds a handler in the wrong place
and nobody notices for six months. That is the failure mode this codebase has
hit repeatedly in other subsystems.

## Sessions

Server-side rows, not self-contained tokens. The cookie holds a random secret;
only its SHA-256 is stored, so reading the database does not hand over live
sessions. It is `HttpOnly`, `SameSite=Lax`, and `Secure` when the request arrived
over TLS.

The reason for server-side state is revocation. A stateless token keeps working
until it expires, which means disabling somebody does nothing until then. Here,
**changing a role, disabling an account or setting a new password deletes that
user's sessions**, so it takes effect on their next request — measured at
200 → 401 on the very next call.

Sessions last 12 hours and slide on activity, so a long scan does not sign you
out while you watch it.

## Passwords

argon2id, 64 MiB / t=3 / p=4, with the parameters encoded in each hash so the
cost can be raised later without invalidating existing ones.

The only rule is **12 characters minimum**. Composition rules — one capital, one
digit, one symbol — mostly produce `Password1!` and buy an attacker very little;
length is worth more, and this is a self-hosted tool whose operator sets their
own password.

Sign-in is limited to 10 attempts per 15 minutes, counted **per username and per
source address**. Limiting one alone is trivially walked around: a botnet varies
the address, and one host can walk the user list.

An unknown username is verified against a dummy hash, so a request for an account
that does not exist costs the same as one that does. Both answer
`wrong username or password`. Without that, response timing enumerates who has an
account — measured at 31–41 ms either way.

**The last enabled administrator cannot be demoted, disabled or deleted.** The
recovery path otherwise runs through `psql`.

## Renaming an account

**Accounts → edit** changes the username. It is safe for history: audit records
and scope ownership point at the account's id, not at its name, so what somebody
did stays attached to them. An audit row keeps the name that was in use when it
was written, and resolves through the id to whatever the account is called now:

```
   action    | name_at_the_time | account_now
-------------+------------------+-------------
 user.setup  | doom             | admin
```

Two things a rename does move:

- **What future `created_by` strings say.** Those columns store a name, so rows
  written before and after a rename disagree. They are a convenience; the id is
  the fact.
- **Which account a trusted proxy resolves to.** If a proxy is in front, its
  `X-Forwarded-User` must be changed to match, or that person stops being able
  to sign in.

Deleting an account is different: its audit rows survive with the name that
performed each action, and only the link to the account is dropped.

## API tokens

For scripts and CI, so automating something does not mean sharing a password.

```bash
curl -H "Authorization: Bearer pgt_…" http://localhost:8080/api/v1/scopes
```

- The secret is shown **once**, at creation. Only a hash is stored, so it cannot
  be recovered — lose it, revoke it, make another.
- A token may be **narrower than its owner, never wider**. An admin can mint a
  read-only token for a dashboard; a viewer asking for an admin token is refused.
- Revocation, expiry and the owner's disabled flag are all checked at lookup, so
  a token stops working the moment any of them changes.
- `X-API-Token` is accepted as well as `Authorization`, because `EventSource`
  cannot set an `Authorization` header.

Give anything that lives in a CI configuration an expiry.

## Putting an identity provider in front

If you already run oauth2-proxy, Authelia or Cloudflare Access, PinkGlasses can
take its word for who you are — but only if the proxy proves it is the proxy:

```bash
ASM_TRUSTED_PROXY_SECRET=$(openssl rand -base64 32)   # set on the api
```

The proxy then sends both:

```
X-Forwarded-User: alice
X-Proxy-Secret:   <that value>
```

The account still has to exist here, with a role: the proxy says *who*,
PinkGlasses says *what they may do*. Create it under **Accounts** with no
password and it will only ever sign in through the proxy.

Leave the variable unset and header authentication is off entirely — the default,
and the right one. `X-Forwarded-User` on its own is refused **and logged**, since
the only two things it can mean are a misconfigured proxy or somebody trying the
old unauthenticated path.

## What this is not

- **No per-scope isolation.** Every signed-in user sees every company. That suits
  a small team working one attack surface together. `scope.owner_id` is recorded
  so it can be tightened later without another migration.
- **No MFA, no OIDC.** Put a proxy in front for either today. The user and
  session layer is shaped so a provider can be added without reworking
  ownership, audit or tokens.
- **The audit log is not tamper-evident.** It records a user id rather than a
  string, which is a large improvement over a header, but anyone with database
  access can still edit it.

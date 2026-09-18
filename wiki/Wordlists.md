# Wordlists

Three stages of the pipeline need a list of lines: subdomain brute-forcing needs
names to try, resolution needs nameservers to ask, and directory search needs
paths to guess. They are the same kind of object, so they share one registry —
one table, one upload path, one editor, three tabs in the UI.

## The three kinds

| Kind | Used by | How a run consumes it |
|---|---|---|
| **Subdomain** (`dns`) | shuffledns | **Every** list marked default becomes its own `dns_brute` task |
| **Resolvers** | shuffledns | **One** list — the first default by name |
| **Directory** (`dir`) | gobuster / ffuf | **One** list — the first default by name |

The difference matters. Marking three subdomain lists default is how you ask for
all three, and they brute-force in parallel across workers. Marking three
directory lists default is not an error but it is a surprise: only the first by
name is used, and dispatch logs which one it chose and which it passed over.

## What ships

Five lists are registered on a fresh install and are loaded from the bundle the
control-plane image carries — fetched once at image build time, so a fresh
deployment needs no internet for them — or, failing that, download themselves on first
boot:

| List | Kind | Size |
|---|---|---|
| assetnote `best-dns-wordlist` | subdomain | ~9.5M entries |
| assetnote `httparchive_subdomains` | subdomain | ~3.2M entries |
| SecLists `common.txt` | directory | ~4.7k entries |
| SecLists `raft-medium-directories.txt` | directory | ~30k entries |
| trickest public resolvers | resolvers | ~12.7k entries |

Until a download finishes the entry reads `pending` and scans skip it. A failed
download shows its reason in the list and is retried on every sweep, so a
network blip heals itself rather than disabling the list for good.

The **Wordlists** page belongs to the install, not to a company, so it shows the
shipped lists before any company has been created. If an upgraded install still
shows the page as it was, the browser is running the previous build of the app:
reload once with the cache bypassed (`Ctrl+Shift+R`). Builds since 2026-09-18 tell
the browser to revalidate the shell on every load, so this is a one-time step.

## How a list reaches a worker

Lists live in object storage, never in the worker image — the assetnote lists
are hundreds of megabytes and change independently of releases.

1. The run records which lists it uses, so it stays reproducible if the registry
   changes afterwards.
2. At **dispatch** the gateway attaches the list's name, SHA-256 and a download
   URL to the job. The URL is the gateway's own (`/agent/v1/wordlists/<sha>`),
   served to enrolled workers by streaming the object from storage: a worker
   inside a run's VPN namespace, or on a VPS, can reach the gateway by
   definition, whereas a presigned store URL names an internal host it may not
   resolve at all — which is how scans used to fail behind some VPNs.
3. The worker looks in its on-disk cache **by content hash** and only fetches a
   list it does not have. It rarely has to: when a worker starts it asks the
   gateway for every ready list and caches them all (`wordlists cached and
   ready` in its log), and the cache volume is shared between the standing
   worker and every run's own workers, so a scan finds its lists already there.

The content hash is what makes editing work: changing a list changes its hash,
so workers fetch the new version instead of serving the old one from cache.

A run with no list of a given kind is not an error. The worker falls back to the
list baked into its image, and the log says which was used:

```
content discovery  url=http://45.33.32.156:80  wordlist="seclists common web content"
                   candidates=8 confirmed=8 by_status="map[200:6 301:2]"
```

## Editing and uploading

You can upload your own list, mark which lists are used by default, and edit
entries in place. Editing is capped at 4 MB: resolver and directory lists are
kilobytes to megabytes, but the assetnote wordlists are far past any sensible
in-browser editor and are replaced by upload instead.

Resolver entries are validated on save — each must be an IP, optionally with a
port — and bad lines are reported with their line numbers. A malformed resolver
otherwise degrades every brute force that uses the list with no visible error.

Built-in lists cannot be deleted; your own can.

## The one that decides how loud a scan is

Directory search is the only stage that fires thousands of requests at a single
host, and the size of the default `dir` list is what sets that number. The
shipped `common.txt` is ~4,700 requests per web service; `raft-medium` is
~30,000. Against a host you do not own, that is the setting to think about
before the port-scan rate limits.

`dir_concurrency` (default 10) caps how many of those run at once, and
`dir_wordlist` still chooses between the two lists baked into the worker image —
but only when no registry list is attached, which on a normal install it is.

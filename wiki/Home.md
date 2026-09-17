<p align="center">
  <img src="https://raw.githubusercontent.com/cobbbex/PinkGlasses/main/assets/brand/lockup-dark-1880.png" alt="PinkGlasses — external attack surface, continuously watched." width="620">
</p>

A self-hosted external attack-surface scanner: a Go control plane, a React SPA,
and a fleet of workers you own — including VPS boxes you enrol from the UI.

This wiki covers how the scanner behaves in practice. For getting it running,
see the [README](https://github.com/cobbbex/PinkGlasses#readme); for the design
rationale, [Architecture](Architecture).

## Pages

- **[Accounts and access](Accounts-and-Access)** — the three roles and where the
  boundaries fall, why sessions are server-side, how API tokens are scoped, and
  how to put an identity provider in front.
- **[Port scanning](Port-Scanning)** — which scanner runs when, the exact nmap
  and naabu command lines, every setting you can change, and what the defaults
  cost you in noise and accuracy.
- **Alerts** — per-company Slack or JSON webhooks, fed one digest per scan with the
  changes each channel asked for; every delivery attempt is recorded.
- **[Workers and containers](Workers-and-Containers)** — what a worker is as
  opposed to a Docker container, and how an active scan travels through the VPN
  gateway, step by step, with pictures.
- **[Passive discovery sources](Passive-Sources)** — every subfinder source that
  takes an API key, in the order of `.env.example`, with the link to get each key.
- **[Where scans run from](VPN-Scanning)** — passive stages on the standing
  workers, active stages from a chosen exit: an ephemeral fleet behind a VPN
  gateway, or a pool of remote workers. Why the privilege is not in the worker,
  why routing is per task, and what happens when the tunnel drops.
- **[API](API)** — every route the server serves, grouped by the role it needs,
  with request and response shapes; kept in step with the code by a test.
- **[Wordlists](Wordlists)** — the three kinds of list, how a run picks them,
  how they reach a worker, and which one decides how loud a scan is.

## The pipeline in one picture

```
subdomains ─┬─────────────────┐
            └─ dns bruteforce ┴→ dns resolve ─→ [new addresses, deduped]
                                                  → port scan (batched, 64/task)
                                                         → service probe
                                                              ├─ tech detect
                                                              ├─ screenshot
                                                              ├─ directory brute
                                                              └─ vulnerability check
```

| Stage | Primary tool | Fallback |
|---|---|---|
| Subdomains | subfinder | stdlib resolver |
| DNS bruteforce | shuffledns + massdns | skipped |
| Resolution & enrichment | dnsx, Team Cymru | stdlib resolver |
| Ports & services | **nmap -sV** alone at top-100; naabu → nmap when wider | Go connect scan |
| Tech & versions | httpx `-tech-detect`, cookie names | header/body fingerprint |
| Screenshots | httpx `-screenshot` | needs the `browser` capability |
| Directory brute | katana, urlfinder → gobuster/ffuf | built-in common-path probe |
| Vulnerabilities | nuclei, default templates, severity low and up; findings `nuclei:<template-id>` | skipped |

Every tool invocation is logged with its result count and duration; a tool that
exits cleanly while producing nothing and complaining on stderr is reported as
a failure; and a batch of results the gateway refuses is logged by both ends
with the reason. That class of silent breakage — the stage runs, the results
evaporate — has cost real debugging time here, and each of those three checks
was added after it had already happened.

## Scheduled scans

The Start-a-scan dialog runs a scan now, once at a chosen time, or on a repeat
from hourly to yearly, with the same profile, exit and settings either way. A
schedule starts its runs through the same code the button uses — so it is refused
for the same reasons, and the refusal is shown on the schedule rather than lost
in a log. A run still going when the next is due is skipped, never stacked; a
one-off disables itself once it has started. Runs can be paused (nothing more is
leased, in-flight tasks finish, the fleet stays up), resumed, stopped and rerun
with the same choices; a finished run can be deleted with everything it recorded,
its screenshots included. See the README's *Scheduled scans* and *Watching a scan*,
and [Architecture](Architecture) §3.3.

## Who can do what

Every endpoint needs a signed-in session or an API token; three ordered roles
decide the rest. Starting a scan needs **operator**, because it sends packets at
somebody else's infrastructure; managing accounts, workers and VPN
configurations needs **admin**, because each hands out a credential, and so does
deleting a company, because that takes its whole inventory and history with it.
See [Accounts and access](Accounts-and-Access).

## Target authorization

Targets come in **groups**: what one *Add targets* on the Dashboard produced, a
name and its list of domains, IPs and CIDRs. A scan picks groups; a schedule
remembers groups and expands them when each run starts, so editing a group later
changes what its scheduled runs cover. The same entry may sit in several groups
and is scanned once.

A target is **passive-only** unless it carries an explicit active authorization,
recorded with who gave it and when — the tick on the group's form applies it to
every entry. Only addresses belonging to an authorized target are port scanned;
everything else is enumerated and resolved but never probed. An entry in several
groups counts as authorized if any of them authorizes it, and as excluded if any
excludes it. RFC1918 and loopback targets are rejected outright.

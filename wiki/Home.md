<p align="center">
  <img src="https://raw.githubusercontent.com/cobbbex/PinkGlasses/main/assets/brand/lockup-dark-1880.png" alt="PinkGlasses — external attack surface, continuously watched." width="620">
</p>

A self-hosted external attack-surface scanner: a Go control plane, a React SPA,
and a fleet of workers you own — including VPS boxes you enrol from the UI.

This wiki covers how the scanner behaves in practice. For getting it running,
see the [README](https://github.com/cobbbex/PinkGlasses#readme); for the design
rationale, `architecture.md` in the repository.

## Pages

- **[Accounts and access](Accounts-and-Access)** — the three roles and where the
  boundaries fall, why sessions are server-side, how API tokens are scoped, and
  how to put an identity provider in front.
- **[Port scanning](Port-Scanning)** — which scanner runs when, the exact nmap
  and naabu command lines, every setting you can change, and what the defaults
  cost you in noise and accuracy.
- **Alerts** — per-company Slack or JSON webhooks, fed one digest per scan with the
  changes each channel asked for; every delivery attempt is recorded.
- **[Scanning through a VPN](VPN-Scanning)** — how a run gets its own tunnel: a
  gateway container the run's workers share a network namespace with, why the
  privilege is not in the worker, and what happens when the tunnel drops.
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
                                                              └─ directory brute
```

| Stage | Primary tool | Fallback |
|---|---|---|
| Subdomains | subfinder | stdlib resolver |
| DNS bruteforce | shuffledns + massdns | skipped |
| Resolution & enrichment | dnsx, Team Cymru | stdlib resolver |
| Ports & services | **nmap -sV** alone at top-100; naabu → nmap when wider | Go connect scan |
| Tech & versions | httpx `-tech-detect`, nuclei, cookie names | header/body fingerprint |
| Screenshots | httpx `-screenshot` | needs the `browser` capability |
| Directory brute | katana, urlfinder → gobuster/ffuf | built-in common-path probe |

Every tool invocation is logged with its result count and duration; a tool that
exits cleanly while producing nothing and complaining on stderr is reported as
a failure; and a batch of results the gateway refuses is logged by both ends
with the reason. That class of silent breakage — the stage runs, the results
evaporate — has cost real debugging time here, and each of those three checks
was added after it had already happened.

## Who can do what

Every endpoint needs a signed-in session or an API token; three ordered roles
decide the rest. Starting a scan needs **operator**, because it sends packets at
somebody else's infrastructure; managing accounts, workers and VPN
configurations needs **admin**, because each hands out a credential. See
[Accounts and access](Accounts-and-Access).

## Target authorization

A target is **passive-only** unless it carries an explicit active
authorization. Only addresses belonging to an authorized target are port
scanned; everything else is enumerated and resolved but never probed. RFC1918
and loopback targets are rejected outright.

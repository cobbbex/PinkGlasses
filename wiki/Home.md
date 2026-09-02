<p align="center">
  <img src="https://raw.githubusercontent.com/cobbbex/PinkGlasses/main/assets/brand/lockup-dark-1880.png" alt="PinkGlasses — external attack surface, continuously watched." width="620">
</p>

A self-hosted external attack-surface scanner: a Go control plane, a React SPA,
and a fleet of workers you own — including VPS boxes you enrol from the UI.

This wiki covers how the scanner behaves in practice. For getting it running,
see the [README](https://github.com/cobbbex/PinkGlasses#readme); for the design
rationale, `architecture.md` in the repository.

## Pages

- **[Port scanning](Port-Scanning)** — which scanner runs when, the exact nmap
  and naabu command lines, every setting you can change, and what the defaults
  cost you in noise and accuracy.

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
| Ports & services | naabu → **nmap -sV** | Go connect scan |
| Tech & versions | httpx `-tech-detect`, nuclei | header/body fingerprint |
| Screenshots | httpx `-screenshot` | needs the `browser` capability |
| Directory brute | katana, urlfinder → gobuster/ffuf | built-in common-path probe |

Every tool invocation is logged with its result count and duration, and a tool
that exits cleanly while producing nothing and complaining on stderr is
reported as a failure — that class of silent breakage has cost real debugging
time here.

## Authorization

A target is **passive-only** unless it carries an explicit active
authorization. Only addresses belonging to an authorized target are port
scanned; everything else is enumerated and resolved but never probed. RFC1918
and loopback targets are rejected outright.

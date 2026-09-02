# Port scanning

How PinkGlasses turns a list of resolved addresses into open ports and service
versions: which scanner runs, with exactly which flags, and which of them you
can change per run.

Everything below is what the worker actually executes — the command lines are
the logged invocations, not a reconstruction of the source.

## What runs, and when

Port scanning is one stage of the pipeline, and it never sees a name — only
addresses that DNS resolution has already produced.

```
subdomains ─┬─────────────────┐
            └─ dns bruteforce ┴→ dns resolve ─→ [new addresses, deduped]
                                                  → port scan → service probe
```

Two things happen before nmap is invoked at all:

- **Addresses are batched.** Up to 64 go into one task and are handed to the
  scanner as a host pool on stdin. One address per task would make
  `--min-hostgroup` and `--min-rate` meaningless and pay process startup per
  host.
- **Authorization is checked.** Each address is resolved back to the scope
  target that produced it, and addresses from passive-only targets are dropped.
  A name discovered under passive authorization is enumerated and resolved, but
  never has a packet sent to it. The scheduler log says so explicitly when it
  happens.

Which scanner runs then depends on how wide the port selection is:

| `ports` setting | Scanner |
|---|---|
| `top-100` (default) | **nmap alone** |
| `top-1000`, `full`, an explicit range (`1-1024`) or list (`80,443`) | **naabu sweep, then nmap** on what it found |
| any setting, on the `deep` profile | **naabu sweep, then nmap** with `-A` |

At top-100 width nmap is fast enough on its own and returns service versions in
the same pass, so a separate discovery sweep adds nothing. For anything wider,
naabu finds open ports far faster than nmap over a large range, and nmap is
then asked only about the ports that answered.

If neither binary is installed the worker falls back to a pure-Go connect scan
over a short built-in port list, so a bare worker still contributes something.

## The default scan

This is the standard profile at `top-100` — the common case:

```
nmap -Pn --open --min-hostgroup 64 --min-rate 10000 --max-retries 3 \
     --defeat-rst-ratelimit -T4 --top-ports 100 -sV --version-intensity 7 \
     -oG - -iL -
```

| Flag | Why | Tunable |
|---|---|---|
| `-Pn` | no ping sweep — every address is treated as up | no |
| `--open` | report only open ports | no |
| `--min-hostgroup 64` | matches the 64-address batch, so the pool scans as one group | no |
| `--min-rate 10000` | floor on packets per second | `nmap_min_rate` |
| `--max-retries 3` | probe retransmissions per port | `nmap_max_retries` |
| `--defeat-rst-ratelimit` | don't wait on hosts that rate-limit RSTs | no |
| `-T4` | timing template | `nmap_timing` |
| `--top-ports 100` | port selection | `ports` |
| `-sV` | service and version detection | no (see `deep`) |
| `--version-intensity 7` | how hard nmap works to identify a service | `nmap_version_intensity` |
| `-oG -` | greppable output on stdout | no |
| `-iL -` | **the host pool, on stdin** | no |

## The wide scan

For `top-1000`, `full`, an explicit range, or the `deep` profile, naabu sweeps
first:

```
naabu -silent -json -c 4 -rate 20 -timeout 1000 -retries 1 <port selection>
```

with the port selection being `-top-ports 1000`, `-p -` (full), or `-p <range>`,
and the host pool again on stdin. Without `CAP_NET_RAW` the worker adds
`-scan-type c` for a connect scan.

nmap then fingerprints only the union of ports naabu found open across the
pool, so `--top-ports 100` above is replaced by an explicit list:

```
nmap -Pn --open --min-hostgroup 64 --min-rate 10000 --max-retries 3 \
     --defeat-rst-ratelimit -T4 -p 22,80,443 -sV --version-intensity 7 \
     -oG - -iL -
```

`--open` means each host reports only the ports actually open on it, so
scanning the union across the whole pool costs very little.

On the `deep` profile `-sV` is replaced by `-A -vvv`, and the nmap timeout goes
from 20 minutes to 60.

## Settings

All per-run, in the scan settings panel. Values are validated against a
whitelist before they ever reach a command line.

| Key | Default | Range | Effect |
|---|---|---|---|
| `ports` | `top-100` | `top-100`, `top-1000`, `full`, `1-1024`, `80,443` | port selection, and which scanner runs |
| `nmap_min_rate` | `10000` | 100–50000 | `--min-rate` |
| `nmap_timing` | `T4` | `T0`–`T5` | timing template |
| `nmap_version_intensity` | `7` | 0–9 | 9 tries every probe, 0 only the likeliest |
| `nmap_max_retries` | `3` | 0–10 | probe retransmissions |
| `naabu_rate` | `20` | 1–1000 | packets per second for the sweep |
| `naabu_concurrency` | `4` | 1–64 | parallel hosts in the sweep |
| `naabu_timeout_ms` | `1000` | 100–10000 | how long to wait for a port to answer |
| `naabu_retries` | `1` | — | sweep retries |

## Three things worth knowing

**The scan type is implicit.** There is no `-sS` or `-sT` in the arguments, so
nmap decides for itself. The bundled worker runs as root with `NET_RAW`, so you
get a **SYN scan**. Remove that capability and the same flags silently become a
connect scan, with a different footprint and different results on filtered
ports.

**The defaults are loud.** `--min-rate 10000` is a floor, not a cap, and with
`-Pn` every one of the 100 ports is probed on every address whether or not
anything is listening. That is fine against a host that invites it; it is worth
lowering before pointing the scanner at a client perimeter, especially from a
VPS whose provider may suspend the account over unsolicited scanning.

**`--defeat-rst-ratelimit` trades accuracy for speed.** Against a host that
rate-limits RSTs, nmap stops waiting — which can report closed ports as
filtered, or miss them. It is the right default for breadth, and it is one
reason a port can appear in one run and not the next.

## A worked example

`scanme.nmap.org`, standard profile, from the worker log:

```
queued port scans    addresses=2 tasks=1
tool finished  tool=nmap args="-Pn --open --min-hostgroup 64 --min-rate 10000
               --max-retries 3 --defeat-rst-ratelimit -T4 --top-ports 100 -sV
               --version-intensity 7 -oG - -iL -" results=4 took=8.936s ok=true
port scan      hosts=2 with_open_ports=1 open=2 scanner=nmap ports="--top-ports 100"
```

Both addresses (A and AAAA) went to nmap as a single host group, and the result
was:

| Port | State | Product | Version |
|---|---|---|---|
| 22/tcp | open | OpenSSH | 6.6.1p1 |
| 80/tcp | open | Apache httpd | 2.4.7 |

Set `ASM_LOG_LEVEL=debug` to see each tool's command line before it runs, plus
every individual port behind these summaries.

## Where this lives in the code

| File | What |
|---|---|
| `internal/scanner/stage_ports.go` | scanner selection, both command lines, greppable parsing |
| `internal/scanparams/scanparams.go` | the settable knobs, their defaults and validation |
| `internal/planner/planner.go` | address batching and the authorization gate |

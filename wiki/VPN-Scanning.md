# Where scans run from

Every scan has two kinds of work, and they leave your network by different
doors. This page is about the door for the work that touches the target.

## The split

| Stage class | Stages | Who sees the traffic | Runs on |
|---|---|---|---|
| **Passive** | `passive_enum`, `dns_brute`, `dns_resolve`, `ip_enrich` | third-party APIs and public resolvers — never the target | the standing local workers |
| **Active** | `port_scan`, `service_probe`, `tech_detect`, `screenshot`, `dir_brute`, `vuln_check` | **the target** | the run's chosen **exit** |

Passive stages talk to Shodan, crt.sh and forty other sources using your API
keys; the target never sees them. They always run on the standing local pool,
so discovery for any run starts at once — even a run whose tunnel is still
coming up. Set `ASM_PASSIVE_PROXY` (http or socks5) to put one hop in front of
subfinder's API calls; DNS stages speak UDP and cannot use an HTTP proxy.

Active stages send packets at the target, so the launch dialog asks where they
should leave from, and a run cannot be created without an answer:

- **Local workers behind a VPN.** The run brings up its own workers and a
  gateway container holding the tunnel; the workers share the gateway's network
  namespace. Everything is destroyed when the run ends. **Requires a VPN
  configuration** — a company with none cannot start a local active scan.
- **Remote workers.** An existing pool of workers you enrolled — a VPS. The scan
  leaves from their addresses.

There is deliberately **no "direct from this host"**. An active scan always
leaves from an address somebody chose. A passive-profile run has no active
stages and needs no exit.

## Why the tunnel is not in the worker

The straightforward way is to give the worker `NET_ADMIN` and `/dev/net/tun`
and let it raise the tunnel itself. PinkGlasses did that first, and it was wrong
for three reasons.

**It puts privilege in the worst container.** The worker runs nmap, chromium,
nuclei, gobuster and katana over output controlled by whatever it is scanning.
It is, by a wide margin, the container most likely to be exploited — and it is
the one that had just been given the ability to reconfigure networking.

**Every worker becomes a separate chance to fail open.** Each raises its own
tunnel; each verification is another place the check can be skipped.

**Three components had to agree on who owned the tunnel** — the planner, the
dispatcher and the worker — and when they disagreed you got tasks demanding a
capability nothing reported, which is a scan that never moves. That happened.

So: one **gateway container** per run raises the tunnel. It holds `NET_ADMIN`
and `/dev/net/tun`, runs one small binary, parses no attacker input, and makes
no outbound request of its own. The workers share its namespace — routing
without capability. The old path is gone, not disabled: `attachVPN`, the
`/agent/v1/vpn-config` route, `ensureTunnel`, the `vpn` capability and the
`worker-vpn` service were all removed, because code that looks alive is how this
repository gets bitten.

```
             ┌──────────────────────────────────────────┐
  scheduler  │  pinkglasses-vpn-<run>                   │
      │      │  vpngw: openvpn/wg → tun0, default route │
      │ 1    │  NET_ADMIN, /dev/net/tun                 │
      ▼      │  healthy only once egress != base        │
 provisioner └──────────────────────────────────────────┘
      │ 2               ▲ network_mode: container:<gw>
      │        ┌────────┴────────┬─────────────────┐
      └───────►│ run worker 0    │ run worker 1    │  no NET_ADMIN
               │ nmap, chromium  │ nuclei, httpx…  │  no /dev/net/tun
               └─────────────────┴─────────────────┘  no routes to change
                        │ 3  enrol into this run's own pool
                        ▼
                     gateway ── leases only this run's active tasks
```

## The guarantees

**A worker cannot exist outside the tunnel.** Workers are created only after
the gateway reports healthy to Docker, and its healthcheck passes only once its
observed public address differs from the one it recorded before connecting. Not
"the client said it connected" — the address actually changed. If it never
does, no worker is started, the containers are removed, and the run fails with
the gateway's last log lines.

**Routing is per task and the lease is strict.** `scan_task.pool_id` is set by
the planner from the stage class, and a worker leases a task only when
`task.pool_id = worker.pool_id`. A run's active tasks are leased only by its own
fleet or its chosen remote pool; a fleet worker cannot pick up anyone else's.
The previous filter allowed `r.pool_id IS NULL` for any worker — so an idle
fleet worker inside a VPN gateway's namespace could lease an unrelated run's
task and scan it *through the tunnel*. Standing workers could not take fleet
work, but fleet workers could take standing work. Strict equality closes both
directions; a task with no pool matches nothing.

**A dropped tunnel fails the run rather than hanging it.** Workers sharing a
dead gateway's namespace lose every route, including the one back to the
control plane, so they cannot report their own failure. The scheduler watches: a
fleet with no live worker for two minutes fails its run and says why.

## Lifecycle

The API records only the intent. The scheduler builds, supervises and tears
down, because the containers have to come down when the run ends whatever
happened to the process that asked for them.

| State | Meaning |
|---|---|
| `requested` | Pool and token exist; no containers yet. If over the ceiling, the reason is shown here |
| `up` | Containers running, egress address recorded |
| `failed` | Could not be built, or lost its workers — the run fails with the same reason |
| `torn_down` | Containers, worker rows and pool removed |

At most `ASM_MAX_RUN_FLEETS` runs (default 3) hold containers at once. A run over
the ceiling **waits**: its passive stages run meanwhile on the standing pool, its
active tasks sit pending on a pool nothing else can lease from, and the run view
says *"Waiting to start a VPN gateway and 2 workers: waiting for a slot: 3 of 3
runs already hold their own workers"*. It is built when a slot frees.

Teardown keeps attribution: a worker's name and kind are stamped on each task
when it is leased, so a finished run still says which worker ran what.
Containers whose run ended while the control plane was down are collected by an
orphan sweep at startup and every five minutes.

## Remote pools

Same routing, no build step. The run binds its active tasks to a pool that is
not run-scoped and has at least one active worker. The API refuses an empty pool
rather than binding to it — a run bound to a pool with no members never moves,
and nothing else can rescue it. Enrol a VPS under **Workers → Add VPS worker**
with the pool chosen on the token; approve it; it appears in the launch dialog.

## Limits and settings

| | |
|---|---|
| Workers per local run | 8 (`maxFleetWorkers`), and the provisioner's `ASM_PROVISIONER_MAX_WORKERS` on top |
| Concurrent fleets | `ASM_MAX_RUN_FLEETS`, default 3; excess runs wait |
| Gateway startup budget | 90 s to report a changed address |
| Dead-fleet grace | 2 minutes with no live worker |
| Passive proxy | `ASM_PASSIVE_PROXY`, http or socks5, on the worker |

The scheduler needs `ASM_PROVISIONER_URL`, `ASM_PROVISIONER_TOKEN` and
`ASM_SECRET_KEY` — it opens the sealed config to hand it to the gateway. With no
provisioner configured, a local exit is refused with a message that names the
two variables; remote exits still work.

## When it does not come up

| Message | Cause |
|---|---|
| `scanning from local workers needs a VPN … this company has no VPN configuration yet` | Add one under **VPN**, or choose a remote pool |
| `pool "x" has no active worker to run this scan` | Enrol or approve a worker in that pool |
| `the VPN gateway did not report a working tunnel within 90s` | Endpoint unreachable, or wrong credentials |
| `…stopped before its tunnel came up: …` | The tail is openvpn's or wg's own error — read it literally |
| `the VPN configuration could not be decrypted` | `ASM_SECRET_KEY` differs from the one it was stored under |
| `this run's own workers stopped reporting for 2m0s` | The tunnel dropped mid-scan |

A WireGuard config whose `AllowedIPs` carries no default route is rejected at
upload. `wg-quick` is deliberately not used — it needs a sysctl a container's
read-only `/proc/sys` refuses — so the gateway drives `ip` and `wg` directly.

## What is stored

Config bodies are sealed with AES-256-GCM under `ASM_SECRET_KEY`, are never
returned by any API endpoint, and are never written to a log. What you can see
is the name, the kind, the endpoint host, and the egress address a gateway last
observed through it — which says where your scans actually came from.

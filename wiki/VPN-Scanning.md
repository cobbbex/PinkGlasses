# Scanning through a VPN

Upload an OpenVPN `.ovpn` or WireGuard `.conf` under **VPN configs**, pick it in the
scan-launch dialog under **Scan from**, and everything that run sends at a target leaves
through that tunnel.

What happens underneath is the interesting part, because the obvious implementation is the
wrong one.

## The obvious implementation, and why it is not this one

The straightforward way is to give the worker container `NET_ADMIN` and `/dev/net/tun`,
hand it the config, and let it raise the tunnel before it scans. PinkGlasses did that
first. Three things are wrong with it.

**It puts privilege in the worst container.** The worker runs nmap, chromium, nuclei,
gobuster and katana over output controlled by whatever it is scanning. It is, by a wide
margin, the container most likely to be exploited — and it is the one you have just given
the ability to reconfigure networking.

**The tunnel becomes a property of a worker rather than of the run.** Every worker raises
its own tunnel and every one of those is a separate chance to fail open. Verification has
to happen N times instead of once.

**It splits the decision across components.** The planner has to mark which tasks need a
tunnel, the dispatcher has to attach the config, and the worker has to decide whether to
build one. When those three disagree you get tasks demanding a capability nothing reports,
which is a scan that never moves — and that is exactly what happened here.

## What it does instead

One **gateway container** per run raises the tunnel. The run's workers share its network
namespace.

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
                     gateway ── leases only this run's tasks
```

Sharing a namespace is not a capability grant. The workers get the tunnel's routing and
none of its privilege; the container holding `NET_ADMIN` runs one small binary, parses no
attacker-controlled input, and makes no outbound request of its own.

## The three guarantees

**A worker cannot exist outside the tunnel.** Workers are created only after the gateway
reports healthy to Docker, and its healthcheck passes only once its observed public
address differs from the one it recorded before connecting. Not "the client said it
connected" — the address actually changed. If it never does, no worker is started, the
containers are removed, and the run fails with the gateway's last log lines.

**No other worker can take the run's work.** The run is bound to a pool created for it
alone, and the enrolment token its workers use is bound to that pool. Standing workers
cannot lease the run's tasks. There is no path by which one of this run's tasks executes
somewhere that is not behind the tunnel.

**A dropped tunnel fails the run rather than hanging it.** Workers sharing a dead
gateway's namespace lose every route, including the one back to the control plane, so they
cannot report their own failure — silence is the only symptom. The scheduler watches for
it: a fleet with no live worker for two minutes fails its run and says why.

## Who owns the tunnel

Three components must agree, so they read one fact — whether the run has a fleet:

| | Run with a fleet | Run with a VPN but no fleet |
|---|---|---|
| Planner | no `vpn` requirement | traffic tasks require `vpn` |
| Dispatcher | no config on the job | config id attached to the job |
| Worker | builds nothing | fetches the config, raises the tunnel |

All three fail **closed** if they cannot read it. A wrong "no fleet" stalls tasks visibly;
a wrong "has fleet" would scan from your own address, which is the one outcome worth
avoiding.

## Lifecycle

The API records only the intent. The scheduler does the work, because the containers have
to come down when the run ends whatever happened to the process that asked for them.

| State | Meaning |
|---|---|
| `requested` | The pool and token exist; no containers yet |
| `up` | Containers running, egress address recorded |
| `failed` | Could not be built, or lost its workers — the run fails with the same reason |
| `torn_down` | Containers, worker rows and pool removed |

Teardown does not lose attribution: a worker's name and kind are stamped on each task when
it is leased, so a finished run still says which worker ran what long after the container
is gone. Containers whose run ended while the control plane was down are collected by an
orphan sweep at startup and every five minutes.

## Without a VPN

The same machinery gives a run its own workers with no tunnel at all — the checkbox in the
launch dialog. Useful when a long scan should not occupy the standing fleet, and it is the
cheaper thing to test when something looks wrong: if a run with its own workers succeeds
and the same run through a VPN does not, the problem is the tunnel and not the fleet.

## Limits and settings

| | |
|---|---|
| Workers per run | 8 (`maxFleetWorkers`), and the provisioner's `ASM_PROVISIONER_MAX_WORKERS` on top |
| Concurrent fleets | `ASM_MAX_RUN_FLEETS`, default 3 |
| Gateway startup budget | 90s to report a changed address |
| Dead-fleet grace | 2 minutes with no live worker |

A run that arrives over the fleet limit is **failed with the reason**, not queued: its
tasks are bound to a pool that has no members, so nothing else can make progress on them.

The scheduler needs `ASM_PROVISIONER_URL`, `ASM_PROVISIONER_TOKEN` and `ASM_SECRET_KEY` —
it opens the sealed config to hand it to the gateway. With no provisioner configured the
feature is off, and runs that ask for a fleet fail saying so.

## When it does not come up

| Message | Cause |
|---|---|
| `the VPN gateway did not report a working tunnel within 90s` | Endpoint unreachable, or wrong credentials |
| `…stopped before its tunnel came up: …` | The tail is openvpn's or wg's own error — read it literally |
| `the VPN configuration could not be decrypted` | `ASM_SECRET_KEY` differs from the one it was stored under |
| `the provisioner is unreachable` | Provisioner settings missing on the **scheduler**, not just the api |
| `this run's own workers stopped reporting for 2m0s` | The tunnel dropped mid-scan |

A WireGuard config whose `AllowedIPs` carries no default route is rejected at upload. A
tunnel that routes nothing is worse than no tunnel, because it looks like one.

`wg-quick` is deliberately not used: it sets `net.ipv4.conf.all.src_valid_mark`, which
cannot be written in a container with a read-only `/proc/sys`, and it fails the whole
tunnel over it. The gateway drives `ip` and `wg` directly instead.

## What is stored

Config bodies are sealed with AES-256-GCM under `ASM_SECRET_KEY`, are never returned by
any API endpoint, and are never written to a log. What you can see is the name, the kind,
the endpoint host, and the egress address a gateway last observed through it — which is
the thing you actually want, since it says where your scans came from.

# Workers, containers, and how a scan goes through the VPN

Two words in this project describe different layers and are easy to mix up.
This page takes them one at a time, then puts them together in the picture of a
real VPN scan. For the design rationale see [Architecture](Architecture) §7; for
the exits a run can choose, [Where scans run from](VPN-Scanning).

## 1. Container versus worker

A **container** is a Docker thing: a running program, isolated, with its own
filesystem and its own network. Docker knows containers. It does not know what
PinkGlasses is.

A **worker** is a PinkGlasses thing: the scanning program (the "agent") *after
it has enrolled with the gateway*. Enrolling gives it a row on the Workers page,
a credential, a heartbeat, and the right to lease tasks. The control plane knows
workers. It never sees containers.

The agent has to run somewhere, and on the machine running the stack that
somewhere is always a container. So each worker lives inside one container,
which makes the two look like the same thing. They are not, and two cases show
it:

```
  Docker sees containers            PinkGlasses sees workers
  ─────────────────────────         ──────────────────────────────
  pinkglasses-worker-1        ───▶  worker "3432220379d1" (local, active)
  pinkglasses-run-a133-0-…    ───▶  worker "pinkglasses-run-a133-0-…" (local, run pool)
  pinkglasses-vpn-a133-0-…    ───▶  (nothing: a gateway is not a worker)
  a box you rent, no container ◀─── worker "remote-vps-1" (vps, remote pool)
```

- The **VPN gateway** is a container but not a worker. It only holds the tunnel;
  it never enrols and never scans.
- A **VPS worker** is a worker but not one of your containers. You installed the
  agent on a box elsewhere and enrolled it under **Workers → Add VPS worker**.

Inside one worker, up to 8 **tasks** run at once (`ASM_WORKER_MAX_CONCURRENCY`),
and that same number is how many the control plane will hand it: the worker
reports it when it enrols and on every heartbeat, so a worker on a small VPS
says a smaller number and is given less. Raise or lower it and restart the
worker; the change arrives on its next heartbeat, without re-enrolling. Held to
1–64; a worker too old to report it gets 8, as before.
So the layering is: one container, one worker, many tasks.

Nobody creates a local worker by hand. The standing one is the `worker` service
in `docker-compose.yml` and enrols itself at boot; a run's own workers are built
and destroyed by the scheduler, below.

## 2. How a scan runs through the VPN

When you start a standard or deep scan and choose **Local workers behind a
VPN**, this happens:

```
  you click Start
       │
       ▼
  api ──▶ PostgreSQL: run row, run_fleet row (wants: VPN config X, N workers)
                                  │
                                  ▼  next scheduler tick
                            scheduler ──▶ provisioner (the only holder of the Docker socket)
                                              │
                    ┌─────────────────────────┴──────────────────────────────┐
                    │ 1. start  vpn-gateway   container                       │
                    │    - has NET_ADMIN and /dev/net/tun                     │
                    │    - reads VPN config X (unsealed only here, in memory)  │
                    │    - brings the tunnel up; all its traffic exits via VPN│
                    │ 2. start  N worker containers with                      │
                    │    network_mode: container:<vpn-gateway>                │
                    │    → they have NO network of their own; they live       │
                    │      inside the gateway's network namespace             │
                    └─────────────────────────────────────────────────────────┘
                                  │
                                  ▼
       each worker enrols ──WSS──▶ gateway   (into this run's own pool)
                                  │
                                  ▼
       worker leases active tasks of THIS run only  (task pool = run's pool)
       worker runs nmap / httpx / nuclei against the target
                  │
                  │  every packet: worker ──▶ gateway's netns ──▶ VPN tunnel ──▶ target
                  │  the target sees the VPN's exit address, never your machine's
                  ▼
       results ──WSS──▶ gateway ──▶ PostgreSQL
                                  │
                                  ▼  run finishes (or you press Stop)
                            scheduler ──▶ provisioner: remove the N workers and the gateway
                            worker rows deleted; tasks keep the worker's name for history
```

N is chosen automatically from the run's targets (one worker, plus one per CIDR
/24-equivalent or per five targets, at most four) unless a number is set under
*Customize scanning → Run workers*. All of a run's workers share one tunnel and
one target, so more of them adds noise at the target and RAM on the host, not
speed.

The two facts that make this safe:

- **The workers have no network of their own.** `network_mode:
  container:<gateway>` means a worker shares the gateway's network namespace, so
  it physically cannot send a packet anywhere except through the gateway, and the
  gateway routes everything into the tunnel. If the tunnel drops, the workers
  lose all connectivity; the scheduler notices they stopped reporting and fails
  the run rather than letting anything leak.
- **Those workers can only take this run's tasks.** They enrol into a pool that
  exists for this run alone, and the lease query matches tasks to pools
  strictly. A fleet behind your VPN can never pick up another run's work, and no
  other worker can pick up this run's.

Meanwhile the **standing local worker** keeps doing the passive stages for the
same run: subfinder, DNS brute force, resolution, ASN enrichment. Those talk to
public sources, never to the target, so they do not need the tunnel and start
immediately, before the fleet is even up. The standing pool is never offered as
an exit for active stages, so no active scan can leave from the control plane's
own address.

## 3. The whole picture at once

```
                          your machine (docker compose)
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  api   gateway   scheduler   provisioner   postgres   minio             │
  │                                                                          │
  │  [worker-1]  standing worker ── passive stages ──▶ public DNS / APIs     │
  │                                                                          │
  │  per active run:                                                         │
  │  ┌─ vpn-gateway ─────────────────────────────┐                           │
  │  │ tunnel ══════════════════════════════════╪═══▶ VPN server ──▶ target │
  │  │  [run worker 0]  [run worker 1]  … ×N    │      (exit IP seen by      │
  │  │   active stages: nmap, httpx, nuclei      │       the target)          │
  │  └───────────────────────────────────────────┘                           │
  └──────────────────────────────────────────────────────────────────────────┘

  elsewhere, optional:   [VPS box]  ── agent enrolled as a remote worker ──▶ target
                                       (the other kind of exit)
```

Every box in square brackets is a worker. Every box drawn is a container,
except the VPS. And no arrow from an active stage ever leaves from your
machine's own address.

## Where to look while it runs

- **Workers** lists every worker the control plane knows: the standing one under
  *Local workers*, a run's own fleet appearing there while the run is going, and
  VPS boxes under *External*.
- A run's row on **Scan runs**, expanded, shows the fleet banner — starting, up
  with the egress address the gateway measured, failed with the reason, or torn
  down — and which worker ran each task.
- `docker ps --format '{{.Names}}' | grep pinkglasses-run-` shows the containers
  behind a live fleet; they are gone within a tick of the run ending.

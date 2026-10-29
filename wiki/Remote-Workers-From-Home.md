# Remote workers for an install at home

A remote worker dials **out** to the gateway: it is given the gateway's
address, connects, and is handed tasks over that connection. An install at
home, behind NAT with no public address, cannot be dialled — nothing on the
internet can open a connection to it. There are two ways around that, and
both keep the one property a remote worker exists for: **scans leave from the
VPS's address, never from yours.**

## What travels where

Only control traffic crosses between the VPS and your install. The tools run
on the VPS, and everything they send goes from the VPS straight to the target.

| Between the VPS and your install | From the VPS straight to the internet |
|---|---|
| task assignments, heartbeats | port scans (nmap, naabu) |
| results: open ports, titles, findings | service probe, tech detection, screenshots |
| wordlist downloads | directory brute force, crawling |
| screenshot uploads | nuclei |

**Discovery** — subdomain sources, DNS brute force, resolution, enrichment —
does not touch a target and by default runs on the standing worker at home,
so its DNS queries leave from your address. To move it to the VPS as well,
tick **Runs discovery** on the `remote` pool under Workers → Pools. It goes
back to the standing worker by itself whenever that pool has no active worker.

## Option 1: an SSH exit (built in)

Your install opens an SSH session to the VPS and asks the VPS's sshd to listen
on its own loopback. Every connection made there is carried back down the
session to your gateway — the same thing `ssh -R` does, held open, reconnected
and watched by the **connector** service.

```
home                                              VPS
gateway:8090 ◀──── SSH session (out from home) ── 127.0.0.1:47090 ◀── worker
minio:9000   ◀────                             ── 127.0.0.1:9000  ◀── (uploads)
```

Nothing at home is published; on the VPS the ports listen on 127.0.0.1 only.

**Needs:** a VPS with Docker, an SSH user that is root or has passwordless
sudo, `AllowTcpForwarding yes` in its sshd_config (the default), and
`ASM_SECRET_KEY` set on your install (the exit's private key is stored
sealed under it).

**Steps**

1. Workers → **SSH exits** → **Add SSH exit**: a name, the VPS's address and
   SSH port, the user. A key pair is generated for the exit (or paste a
   private key you already use — one without a passphrase).
2. Add the public key you are shown to the user's `~/.ssh/authorized_keys` on
   the VPS. The page gives you the one-line command.
3. Within seconds the session shows **connected**, and the VPS's host key is
   pinned. From then on a different host key is refused: a rebuilt VPS means
   deleting the exit and adding it again.
4. **Install worker.** Over the same session the connector mints a single-use
   enrolment token, pulls the worker image on the VPS and starts it with
   `--restart unless-stopped`. The worker enrols already approved, recorded
   with the VPS's address, in the `remote` pool. The install log is kept on
   the exit.
5. Scan with exit **remote**.

**Remove** takes the worker container and its credential off the VPS (when
the session is up), then the exit. The key stays in authorized_keys: delete
that line yourself.

If the session drops, the connector reconnects on its own, backing off up to
a minute. The worker keeps results it could not deliver on disk and sends
them once the tunnel is back, so a drop loses nothing.

**Settings** (on the `connector` service): `ASM_REMOTE_WORKER_IMAGE` — what a
VPS pulls, `ghcr.io/cobbbex/pinkglasses-worker:latest` by default.

## Option 2: a mesh VPN (no code involved)

Put your install and the VPS on one private network — WireGuard, Tailscale,
Headscale, NetBird — and use the ordinary **Add VPS worker** flow:

1. Join both machines to the mesh. Note your machine's mesh address, say
   `100.64.0.1`.
2. Set `ASM_PUBLIC_GATEWAY_URL=http://100.64.0.1:8090` and restart the api, so
   the install command names the address the VPS can reach.
3. Workers → **Add VPS worker**, run the command on the VPS, approve it.

The gateway hands every worker its own way back — results and wordlists go to
the address the worker connected to — so nothing else needs configuring.

**Route only the mesh through the mesh.** If the VPS sends all its traffic
through the VPN (a Tailscale exit node, a WireGuard `AllowedIPs = 0.0.0.0/0`),
scans leave from your home address — exactly what the remote worker was for.
Only the mesh's own range belongs in the tunnel.

Screenshots: workers upload to the object store by its internal name
(`minio:9000`). Over a mesh, publish MinIO on the mesh address and add
`--add-host minio:100.64.0.1` to the worker's `docker run`, or screenshots from
that worker will not upload. An SSH exit carries this for you.

## Which to use

| | SSH exit | Mesh VPN |
|---|---|---|
| Set up | key on the VPS, two clicks | install the mesh on both, one setting |
| Third party | none | none with WireGuard or Headscale; Tailscale's coordination server otherwise |
| Many VPS boxes | one session each | one mesh for all |
| Screenshots | carried | needs the extra step above |
| Worker approval | automatic | by hand |

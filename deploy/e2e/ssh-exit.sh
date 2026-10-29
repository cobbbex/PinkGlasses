#!/usr/bin/env bash
# End to end for SSH exits (wiki/Remote-Workers-From-Home.md), as its own
# compose project so a real install is untouched:
#   - a "VPS" (Docker-in-Docker with sshd) on a network with no route to the
#     gateway, so a worker there can only reach it through the exit's session;
#   - a target only the VPS can reach, so finding it proves the scan left
#     from the VPS;
#   - add the exit, authorize its key, install the worker over the session,
#     check it enrolled approved with the VPS's address, scan, remove.
#
#   deploy/e2e/ssh-exit.sh       # pulls the published worker image on the "VPS"
set -euo pipefail
cd "$(dirname "$0")/../.."
cleanup() {
  docker rm -f sshlab-vps sshlab-target >/dev/null 2>&1 || true
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm sshlab-net >/dev/null 2>&1 || true
  rm -f "$JAR"
}
P=pinkglasses-sshlab
export E2E_ADMIN_PASSWORD=sshlab-admin-not-secret
export ASM_SECRET_KEY=$(openssl rand -base64 32)
export ASM_API_PUBLISH=127.0.0.1:18080 ASM_GATEWAY_PUBLISH=127.0.0.1:18091
export ASM_MINIO_PUBLISH=127.0.0.1:19000 ASM_MINIO_CONSOLE_PUBLISH=127.0.0.1:19001
DC=(docker compose -p $P -f docker-compose.yml -f deploy/e2e/docker-compose.e2e.yml)
API=http://127.0.0.1:18080/api/v1
JAR=$(mktemp)
trap cleanup EXIT
say() { printf '\n=== %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*"; "${DC[@]}" logs --tail 40 connector gateway 2>&1 | tail -n 60; exit 1; }
api() { if [ $# -ge 3 ]; then curl -sS -b $JAR -c $JAR -X $1 $API$2 -H 'Content-Type: application/json' -d "$3";
        else curl -sS -b $JAR -c $JAR -X $1 $API$2; fi; }
py() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }

say "stack"
"${DC[@]}" up -d --build postgres minio migrate api gateway scheduler worker connector >/dev/null 2>&1
for i in $(seq 1 90); do curl -sf http://127.0.0.1:18080/healthz >/dev/null && break; sleep 2; done
api POST /auth/login "{\"username\":\"admin\",\"password\":\"$E2E_ADMIN_PASSWORD\"}" >/dev/null

say "a VPS on its own network, and a target only it can reach"
docker network create sshlab-net >/dev/null 2>&1 || true
docker rm -f sshlab-vps sshlab-target >/dev/null 2>&1 || true
docker run -d --name sshlab-target --network sshlab-net nginx:alpine >/dev/null
docker run -d --name sshlab-vps --privileged --network sshlab-net docker:27-dind >/dev/null
docker exec sshlab-vps sh -c 'apk add -q -U --upgrade openssh openssh-client >/dev/null && ssh-keygen -A >/dev/null && mkdir -p /root/.ssh && chmod 700 /root/.ssh &&
  sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/; s/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/" /etc/ssh/sshd_config &&
  passwd -u root >/dev/null 2>&1; /usr/sbin/sshd'
docker network connect sshlab-net $("${DC[@]}" ps -q connector)
VPS=$(docker inspect sshlab-vps -f '{{(index .NetworkSettings.Networks "sshlab-net").IPAddress}}')
TARGET=$(docker inspect sshlab-target -f '{{(index .NetworkSettings.Networks "sshlab-net").IPAddress}}')
echo "vps $VPS  target $TARGET"
docker exec sshlab-vps sh -c "wget -q -T 3 -O- http://gateway:8090/healthz" >/dev/null 2>&1 \
  && fail "the VPS can reach the gateway directly; the test would prove nothing" \
  || echo "OK: the VPS has no route to the gateway"

say "add the exit; authorize its key on the VPS"
EXIT=$(api POST /ssh-exits "{\"name\":\"lab-vps\",\"host\":\"$VPS\",\"username\":\"root\"}")
EID=$(echo "$EXIT" | py "d['id']") || fail "create refused: $EXIT"
PUB=$(echo "$EXIT" | py "d['public_key']")
docker exec sshlab-vps sh -c "echo '$PUB' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
for i in $(seq 1 30); do
  ST=$(api GET /ssh-exits | py "next(e['status'] for e in d['exits'] if e['id']=='$EID')")
  [ "$ST" = connected ] && break; sleep 2
done
[ "$ST" = connected ] || fail "session never came up: $(api GET /ssh-exits)"
api GET /ssh-exits | py "next(f\"OK: connected, host key {e['host_key']}, reached {e['remote_addr']}\" for e in d['exits'])"

say "install the worker over the session (pulls the worker image on the VPS)"
until docker exec sshlab-vps docker info >/dev/null 2>&1; do sleep 2; done
api POST /ssh-exits/$EID/install >/dev/null
for i in $(seq 1 180); do
  IS=$(api GET /ssh-exits | py "next(e['install_status'] for e in d['exits'] if e['id']=='$EID')")
  case $IS in done|failed) break;; esac; sleep 5
done
api GET /ssh-exits | py "next(e['install_log'] for e in d['exits'])" | tail -n 8
[ "$IS" = done ] || fail "install $IS"

say "the worker enrols, approved, with the VPS's address"
for i in $(seq 1 40); do
  W=$(api GET /workers | py "next((f\"{w['status']} {w.get('egress_ip')}\" for w in d if w['name']=='lab-vps'), '')")
  case "$W" in active*) break;; esac; sleep 3
done
echo "worker: $W"
[ "$W" = "active $VPS" ] || fail "expected 'active $VPS', got '$W'"

say "scan the target only the VPS can reach"
POOL=$(api GET /pools | py "next(p['id'] for p in d if p['name']=='remote')")
SCOPE=$(api POST /scopes '{"name":"sshlab"}' | py "d['id']")
api POST /scopes/$SCOPE/target-groups "{\"name\":\"t\",\"values\":[\"$TARGET\"],\"authorize\":true,\"mode\":\"active\"}" >/dev/null
RUN=$(api POST /scopes/$SCOPE/runs "{\"profile\":\"standard\",\"all\":true,\"exit\":\"remote\",\"pool_id\":\"$POOL\",
  \"params\":{\"subfinder_enabled\":\"false\",\"dns_bruteforce\":\"false\",\"gobuster_enabled\":\"false\",
  \"katana_enabled\":\"false\",\"nuclei_enabled\":\"false\",\"ports\":\"80,443\"}}" | py "d['id']")
for i in $(seq 1 120); do
  S=$(api GET /runs/$RUN | py "d['run']['status']")
  case $S in completed|failed|cancelled) break;; esac; sleep 5
done
echo "run $S"
api GET "/scopes/$SCOPE/search?q=*" | py "'\n'.join(f\"  {r['ip']} {r['port']} {r.get('product') or '-'}\" for r in (d or []))"
api GET "/scopes/$SCOPE/search?q=*" | py "any(r['port']==80 for r in (d or []))" | grep -q True \
  && echo "OK: port 80 found on a target only the VPS can reach" || fail "the scan did not find the target"

say "remove the exit: the worker leaves the VPS"
api DELETE /ssh-exits/$EID >/dev/null
for i in $(seq 1 30); do
  N=$(api GET /ssh-exits | py "len(d['exits'])"); [ "$N" = 0 ] && break; sleep 2
done
docker exec sshlab-vps docker ps -a --format '{{.Names}}' | grep -q pinkglasses-worker \
  && fail "the worker container is still on the VPS" || echo "OK: exit gone, worker container removed from the VPS"
printf '\n=== SSH exit live test passed\n'

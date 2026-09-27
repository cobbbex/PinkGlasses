#!/usr/bin/env bash
# End to end: bring the stack up, enrol a worker, scan a web server running
# beside it, and check the run found what it should.
#
# It exercises what unit tests cannot: migrations, the worker's enrolment and
# approval, the dispatcher handing out tasks, a real port scan and service
# probe, and ingest writing what they found.
#
# Runs as its own compose project with its own volumes, so a real install on
# the same machine is untouched.
#
#   deploy/e2e/run.sh            # build, run, tear down
#   E2E_KEEP=1 deploy/e2e/run.sh # leave it running to look at
set -euo pipefail

cd "$(dirname "$0")/../.."
PROJECT="${E2E_PROJECT:-pinkglasses-e2e}"
API_PORT="${E2E_API_PORT:-18080}"
export E2E_ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-e2e-admin-password-not-secret}"
export ASM_API_PUBLISH="127.0.0.1:${API_PORT}"
export ASM_GATEWAY_PUBLISH="127.0.0.1:${E2E_GATEWAY_PORT:-18090}"
# Its own object storage ports too, so the test can run beside a real install.
export ASM_MINIO_PUBLISH="127.0.0.1:${E2E_MINIO_PORT:-19000}"
export ASM_MINIO_CONSOLE_PUBLISH="127.0.0.1:${E2E_MINIO_CONSOLE_PORT:-19001}"
API="http://127.0.0.1:${API_PORT}/api/v1"
JAR="$(mktemp)"
DC=(docker compose -p "$PROJECT" -f docker-compose.yml -f deploy/e2e/docker-compose.e2e.yml)
SERVICES=(postgres minio migrate api gateway scheduler worker e2e-target)

say() { printf '\n=== %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; dump; exit 1; }
dump() {
  printf '\n--- api\n';       "${DC[@]}" logs --tail 40 api       2>&1 || true
  printf '\n--- scheduler\n'; "${DC[@]}" logs --tail 40 scheduler 2>&1 || true
  printf '\n--- worker\n';    "${DC[@]}" logs --tail 60 worker    2>&1 || true
}
cleanup() {
  rm -f "$JAR"
  docker rm -f "${PROJECT}-remote-worker" >/dev/null 2>&1 || true
  if [ "${E2E_KEEP:-}" = "1" ]; then
    echo "E2E_KEEP=1: left running as project $PROJECT (api on $API_PORT)"
    return
  fi
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

api() { # method path [body]
  local m=$1 p=$2
  if [ $# -ge 3 ]; then
    curl -sS -b "$JAR" -c "$JAR" -X "$m" "$API$p" -H 'Content-Type: application/json' -d "$3"
  else
    curl -sS -b "$JAR" -c "$JAR" -X "$m" "$API$p"
  fi
}
jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]))" "$1"; }

say "building and starting $PROJECT"
"${DC[@]}" up -d --build "${SERVICES[@]}"

say "waiting for the api"
for i in $(seq 1 90); do
  curl -sf "http://127.0.0.1:${API_PORT}/healthz" >/dev/null 2>&1 && break
  [ "$i" = 90 ] && fail "the api never answered on port $API_PORT"
  sleep 2
done

say "signing in"
api POST /auth/login "{\"username\":\"admin\",\"password\":\"$E2E_ADMIN_PASSWORD\"}" >/dev/null \
  || fail "could not sign in"

say "the target's address"
TARGET_IP=$(docker inspect "$("${DC[@]}" ps -q e2e-target)" \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
[ -n "$TARGET_IP" ] || fail "the target container has no address"
echo "target $TARGET_IP"

say "a company with that target, authorized for active scanning"
SCOPE=$(api POST /scopes '{"name":"e2e"}' | jget "['id']")
api POST "/scopes/$SCOPE/target-groups" \
  "{\"name\":\"e2e\",\"values\":[\"$TARGET_IP\"],\"authorize\":true,\"mode\":\"active\"}" >/dev/null
echo "company $SCOPE"

say "enrolling a worker into the remote pool"
POOL=$(api GET /pools | python3 -c "
import json,sys
print(next(p['id'] for p in json.load(sys.stdin) if p['name'] == 'remote'))")
TOKEN=$(api POST /workers/enrollment-tokens "{\"kind\":\"vps\",\"pool_id\":\"$POOL\",\"ttl_mins\":30}" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('token') or d.get('enroll_token'))")
[ -n "$TOKEN" ] && [ "$TOKEN" != None ] || fail "no enrolment token came back"
docker run -d --name "${PROJECT}-remote-worker" --network "${PROJECT}_default" \
  --cap-add NET_RAW \
  -e ASM_GATEWAY_URL=http://gateway:8090 \
  -e ASM_ENROLL_TOKEN="$TOKEN" \
  -e ASM_WORKER_NAME=e2e-remote \
  "$(docker inspect "$("${DC[@]}" ps -q worker | head -1)" --format '{{.Config.Image}}')" >/dev/null

say "approving it"
for i in $(seq 1 40); do
  WID=$(api GET /workers | python3 -c "
import json,sys
ws = [w for w in json.load(sys.stdin) if w['name'] == 'e2e-remote']
print(ws[0]['id'] if ws else '')")
  [ -n "$WID" ] && break
  [ "$i" = 40 ] && fail "the worker never enrolled"
  sleep 2
done
api POST "/workers/$WID/approve" >/dev/null || true
for i in $(seq 1 30); do
  ST=$(api GET /workers | python3 -c "
import json,sys
print(next((w['status'] for w in json.load(sys.stdin) if w['name'] == 'e2e-remote'), ''))")
  [ "$ST" = active ] && break
  [ "$i" = 30 ] && fail "the worker did not become active (status $ST)"
  sleep 2
done
echo "worker $WID active"

say "scanning"
RUN=$(api POST "/scopes/$SCOPE/runs" \
  "{\"profile\":\"standard\",\"all\":true,\"exit\":\"remote\",\"pool_id\":\"$POOL\",
    \"params\":{\"subfinder_enabled\":\"false\",\"dns_bruteforce\":\"false\",
                \"gobuster_enabled\":\"false\",\"katana_enabled\":\"false\",
                \"nuclei_enabled\":\"false\",\"ports\":\"top-1000\"}}")
RUN_ID=$(echo "$RUN" | jget "['id']" 2>/dev/null) || fail "the scan was refused: $RUN"
echo "run $RUN_ID"

for i in $(seq 1 120); do
  STATUS=$(api GET "/runs/$RUN_ID" | jget "['run']['status']")
  case "$STATUS" in
    completed) break ;;
    failed|cancelled) fail "the run ended $STATUS" ;;
  esac
  [ "$i" = 120 ] && fail "the run was still $STATUS after 10 minutes"
  sleep 5
done
echo "run completed"

say "what it found"
api GET "/scopes/$SCOPE/search?q=*" | python3 -c "
import json, sys
rows = json.load(sys.stdin) or []
for r in rows:
    print(' ', r['ip'], r['port'], r.get('product') or '-', r.get('title') or '-')
ports = {r['port'] for r in rows}
assert 80 in ports, f'port 80 was not found; ports seen: {sorted(ports)}'
assert any((r.get('product') or '').lower().startswith('nginx') for r in rows), \
    'no service was identified as nginx'
print('OK: port 80 open and identified as nginx')
" || fail "the scan did not find the target's web server"

say "the certificate it found"
api GET "/scopes/$SCOPE/findings" | python3 -c "
import json, sys
fs = json.load(sys.stdin) or []
certs = [f for f in fs if f['kind'].startswith('tls_certificate')]
for f in certs:
    print(' ', f['severity'], f['title'], '|', (f.get('evidence') or {}).get('days_left'), 'days left')
assert certs, 'the target serves a certificate expiring in 7 days; no finding was raised'
assert any(f['kind'] == 'tls_certificate_expiring' and f['severity'] == 'medium' for f in certs), \
    f'expected a medium expiring-certificate finding, got {[(f[\"kind\"], f[\"severity\"]) for f in certs]}'
print('OK: the expiring certificate was found and rated medium')
" || fail "the expiring certificate was not reported"

say "the run's own record"
api GET "/runs/$RUN_ID/activity" | python3 -c "
import json, sys
a = json.load(sys.stdin)
stages = {s['stage']: s for s in a['stages']}
for name in ('port_scan', 'service_probe'):
    assert name in stages, f'{name} was never planned'
    assert stages[name]['failed'] == 0, f'{name} had {stages[name][\"failed\"]} failed tasks'
    assert stages[name]['done'] > 0, f'{name} finished nothing'
print('OK: port_scan and service_probe both ran with no failures')
" || fail "the run's stages did not look right"

printf '\n=== end to end passed\n'

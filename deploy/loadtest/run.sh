#!/usr/bin/env bash
# Several companies scanning at once, against a real install.
#
# It starts one active scan per company, all within a second of each other, and
# watches what the install does with them: whether every run gets work, whether
# one company can hold every worker, whether anything is left waiting with no
# worker able to take it, and whether any task loses its lease. Those are the
# failures that only appear under contention — a single scan never shows them.
#
# What it needs:
#   ASM_TOKEN         an API token with the operator or admin role (Accounts →
#                     API tokens), or ASM_ADMIN_PASSWORD to sign in instead
#   LOAD_TARGETS      what each company scans: one entry per company, space
#                     separated, and an entry may be several targets joined by
#                     commas. Every one is authorized for ACTIVE scanning, so
#                     pass only targets you are allowed to send traffic at.
#                       "a.example b.example"          two companies, one each
#                       "a,b,c a,b,c"                  two companies, three each
#
# What it does not do: it never touches an existing company. It works in
# companies of its own (load-1…load-N) and leaves them behind to look at.
#
#   LOAD_TARGETS="a.example b.example" deploy/loadtest/run.sh
#   LOAD_WORKERS=2 LOAD_KEEP_WORKERS=1 deploy/loadtest/run.sh    # more knobs below
set -euo pipefail

cd "$(dirname "$0")/../.."

API_BASE="${ASM_API_URL:-http://127.0.0.1:8080}"
API="$API_BASE/api/v1"
PROJECT="${LOAD_PROJECT:-pinkglasses}"
# Workers enrolled for the test. Deliberately fewer than the number of
# companies: the interesting behaviour is what happens when four companies want
# the same two workers.
WORKERS="${LOAD_WORKERS:-2}"
# Task slots per test worker, passed as ASM_WORKER_MAX_CONCURRENCY.
#
# Note: as of 2026-09-30 the gateway stamps every enrolling worker with 8 slots
# (internal/agentapi/gateway.go) and ignores what the worker asks for, so this
# currently changes nothing for a remote worker — see TODO 29.4. It is passed
# anyway, so the knob starts working the day that is fixed. Until then, make
# contention with more work rather than fewer slots.
WORKER_SLOTS="${LOAD_WORKER_SLOTS:-2}"
PREFIX="${LOAD_PREFIX:-load}"
# Worker names carry the run's own stamp. A container re-enrolling under a name
# that an earlier run used leaves two rows behind — the old one stays `active`
# until the scheduler's sweep marks it stale, and while it does the pool looks
# staffed by a worker that is gone. The test should measure the queue, not that.
STAMP="$(date +%H%M%S)"
# A task this long is worth a line of its own in the report: it is the shape of
# a tool that ran out of its own time budget and returned partial results.
SLOW_TASK_MINS="${LOAD_SLOW_TASK_MINS:-10}"
# How long to wait for every run to finish, and how often to sample.
TIMEOUT_MINS="${LOAD_TIMEOUT_MINS:-30}"
SAMPLE_SECS="${LOAD_SAMPLE_SECS:-10}"
# The scan itself: active, but bounded. Discovery off, so each run resolves its
# own seed target and then port-scans and probes what it finds — the part that
# actually sends traffic, without a subdomain sweep making one run enormous.
PARAMS="${LOAD_PARAMS:-{\"subfinder_enabled\":\"false\",\"dns_bruteforce\":\"false\",\"gobuster_enabled\":\"false\",\"katana_enabled\":\"false\",\"nuclei_enabled\":\"false\",\"ports\":\"top-1000\"}}"

TARGETS=(${LOAD_TARGETS:-})
[ ${#TARGETS[@]} -gt 0 ] || { echo "set LOAD_TARGETS to the targets to scan, one per company" >&2; exit 2; }
N=${#TARGETS[@]}

OUT="${LOAD_OUT:-$(mktemp -d)}"
JAR="$(mktemp)"
say()  { printf '\n=== %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

AUTH=()
if [ -n "${ASM_TOKEN:-}" ]; then AUTH=(-H "Authorization: Bearer $ASM_TOKEN"); fi
api() { # method path [body]
  local m=$1 p=$2
  if [ $# -ge 3 ]; then
    curl -sS "${AUTH[@]}" -b "$JAR" -c "$JAR" -X "$m" "$API$p" -H 'Content-Type: application/json' -d "$3"
  else
    curl -sS "${AUTH[@]}" -b "$JAR" -c "$JAR" -X "$m" "$API$p"
  fi
}
py() { python3 -c "$1" ${2:+"$2"}; }

# Workers are removed only when the test reaches its own end. If this script is
# interrupted — a terminal closed, a wrapper's time limit, Ctrl-C — the scans it
# started are still running on those workers, and taking the workers away kills
# them: half an hour of sweeping was lost that way once. An interrupted test
# leaves its workers behind and says how to remove them.
test_complete=0
cleanup() {
  rm -f "$JAR"
  if [ "${LOAD_KEEP_WORKERS:-}" = "1" ] || [ "$test_complete" = "0" ]; then
    local why="LOAD_KEEP_WORKERS=1"
    [ "$test_complete" = "0" ] && why="the test did not finish, so the scans may still be running"
    note "test workers left running ($why). Remove them with:"
    for i in $(seq 1 "$WORKERS"); do note "  docker rm -f ${PREFIX}-w${STAMP}-$i"; done
    return
  fi
  for i in $(seq 1 "$WORKERS"); do docker rm -f "${PREFIX}-w${STAMP}-$i" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
trap 'echo; note "interrupted — leaving the workers so the scans survive"; exit 130' INT TERM

say "the install"
curl -sf "$API_BASE/healthz" >/dev/null || fail "no api on $API_BASE"
if [ -z "${ASM_TOKEN:-}" ]; then
  [ -n "${ASM_ADMIN_PASSWORD:-}" ] || fail "set ASM_TOKEN (an API token) or ASM_ADMIN_PASSWORD"
  api POST /auth/login "{\"username\":\"${ASM_ADMIN_USER:-admin}\",\"password\":\"$ASM_ADMIN_PASSWORD\"}" >/dev/null \
    || fail "could not sign in"
fi
api GET /scopes >/dev/null || fail "the token was refused"
note "api $API_BASE · $N companies · $WORKERS test workers · output in $OUT"

say "companies, authorized for active scanning"
SCOPES=(); NAMES=()
for i in $(seq 1 "$N"); do
  name="${PREFIX}-$i"
  target="${TARGETS[$((i-1))]}"
  # One entry may hold several targets: "a,b,c" is one company scanning three.
  values=$(py 'import json,sys;print(json.dumps([v.strip() for v in sys.argv[1].split(",") if v.strip()]))' "$target")
  existing=$(api GET /scopes | py 'import json,sys;print(next((s["id"] for s in json.load(sys.stdin) if s["name"]==sys.argv[1]),""))' "$name")
  if [ -n "$existing" ]; then
    sid="$existing"
  else
    sid=$(api POST /scopes "{\"name\":\"$name\"}" | py 'import json,sys;print(json.load(sys.stdin)["id"])')
    api POST "/scopes/$sid/target-groups" \
      "{\"name\":\"$name\",\"values\":$values,\"authorize\":true}" >/dev/null
  fi
  SCOPES+=("$sid"); NAMES+=("$name")
  note "$name → $target ($sid)"
done

say "workers in the remote pool"
POOL=$(api GET /pools | py 'import json,sys;print(next(p["id"] for p in json.load(sys.stdin) if p["name"]=="remote"))')
WORKER_IMAGE=$(docker inspect "$(docker compose -p "$PROJECT" ps -q worker | head -1)" --format '{{.Config.Image}}')
NETWORK="${LOAD_NETWORK:-${PROJECT}_default}"
for i in $(seq 1 "$WORKERS"); do
  wname="${PREFIX}-w${STAMP}-$i"
  docker rm -f "$wname" >/dev/null 2>&1 || true
  tok=$(api POST /workers/enrollment-tokens "{\"kind\":\"vps\",\"pool_id\":\"$POOL\",\"ttl_mins\":30}" \
        | py 'import json,sys;d=json.load(sys.stdin);print(d.get("token") or d.get("enroll_token"))')
  [ -n "$tok" ] && [ "$tok" != None ] || fail "no enrolment token came back"
  docker run -d --name "$wname" --network "$NETWORK" --cap-add NET_RAW \
    -e ASM_GATEWAY_URL=http://gateway:8090 -e ASM_ENROLL_TOKEN="$tok" \
    -e ASM_WORKER_MAX_CONCURRENCY="$WORKER_SLOTS" \
    -e ASM_WORKER_NAME="$wname" "$WORKER_IMAGE" >/dev/null
done
for i in $(seq 1 60); do
  ready=0
  for i2 in $(seq 1 "$WORKERS"); do
    wname="${PREFIX}-w${STAMP}-$i2"
    # Every row with this name that still waits for approval, since a name can
    # briefly carry more than one row.
    for wid in $(api GET /workers | py 'import json,sys
print(" ".join(w["id"] for w in json.load(sys.stdin)
               if w["name"] == sys.argv[1] and w["status"] == "pending"))' "$wname"); do
      api POST "/workers/$wid/approve" >/dev/null 2>&1 || true
    done
    live=$(api GET /workers | py 'import json,sys
print(sum(1 for w in json.load(sys.stdin)
          if w["name"] == sys.argv[1] and w["status"] == "active"))' "$wname")
    [ "${live:-0}" -ge 1 ] && ready=$((ready+1))
  done
  [ "$ready" -ge "$WORKERS" ] && break
  [ "$i" = 60 ] && fail "only $ready of $WORKERS workers became active"
  sleep 2
done
note "$WORKERS workers active in the remote pool, $WORKER_SLOTS task slots each"

say "starting $N active scans at once"
RUNS=()
for i in $(seq 1 "$N"); do
  sid="${SCOPES[$((i-1))]}"
  ( api POST "/scopes/$sid/runs" \
      "{\"profile\":\"standard\",\"all\":true,\"exit\":\"remote\",\"pool_id\":\"$POOL\",\"params\":$PARAMS}" \
      > "$OUT/launch-$i.json" 2>&1 ) &
done
wait
for i in $(seq 1 "$N"); do
  rid=$(py 'import json,sys;print(json.load(open(sys.argv[1])).get("id",""))' "$OUT/launch-$i.json" 2>/dev/null || true)
  [ -n "$rid" ] || fail "${NAMES[$((i-1))]} was refused: $(cat "$OUT/launch-$i.json")"
  RUNS+=("$rid")
  note "${NAMES[$((i-1))]} run $rid"
done
START=$(date +%s)

say "watching"
printf 'elapsed' > "$OUT/timeline.tsv"
for n in "${NAMES[@]}"; do printf '\t%s' "$n" >> "$OUT/timeline.tsv"; done
printf '\tqueue_oldest_s\tlease_expiries\tfailed_tasks\tstranded\n' >> "$OUT/timeline.tsv"
deadline=$((START + TIMEOUT_MINS * 60))
declare -A PEAK; declare -A DONE_AT
while :; do
  now=$(date +%s); elapsed=$((now - START))
  line="$elapsed"
  finished=0
  for i in $(seq 1 "$N"); do
    rid="${RUNS[$((i-1))]}"; name="${NAMES[$((i-1))]}"
    status=$(api GET "/runs/$rid" | py 'import json,sys;print(json.load(sys.stdin)["run"]["status"])')
    read -r inflight pending done total <<<"$(api GET "/runs/$rid/activity" | py 'import json,sys
ts=json.load(sys.stdin).get("tasks") or []
f=lambda *w: sum(1 for t in ts if t.get("status") in w)
print(f("running","leased"), f("pending"), f("done"), len(ts))')"
    cur=${PEAK[$name]:-0}; [ "$inflight" -gt "$cur" ] && PEAK[$name]=$inflight
    case "$status" in
      completed|failed|cancelled)
        finished=$((finished+1))
        [ -z "${DONE_AT[$name]:-}" ] && DONE_AT[$name]="${elapsed}s $status"
        line="$line	$status ${done}/${total}" ;;
      *) line="$line	$status ${inflight}fly/${pending}wait" ;;
    esac
  done
  h=$(api GET /system/health)
  oldest=$(echo "$h" | py 'import json,sys
d=json.load(sys.stdin)
q=d.get("queue") or []
print(int(max([x["oldest_pending_s"] for x in q], default=0)))')
  metrics=$(echo "$h" | py 'import json,sys
d=json.load(sys.stdin); c=d["counts"]; st=d.get("stranded") or []
print(c["lease_expiries_24h"], c["failed_tasks_24h"], len(st))')
  printf '%s\t%s\t%s\n' "$line" "$oldest" "$metrics" >> "$OUT/timeline.tsv"
  printf '  %4ds  %s\n' "$elapsed" "$(echo "$line" | cut -f2- | tr '\t' ' ')"
  [ "$finished" -ge "$N" ] && break
  [ "$now" -ge "$deadline" ] && { note "gave up after $TIMEOUT_MINS minutes"; break; }
  sleep "$SAMPLE_SECS"
done

say "how it went"
bad=0
for i in $(seq 1 "$N"); do
  rid="${RUNS[$((i-1))]}"; name="${NAMES[$((i-1))]}"
  st=$(api GET "/runs/$rid" | py 'import json,sys;print(json.load(sys.stdin)["run"]["status"])')
  api GET "/runs/$rid/activity" | py 'import json,sys
from collections import Counter
from datetime import datetime
d=json.load(sys.stdin); ts=d.get("tasks") or []
c=Counter(t["status"] for t in ts)
name, st, slow = sys.argv[1].split("|")
slow=float(slow)
print("  %-10s %-10s %3d tasks: %s" % (name, st, len(ts),
      ", ".join("%s %d" % (k, v) for k, v in sorted(c.items())) or "none"))
def mins(t):
    a, b = t.get("started_at"), t.get("finished_at")
    if not a or not b: return None
    f=lambda x: datetime.fromisoformat(x.replace("Z","+00:00"))
    return (f(b)-f(a)).total_seconds()/60
for t in ts:
    if t["status"] == "failed":
        print("      failed: %s %s — %s" % (t["stage"], t.get("target",""), (t.get("error") or "")[:140]))
    if t.get("attempts", 0) > 1 and t["status"] != "failed":
        print("      retried %dx: %s %s" % (t["attempts"], t["stage"], t.get("target","")))
    m = mins(t)
    if m is not None and m >= slow:
        print("      slow: %s %s took %.0f min — a tool that long has probably hit its own"
              " time budget and returned partial results (check the worker log)"
              % (t["stage"], t.get("target",""), m))
for w in d.get("workers") or []:
    print("      worker %s: %d running, %d done" % (w["name"], w["running"], w["done"]))' "$name|$st|$SLOW_TASK_MINS"
  [ "$st" = completed ] || bad=$((bad+1))
done

say "fairness: the most tasks each company held at once"
for n in "${NAMES[@]}"; do note "$(printf '%-10s peak %s in flight, finished at %s' "$n" "${PEAK[$n]:-0}" "${DONE_AT[$n]:-not finished}")"; done

say "what the install reported"
api GET /system/health | py 'import json,sys
d=json.load(sys.stdin); c=d["counts"]
print("  status            ", d["status"])
print("  lease expiries 24h", c["lease_expiries_24h"])
print("  failed tasks 24h  ", c["failed_tasks_24h"])
print("  failed runs 24h   ", c["failed_runs_24h"])
print("  stranded          ", len(d.get("stranded") or []))
q=d.get("queue") or []
print("  queue now         ", ", ".join("%s %d/%d" % (x["stage"], x["pending"], x["in_flight"]) for x in q) or "empty")'

note "timeline: $OUT/timeline.tsv"
if [ "$bad" -gt 0 ]; then test_complete=1; fail "$bad of $N runs did not complete"; fi
test_complete=1
say "$N companies scanned at once with nothing stuck"

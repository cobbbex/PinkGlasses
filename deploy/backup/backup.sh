#!/bin/sh
# PinkGlasses backups: the database and the artifact store, on a schedule.
#
# Every ASM_BACKUP_EVERY_HOURS (default 24) this writes, into /backups:
#   pg-<UTC timestamp>.dump        pg_dump custom format — restore with pg_restore
#   artifacts-<UTC timestamp>.tgz  the object store's data directory
# and removes sets older than ASM_BACKUP_KEEP_DAYS (default 14). Each finished
# set is reported to the database, so the System page shows its age.
#
# Run once by hand:  docker compose run --rm backup once
set -eu

EVERY_H="${ASM_BACKUP_EVERY_HOURS:-24}"
KEEP_D="${ASM_BACKUP_KEEP_DAYS:-14}"
OUT=/backups

report() { # status detail
  detail=$(printf '{"status":"%s","detail":"%s","every_hours":%s,"keep_days":%s}' "$1" "$2" "$EVERY_H" "$KEEP_D")
  psql -q -v ON_ERROR_STOP=1 -c "INSERT INTO component_heartbeat (name, last_seen, detail)
    VALUES ('backup', now(), '$detail'::jsonb)
    ON CONFLICT (name) DO UPDATE SET last_seen = now(), detail = EXCLUDED.detail" >/dev/null 2>&1 || true
}

one() {
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  mkdir -p "$OUT"
  echo "backup $ts: database"
  if ! pg_dump -Fc -f "$OUT/pg-$ts.dump.part"; then
    rm -f "$OUT/pg-$ts.dump.part"; report failed "pg_dump failed"; return 1
  fi
  mv "$OUT/pg-$ts.dump.part" "$OUT/pg-$ts.dump"
  echo "backup $ts: artifacts"
  if ! tar -czf "$OUT/artifacts-$ts.tgz.part" -C /minio .; then
    rm -f "$OUT/artifacts-$ts.tgz.part"; report failed "archiving the artifact store failed"; return 1
  fi
  mv "$OUT/artifacts-$ts.tgz.part" "$OUT/artifacts-$ts.tgz"
  find "$OUT" -maxdepth 1 \( -name 'pg-*.dump' -o -name 'artifacts-*.tgz' \) -mtime +"$KEEP_D" -delete
  size=$(du -ch "$OUT/pg-$ts.dump" "$OUT/artifacts-$ts.tgz" | tail -1 | cut -f1)
  echo "backup $ts: done ($size)"
  report ok "pg-$ts.dump and artifacts-$ts.tgz, $size"
}

if [ "${1:-}" = "once" ]; then one; exit $?; fi

echo "backups every ${EVERY_H}h into $OUT, kept ${KEEP_D} days"
while :; do
  one || echo "backup failed; retrying at the next interval"
  sleep $((EVERY_H * 3600))
done

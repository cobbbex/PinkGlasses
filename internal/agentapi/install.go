package agentapi

// installSh is the worker installer served at GET /install.sh (§7.1).
const installSh = `
#!/usr/bin/env bash
# PinkGlasses — worker installer.
# Enrolls this machine as a scan worker. Pull-based: the only secret is a
# single-use, short-TTL enrollment token (architecture.md §7.1).
set -euo pipefail

URL=""; TOKEN=""; NAME="$(hostname)"; POOL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --name) NAME="$2"; shift 2;;
    --pool) POOL="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done
[ -n "$URL" ] && [ -n "$TOKEN" ] || { echo "usage: install.sh --url <gw> --token <tok> [--name n]"; exit 1; }

IMAGE="${ASM_WORKER_IMAGE:-ghcr.io/benlik386/pinkglasses-worker:latest}"
CRED_DIR="/etc/pinkglasses-worker"
mkdir -p "$CRED_DIR"; chmod 700 "$CRED_DIR"

echo ">> Pulling worker image $IMAGE"
docker pull "$IMAGE"

echo ">> Enrolling with $URL"
# The worker binary performs enrollment on first boot using the token, stores
# its long-lived credential in $CRED_DIR/credential (0600), then connects.
cat > /etc/systemd/system/pinkglasses-worker.service <<UNIT
[Unit]
Description=ASM scan worker
After=network-online.target docker.service
Requires=docker.service

[Service]
Restart=always
RestartSec=5
ExecStartPre=-/usr/bin/docker rm -f pinkglasses-worker
ExecStart=/usr/bin/docker run --rm --name pinkglasses-worker \\
  --cap-add=NET_RAW \\
  -e ASM_GATEWAY_URL=${URL} \\
  -e ASM_ENROLL_TOKEN=${TOKEN} \\
  -e ASM_WORKER_NAME=${NAME} \\
  -e ASM_WORKER_POOL=${POOL} \\
  -v ${CRED_DIR}:/etc/pinkglasses-worker \\
  ${IMAGE}
ExecStop=/usr/bin/docker stop pinkglasses-worker

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now pinkglasses-worker
echo ">> Worker installed. It will appear in the fleet as 'pending' — approve it in the UI."
`

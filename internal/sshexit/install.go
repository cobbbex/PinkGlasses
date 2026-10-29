package sshexit

import (
	"fmt"
	"strings"
)

// InstallSpec is what the install script needs. Every field is checked by
// Script before it reaches the shell.
type InstallSpec struct {
	Image       string // worker image the VPS pulls
	Token       string // single-use enrolment token
	WorkerName  string
	GatewayPort int    // VPS loopback port that leads to the gateway
	StoreHost   string // the object store's host name in presigned URLs ("minio")
}

// containerName is the worker's container on the VPS: fixed, so a reinstall
// replaces the previous one and an uninstall knows what to remove.
const containerName = "pinkglasses-worker"

// credDir is where the worker keeps the credential it enrols for.
const credDir = "/etc/pinkglasses-worker"

// preamble finds a way to run as root and checks Docker, with an error that
// names the fix. "PG-ERR:" lines are what the UI shows when an install fails.
const preamble = `set -eu
if [ "$(id -u)" = 0 ]; then SUDO=""
elif sudo -n true 2>/dev/null; then SUDO="sudo -n"
else echo "PG-ERR: $(id -un) is not root and cannot run sudo without a password; connect as root or allow passwordless sudo"; exit 3
fi
command -v docker >/dev/null 2>&1 || { echo "PG-ERR: Docker is not installed on this machine: https://docs.docker.com/engine/install/"; exit 4; }
$SUDO docker info >/dev/null 2>&1 || { echo "PG-ERR: Docker is installed but its daemon is not running (systemctl start docker)"; exit 5; }
`

// Script returns the shell script that installs (or reinstalls) the worker.
//
// The worker runs with the host's network so 127.0.0.1 is the VPS's loopback,
// where the tunnel listens; --add-host points the store's name there too, so
// presigned upload URLs reach the store through the same session. The old
// credential is removed so a reinstall enrols afresh with the new token.
func Script(s InstallSpec) (string, error) {
	switch {
	case !imageRe.MatchString(s.Image):
		return "", fmt.Errorf("worker image %q is not an image reference", s.Image)
	case !tokenRe.MatchString(s.Token):
		return "", fmt.Errorf("enrolment token has an unexpected shape")
	case !nameRe.MatchString(s.WorkerName):
		return "", fmt.Errorf("worker name %q: use letters, digits, dot, dash and underscore", s.WorkerName)
	case s.GatewayPort < 1024 || s.GatewayPort > 65535:
		return "", fmt.Errorf("gateway port %d out of range", s.GatewayPort)
	case s.StoreHost != "" && !nameRe.MatchString(s.StoreHost):
		return "", fmt.Errorf("object store host %q is not a host name", s.StoreHost)
	}
	var b strings.Builder
	b.WriteString(preamble)
	fmt.Fprintf(&b, "echo \">> pulling %s\"\n", s.Image)
	fmt.Fprintf(&b, "$SUDO docker pull -q '%s' >/dev/null\n", s.Image)
	fmt.Fprintf(&b, "$SUDO docker rm -f %s >/dev/null 2>&1 || true\n", containerName)
	fmt.Fprintf(&b, "$SUDO mkdir -p %s\n$SUDO chmod 700 %s\n$SUDO rm -f %s/credential\n", credDir, credDir, credDir)
	b.WriteString("echo \">> starting the worker\"\n")
	fmt.Fprintf(&b, "$SUDO docker run -d --name %s --restart unless-stopped --network host --cap-add NET_RAW \\\n", containerName)
	if s.StoreHost != "" {
		fmt.Fprintf(&b, "  --add-host '%s:127.0.0.1' \\\n", s.StoreHost)
	}
	fmt.Fprintf(&b, "  -e ASM_GATEWAY_URL='http://127.0.0.1:%d' -e ASM_ENROLL_TOKEN='%s' -e ASM_WORKER_NAME='%s' \\\n",
		s.GatewayPort, s.Token, s.WorkerName)
	fmt.Fprintf(&b, "  -v %s:%s '%s' >/dev/null\n", credDir, credDir, s.Image)
	// A worker that exits straight away (wrong platform, bad image) should
	// fail the install, not leave it looking done.
	fmt.Fprintf(&b, "sleep 5\nif [ \"$($SUDO docker inspect -f '{{.State.Running}}' %s)\" != true ]; then\n", containerName)
	fmt.Fprintf(&b, "  echo \"PG-ERR: the worker container stopped right after starting; its last output:\"\n  $SUDO docker logs --tail 20 %s 2>&1\n  exit 6\nfi\n", containerName)
	fmt.Fprintf(&b, "$SUDO docker logs --tail 5 %s 2>&1 || true\n", containerName)
	b.WriteString("echo \">> worker running\"\n")
	return b.String(), nil
}

// UninstallScript removes the worker and its credential from the VPS.
func UninstallScript() string {
	return preamble + fmt.Sprintf("$SUDO docker rm -f %s >/dev/null 2>&1 || true\n$SUDO rm -rf %s\necho \">> worker removed\"\n",
		containerName, credDir)
}

// FailureReason picks the PG-ERR line out of a failed script's output, or
// the last line when there is none.
func FailureReason(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "PG-ERR: ") {
			return strings.TrimPrefix(l, "PG-ERR: ")
		}
	}
	if len(lines) > 0 && lines[len(lines)-1] != "" {
		return lines[len(lines)-1]
	}
	return "the install script failed without saying why"
}

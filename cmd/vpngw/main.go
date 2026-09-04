// Command vpngw holds a VPN tunnel for one scan run and does nothing else.
//
// The run's workers share this container's network namespace, so they scan from
// its address without holding any network privilege themselves. That is the
// whole point of separating it: NET_ADMIN lets a container rewrite its own
// networking, and the container running nmap, chromium, gobuster and nuclei is
// the one most likely to be the thing that gets exploited. It should hold the
// least, not the most.
//
// Two modes:
//
//	vpngw          bring the tunnel up and stay running
//	vpngw -check   the healthcheck: is the tunnel carrying traffic right now?
//
// Docker only calls the container healthy once -check succeeds, and the
// provisioner only starts workers once Docker calls it healthy — so a worker is
// never placed in a namespace that turned out not to be tunnelled.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/benlik386/pinkglasses/internal/tunnel"
)

// egressFile is where the running process records the address it established,
// so the healthcheck — a separate process — can compare against it.
const egressFile = "/run/pgvpn.egress"

func main() {
	check := flag.Bool("check", false, "healthcheck: report whether the tunnel is carrying traffic")
	flag.Parse()

	if *check {
		os.Exit(runCheck())
	}

	kind := os.Getenv("PG_VPN_KIND")
	config := os.Getenv("PG_VPN_CONFIG")
	if kind == "" || config == "" {
		slog.Error("no tunnel configured", "hint", "PG_VPN_KIND and PG_VPN_CONFIG must be set")
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var t tunnel.Tunnel
	if err := t.Up(ctx, "fleet", kind, config); err != nil {
		// Exiting is the correct outcome: the provisioner sees the container
		// stop, reports why, and does not start workers into a namespace with
		// no tunnel in it.
		slog.Error("the tunnel did not come up", "kind", kind, "err", err)
		os.Exit(1)
	}
	egress := t.Egress()
	if err := os.WriteFile(egressFile, []byte(egress), 0o600); err != nil {
		slog.Warn("could not record the egress address", "err", err)
	}
	slog.Info("tunnel up; this fleet scans from here", "kind", kind, "egress", egress)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	slog.Info("shutting the tunnel down")
	t.Down()
}

// runCheck is the healthcheck. It asks what address this namespace exits from
// and compares it with the one the tunnel established: if they differ, traffic
// is no longer taking the tunnel and the container must stop being healthy,
// because workers in this namespace would be scanning from the wrong address.
func runCheck() int {
	want, err := os.ReadFile(egressFile)
	if err != nil {
		fmt.Println("tunnel not up yet")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	got := tunnel.ObservedEgressIP(ctx)
	if got == "" {
		fmt.Println("cannot reach anything to confirm the egress address")
		return 1
	}
	if got != string(want) {
		fmt.Printf("egress changed from %s to %s: traffic is no longer taking the tunnel\n", want, got)
		return 1
	}
	fmt.Printf("egress=%s\n", got)
	return 0
}

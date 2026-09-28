package httpapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benlik386/pinkglasses/internal/version"
)

// Prometheus metrics, so an existing monitoring stack can page someone at
// 03:00 about what the System page would have shown at 09:00: a queue that
// stopped moving, runs failing, workers gone, backups overdue.
//
// Written by hand in the text exposition format rather than pulling in a
// client library: these are a few dozen gauges read from the database, and a
// scrape is a page load, not a hot path.
//
// Nothing here is labelled by company. An install-wide number says how much is
// happening; a per-company one would tell any account with a viewer token the
// names of companies it cannot see.

const metricsCacheFor = 10 * time.Second

type metricsCache struct {
	mu   sync.Mutex
	at   time.Time
	body []byte
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	s.metricsCache.mu.Lock()
	defer s.metricsCache.mu.Unlock()
	if time.Since(s.metricsCache.at) < metricsCacheFor && s.metricsCache.body != nil {
		w.Write(s.metricsCache.body)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	m, err := s.st.Metrics(ctx)
	if err != nil {
		// A scrape that fails is an alert in itself; say why in the body.
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("# the database could not be read: " + err.Error() + "\n"))
		return
	}

	var b strings.Builder
	g := func(name, help string) { b.WriteString("# HELP " + name + " " + help + "\n# TYPE " + name + " gauge\n") }
	val := func(name, labels string, v float64) {
		b.WriteString(name)
		if labels != "" {
			b.WriteString("{" + labels + "}")
		}
		b.WriteString(" " + strconv.FormatFloat(v, 'f', -1, 64) + "\n")
	}
	// Sorted, so a diff of two scrapes is readable.
	each := func(m map[string]int, emit func(k string, n int)) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			emit(k, m[k])
		}
	}

	g("pinkglasses_build_info", "The running version, as a label on a constant 1.")
	val("pinkglasses_build_info", `version=`+quote(version.Version)+`,commit=`+quote(version.Commit), 1)

	g("pinkglasses_schema_version", "Applied database migration number.")
	val("pinkglasses_schema_version", "", float64(m.SchemaVersion))

	g("pinkglasses_runs", "Scan runs by status, all time.")
	each(m.RunsByStatus, func(k string, n int) { val("pinkglasses_runs", "status="+quote(k), float64(n)) })

	g("pinkglasses_runs_finished_24h", "Scan runs that finished in the last 24 hours, by status.")
	each(m.RunsFinished24h, func(k string, n int) { val("pinkglasses_runs_finished_24h", "status="+quote(k), float64(n)) })

	g("pinkglasses_queue_tasks", "Tasks on running scans, by stage and whether they are waiting or in flight.")
	g("pinkglasses_queue_oldest_seconds", "How long the oldest waiting task of a stage has waited. The number to alert on: work that stops moving shows here first.")
	for _, q := range m.Queue {
		val("pinkglasses_queue_tasks", "stage="+quote(q.Stage)+`,state="pending"`, float64(q.Pending))
		val("pinkglasses_queue_tasks", "stage="+quote(q.Stage)+`,state="in_flight"`, float64(q.InFlight))
		val("pinkglasses_queue_oldest_seconds", "stage="+quote(q.Stage), q.OldestPending)
	}

	g("pinkglasses_workers", "Workers by status.")
	each(m.WorkersByStatus, func(k string, n int) { val("pinkglasses_workers", "status="+quote(k), float64(n)) })

	g("pinkglasses_findings_open", "Open findings by severity.")
	each(m.FindingsBySeverity, func(k string, n int) { val("pinkglasses_findings_open", "severity="+quote(k), float64(n)) })

	g("pinkglasses_lease_expiries_24h", "Tasks whose lease expired in the last 24 hours: a worker took work and stopped reporting.")
	val("pinkglasses_lease_expiries_24h", "", float64(m.LeaseExpiries24h))
	g("pinkglasses_failed_tasks_24h", "Tasks that failed in the last 24 hours.")
	val("pinkglasses_failed_tasks_24h", "", float64(m.FailedTasks24h))
	g("pinkglasses_failed_runs_24h", "Runs that failed in the last 24 hours.")
	val("pinkglasses_failed_runs_24h", "", float64(m.FailedRuns24h))

	g("pinkglasses_inventory", "What the install knows about: companies, names, hosts, services.")
	val("pinkglasses_inventory", `kind="companies"`, float64(m.Companies))
	val("pinkglasses_inventory", `kind="names"`, float64(m.Names))
	val("pinkglasses_inventory", `kind="hosts"`, float64(m.Hosts))
	val("pinkglasses_inventory", `kind="services"`, float64(m.Services))

	g("pinkglasses_component_heartbeat_age_seconds", "Seconds since each service last reported: gateway, scheduler, every api copy, and backup (whose age is the age of the last backup set).")
	names := make([]string, 0, len(m.Beats))
	for k := range m.Beats {
		names = append(names, k)
	}
	sort.Strings(names)
	now := time.Now()
	for _, k := range names {
		age := now.Sub(m.Beats[k])
		// A copy that has been gone for ten minutes is gone: its row belongs
		// to a container that no longer exists, and reporting it forever
		// would keep an alert on heartbeat age firing about nothing. The
		// scheduler deletes these rows an hour after they go quiet.
		if age > 10*time.Minute && strings.Contains(k, ":") {
			continue
		}
		val("pinkglasses_component_heartbeat_age_seconds", "component="+quote(k), age.Seconds())
	}

	body := []byte(b.String())
	s.metricsCache.at = time.Now()
	s.metricsCache.body = body
	w.Write(body)
}

// quote renders a Prometheus label value, escaping what the format reserves.
func quote(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(v) + `"`
}

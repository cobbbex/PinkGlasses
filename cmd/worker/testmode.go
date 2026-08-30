package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/benlik386/asm/internal/scanner"
	"github.com/benlik386/asm/internal/scanproto"
)

// runStageTest executes a single pipeline stage locally and prints the
// observations it produced. It never contacts the gateway and never writes to
// the database, so it is the fastest way to verify one tool in isolation:
//
//	worker -stage passive_enum -target example.com
//
// This backs `make tool-test` and the Phase 13 gates.
func runStageTest(stage, target string, timeout time.Duration) int {
	caps := scanner.DetectCapabilities()
	pc, sources, err := scanner.WriteProviderConfig(os.TempDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "provider config: %v\n", err)
	}

	sc := &scanner.Scanner{Detected: caps, ProviderConfig: pc}

	capNames := make([]string, 0, len(caps))
	for c, ok := range caps {
		if ok {
			capNames = append(capNames, string(c))
		}
	}
	sort.Strings(capNames)

	fmt.Fprintf(os.Stderr, "stage=%s target=%s\ncapabilities=%v\npassive_sources=%v\ntools=%v\n\n",
		stage, target, capNames, sources, toolList())

	job := scanproto.Job{
		Schema:  scanproto.JobSchema,
		JobID:   "stage-test",
		TaskID:  "stage-test",
		Stage:   scanproto.Stage(stage),
		Profile: os.Getenv("ASM_TEST_PROFILE"),
		Targets: []scanproto.Target{targetFor(stage, target)},
	}
	if job.Profile == "" {
		job.Profile = "standard"
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started := time.Now()
	obs, err := sc.Run(ctx, job)
	elapsed := time.Since(started).Round(time.Millisecond)

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(obs)

	byType := map[string]int{}
	for _, o := range obs {
		byType[string(o.Type)]++
	}
	fmt.Fprintf(os.Stderr, "\n%d observations in %s %v\n", len(obs), elapsed, byType)
	if len(obs) == 0 {
		fmt.Fprintln(os.Stderr, "GATE: FAIL — no observations produced")
		return 2
	}
	fmt.Fprintln(os.Stderr, "GATE: observations produced")
	return 0
}

// targetFor puts the target in the field the stage actually reads.
func targetFor(stage, target string) scanproto.Target {
	switch scanproto.Stage(stage) {
	case scanproto.StagePassiveEnum, scanproto.StageDNSResolve:
		return scanproto.Target{Domain: target}
	case scanproto.StageIPEnrich, scanproto.StagePortScan:
		return scanproto.Target{IP: target}
	case scanproto.StageServiceProbe:
		return scanproto.Target{IP: target, Port: 80}
	default:
		// tech_detect, screenshot, dir_brute, vuln_check take a URL
		if len(target) > 4 && (target[:4] == "http") {
			return scanproto.Target{URL: target}
		}
		return scanproto.Target{URL: "http://" + target}
	}
}

func toolList() []string {
	t := scanner.DetectTools()
	names := make([]string, 0, len(t))
	for n := range t {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

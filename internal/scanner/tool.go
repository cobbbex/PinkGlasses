// Package scanner implements the worker's scan pipeline. Each stage prefers the
// real tool (worker-pipeline.md) when its binary is present and parses its JSON
// output; otherwise it falls back to a pure-Go implementation so the worker is
// useful out of the box. Swapping a fallback for the linked library later is a
// localized change (architecture.md §6.1).
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// have reports whether a tool binary is on PATH.
func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// execution is the outcome of running one scan tool.
type execution struct {
	name   string
	args   []string
	stdout bytes.Buffer
	stderr string
	took   time.Duration
	err    error
}

// runTool executes a scan tool, capturing output and timing. Every invocation
// is logged: which tool, against what, how long it took and how much it
// produced. Without that a stage that quietly does nothing is invisible, which
// this pipeline has already been bitten by more than once.
func runTool(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) *execution {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	e := &execution{name: name, args: args}
	cmd := exec.CommandContext(cctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var errb bytes.Buffer
	cmd.Stdout = &e.stdout
	cmd.Stderr = &errb

	slog.Debug("tool starting", "tool", name, "args", argSummary(args))
	start := time.Now()
	e.err = cmd.Run()
	e.took = time.Since(start)
	e.stderr = errb.String()

	if e.err != nil {
		// Tools often exit non-zero yet still produce useful lines, so this is
		// not fatal — but it must not be silent either: a rejected flag makes a
		// stage return nothing at all, which is otherwise indistinguishable
		// from a clean "found nothing".
		logToolFailure(name, args, e.err, e.stderr)
	}
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		slog.Warn("tool timed out — results are partial",
			"tool", name, "timeout", timeout, "args", argSummary(args))
	}
	return e
}

// logResult records what an invocation produced, so a run can be followed
// tool by tool rather than only stage by stage.
func (e *execution) logResult(results int) {
	slog.Info("tool finished",
		"tool", e.name,
		"args", argSummary(e.args),
		"results", results,
		"took", e.took.Round(time.Millisecond).String(),
		"ok", e.err == nil,
	)
}

// argSummary renders a command line for logs, bounded so a port list or a
// thousand-name stdin batch cannot flood the output.
func argSummary(args []string) string {
	s := strings.Join(args, " ")
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// runJSONL executes a command and returns each stdout line parsed as JSON into
// a map. Most ProjectDiscovery tools emit newline-delimited JSON with -json.
func runJSONL(ctx context.Context, timeout time.Duration, name string, args ...string) ([]map[string]any, error) {
	return parseJSONL(runTool(ctx, timeout, "", name, args...))
}

// runJSONLStdin pipes stdin into a command and parses newline-delimited JSON
// from its stdout. Several Tools.md pipelines are `cat <list> | tool ...`.
func runJSONLStdin(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) ([]map[string]any, error) {
	e := runTool(ctx, timeout, stdin, name, args...)
	slog.Debug("tool stdin", "tool", name, "lines", strings.Count(stdin, "\n"))
	return parseJSONL(e)
}

// parseJSONL turns an invocation's stdout into rows of newline-delimited JSON.
func parseJSONL(e *execution) ([]map[string]any, error) {
	var rows []map[string]any
	sc := bufio.NewScanner(&e.stdout)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			rows = append(rows, m)
		}
	}
	e.logResult(len(rows))
	return rows, nil
}

// parseLines turns an invocation's stdout into trimmed non-empty lines.
func parseLines(e *execution) ([]string, error) {
	var lines []string
	sc := bufio.NewScanner(&e.stdout)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	e.logResult(len(lines))
	return lines, nil
}

// runLinesStdin pipes stdin into a command and returns its stdout lines.
func runLinesStdin(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) ([]string, error) {
	e := runTool(ctx, timeout, stdin, name, args...)
	slog.Debug("tool stdin", "tool", name, "lines", strings.Count(stdin, "\n"))
	return parseLines(e)
}

// runLines executes a command and returns trimmed non-empty stdout lines.
func runLines(ctx context.Context, timeout time.Duration, name string, args ...string) ([]string, error) {
	return parseLines(runTool(ctx, timeout, "", name, args...))
}

func str(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func num(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

// logToolFailure reports a scan tool exiting non-zero, with the first line of
// its stderr. Silent failures here look exactly like empty results, which is
// how an unsupported flag can quietly disable a whole stage.
func logToolFailure(name string, args []string, err error, stderr string) {
	first := strings.TrimSpace(stderr)
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if len(first) > 200 {
		first = first[:200]
	}
	slog.Warn("scan tool exited non-zero",
		"tool", name, "args", strings.Join(args, " "), "err", err, "stderr", first)
}

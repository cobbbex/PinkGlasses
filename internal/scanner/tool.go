// Package scanner implements the worker's scan pipeline. Each stage prefers the
// real tool (worker-pipeline.md) when its binary is present and parses its JSON
// output; otherwise it falls back to a pure-Go implementation so the worker is
// useful out of the box. Swapping a fallback for the linked library later is a
// localized change (architecture.md §6.1).
package scanner

import (
	"bufio"
	"log/slog"
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// have reports whether a tool binary is on PATH.
func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// runJSONL executes a command and returns each stdout line parsed as JSON into
// a map. Most ProjectDiscovery tools emit newline-delimited JSON with -json.
func runJSONL(ctx context.Context, timeout time.Duration, name string, args ...string) ([]map[string]any, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		// Tools often exit non-zero yet still produce useful lines, so this is
		// not fatal — but it must not be silent either: a rejected flag makes a
		// stage return nothing at all, which is otherwise indistinguishable
		// from a clean "found nothing".
		logToolFailure(name, args, err, errb.String())
	}
	var rows []map[string]any
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
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
	return rows, nil
}

// runJSONLStdin pipes stdin into a command and parses newline-delimited JSON
// from its stdout. Several Tools.md pipelines are `cat <list> | tool ...`.
func runJSONLStdin(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) ([]map[string]any, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		logToolFailure(name, args, err, errb.String())
	} // tools may exit non-zero yet still emit useful lines

	var rows []map[string]any
	sc := bufio.NewScanner(&out)
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
	return rows, nil
}

// runLinesStdin pipes stdin into a command and returns its stdout lines.
func runLinesStdin(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()

	var lines []string
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// runLines executes a command and returns trimmed non-empty stdout lines.
func runLines(ctx context.Context, timeout time.Duration, name string, args ...string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		logToolFailure(name, args, err, errb.String())
	}
	var lines []string
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
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

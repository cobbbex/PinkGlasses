package scanner

import (
	"context"

	"github.com/benlik386/asm/internal/scanproto"
)

// Scanner runs pipeline stages. Detected holds the worker's capabilities so a
// stage can pick SYN vs connect scan, etc.
type Scanner struct {
	Detected map[scanproto.Capability]bool
}

// New builds a Scanner with detected capabilities.
func New(caps map[scanproto.Capability]bool) *Scanner { return &Scanner{Detected: caps} }

// Run executes a job's stage and returns observations (facts only).
func (s *Scanner) Run(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	switch job.Stage {
	case scanproto.StagePassiveEnum:
		return s.passiveEnum(ctx, job)
	case scanproto.StageDNSResolve:
		return s.dnsResolve(ctx, job)
	case scanproto.StageIPEnrich:
		return s.ipEnrich(ctx, job)
	case scanproto.StagePortScan:
		return s.portScan(ctx, job)
	case scanproto.StageServiceProbe:
		return s.serviceProbe(ctx, job)
	case scanproto.StageTechDetect:
		return s.techDetect(ctx, job)
	case scanproto.StageScreenshot:
		return s.screenshot(ctx, job)
	case scanproto.StageDirBrute:
		return s.dirBrute(ctx, job)
	default:
		return nil, nil
	}
}

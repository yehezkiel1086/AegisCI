package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

type Scanner interface {
	Name() string
	Category() string
	IsAvailable() bool
	Scan(ctx context.Context, targetDir string) (*sarif.Report, error)
}

type SBOMGenerator interface {
	GenerateSBOM(ctx context.Context, targetDir, format, outputPath string) error
}

type ScanResult struct {
	ScannerName string
	Category    string
	Report      *sarif.Report
	Duration    time.Duration
	Error       error
}

type Orchestrator struct {
	scanners []Scanner
}

func NewOrchestrator(scanners ...Scanner) *Orchestrator {
	return &Orchestrator{
		scanners: scanners,
	}
}

func (o *Orchestrator) RegisterScanner(s Scanner) {
	o.scanners = append(o.scanners, s)
}

func (o *Orchestrator) Scanners() []Scanner {
	return o.scanners
}

func (o *Orchestrator) Run(ctx context.Context, targetDir string) []ScanResult {
	var wg sync.WaitGroup
	results := make([]ScanResult, len(o.scanners))

	for i, scanner := range o.scanners {
		wg.Add(1)
		go func(idx int, sc Scanner) {
			defer wg.Done()

			start := time.Now()
			res := ScanResult{
				ScannerName: sc.Name(),
				Category:    sc.Category(),
			}

			if !sc.IsAvailable() {
				res.Error = fmt.Errorf("scanner '%s' is not installed or not in PATH", sc.Name())
				res.Duration = time.Since(start)
				results[idx] = res
				return
			}

			report, err := sc.Scan(ctx, targetDir)
			res.Duration = time.Since(start)
			res.Report = report
			res.Error = err
			results[idx] = res
		}(i, scanner)
	}

	wg.Wait()
	return results
}

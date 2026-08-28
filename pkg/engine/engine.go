package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// Scanner defines the standard interface for all security scanning engines.
type Scanner interface {
	Name() string
	Category() string
	IsAvailable() bool
	Scan(ctx context.Context, targetDir string) (*sarif.Report, error)
}

// ScanResult holds the result of a single scanner execution.
type ScanResult struct {
	ScannerName string
	Category    string
	Report      *sarif.Report
	Duration    time.Duration
	Error       error
}

// Orchestrator coordinates concurrent scanner execution.
type Orchestrator struct {
	scanners []Scanner
}

// NewOrchestrator creates a new Orchestrator instance with the specified scanners.
func NewOrchestrator(scanners ...Scanner) *Orchestrator {
	return &Orchestrator{
		scanners: scanners,
	}
}

// RegisterScanner adds a scanner to the orchestrator.
func (o *Orchestrator) RegisterScanner(s Scanner) {
	o.scanners = append(o.scanners, s)
}

// Scanners returns the registered scanners.
func (o *Orchestrator) Scanners() []Scanner {
	return o.scanners
}

// Run executes all available scanners concurrently and collects their results.
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

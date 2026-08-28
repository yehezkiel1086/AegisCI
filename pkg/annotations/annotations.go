package annotations

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yehezkiel1086/AegisCI/pkg/aggregator"
	"github.com/yehezkiel1086/AegisCI/pkg/config"
)

// Emitter formats security findings as GitHub Actions workflow command annotations.
type Emitter struct {
	writer io.Writer
}

// NewEmitter creates a new annotation emitter writing to the specified writer.
func NewEmitter(w io.Writer) *Emitter {
	if w == nil {
		w = os.Stdout
	}
	return &Emitter{writer: w}
}

// Emit outputs GitHub Actions inline annotations for all findings in the summary.
func (e *Emitter) Emit(summary *aggregator.Summary) {
	if summary == nil || len(summary.Findings) == 0 {
		return
	}

	for _, f := range summary.Findings {
		command := "warning"
		sevUpper := strings.ToUpper(f.Severity)

		if sevUpper == config.SeverityCritical || sevUpper == config.SeverityHigh {
			command = "error"
		} else if sevUpper == config.SeverityLow || sevUpper == config.SeverityNone {
			command = "notice"
		}

		filePath := escapeProperty(f.FilePath)
		line := f.Line
		title := escapeProperty(fmt.Sprintf("[%s] %s (%s)", f.Engine, f.RuleID, f.Severity))
		msg := escapeData(f.Message)

		if line > 0 && filePath != "" && filePath != "unknown" {
			fmt.Fprintf(e.writer, "::%s file=%s,line=%d,title=%s::%s\n", command, filePath, line, title, msg)
		} else if filePath != "" && filePath != "unknown" {
			fmt.Fprintf(e.writer, "::%s file=%s,title=%s::%s\n", command, filePath, title, msg)
		} else {
			fmt.Fprintf(e.writer, "::%s title=%s::%s\n", command, title, msg)
		}
	}
}

// escapeData escapes special characters in GitHub Workflow Command message bodies.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeProperty escapes special characters in GitHub Workflow Command property attributes.
func escapeProperty(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

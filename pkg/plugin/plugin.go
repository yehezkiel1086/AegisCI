package plugin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/yehezkiel1086/AegisCI/pkg/engine"
)

type Plugin interface {
	Name() string
	Version() string
	Category() string
	Execute(ctx context.Context, targetDir string) (*sarif.Report, error)
}

type ExecutablePlugin struct {
	BinaryPath string
	PluginName string
	Ver        string
	Cat        string
}

func (e *ExecutablePlugin) Name() string {
	if e.PluginName != "" {
		return e.PluginName
	}
	base := filepath.Base(e.BinaryPath)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func (e *ExecutablePlugin) Version() string {
	if e.Ver != "" {
		return e.Ver
	}
	return "1.0.0"
}

func (e *ExecutablePlugin) Category() string {
	if e.Cat != "" {
		return e.Cat
	}
	return "Custom Plugin"
}

func (e *ExecutablePlugin) Execute(ctx context.Context, targetDir string) (*sarif.Report, error) {
	tmpFile, err := os.CreateTemp("", "plugin-sarif-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for plugin output: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"--target", targetDir,
		"--output", tmpPath,
		"--format", "sarif",
	}

	cmd := exec.CommandContext(ctx, e.BinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()

	var data []byte
	if fileInfo, statErr := os.Stat(tmpPath); statErr == nil && fileInfo.Size() > 0 {
		data, _ = os.ReadFile(tmpPath)
	} else if stdout.Len() > 0 {
		data = stdout.Bytes()
	} else {
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI(e.Name(), "https://github.com/aegisci/plugins")
		report.AddRun(run)
		return report, nil
	}

	report, err := sarif.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("plugin '%s' output is not valid SARIF: %w (stderr: %s)", e.Name(), err, stderr.String())
	}

	return report, nil
}

type Adapter struct {
	plugin Plugin
}

func AsScanner(p Plugin) engine.Scanner {
	return &Adapter{plugin: p}
}

func (a *Adapter) Name() string     { return a.plugin.Name() }
func (a *Adapter) Category() string { return a.plugin.Category() }
func (a *Adapter) IsAvailable() bool {
	return true
}
func (a *Adapter) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	return a.plugin.Execute(ctx, targetDir)
}

func DiscoverPlugins(pluginsDir string) ([]Plugin, error) {
	var plugins []Plugin

	if _, err := os.Stat(pluginsDir); os.IsNotExist(err) {
		return plugins, nil
	}

	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugins directory %s: %w", pluginsDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fullPath := filepath.Join(pluginsDir, entry.Name())
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".sh" || ext == ".py" || ext == ".exe" || ext == ".bin" || ext == ".wasm" || ext == "" {
			plugins = append(plugins, &ExecutablePlugin{
				BinaryPath: fullPath,
				PluginName: name,
				Ver:        "1.0.0",
				Cat:        "Custom Plugin",
			})
		}
	}

	return plugins, nil
}

package detector

import (
	"os"
	"path/filepath"
	"strings"
)

type StackInfo struct {
	Languages      []string `json:"languages"`
	Frameworks     []string `json:"frameworks"`
	Infrastructure []string `json:"infrastructure"`
	HasGitRepo     bool     `json:"has_git_repo"`
	HasWorkflows   bool     `json:"has_workflows"`
}

func Detect(targetDir string) (*StackInfo, error) {
	info := &StackInfo{
		Languages:      make([]string, 0),
		Frameworks:     make([]string, 0),
		Infrastructure: make([]string, 0),
	}

	if _, err := os.Stat(filepath.Join(targetDir, ".git")); err == nil {
		info.HasGitRepo = true
	}

	if _, err := os.Stat(filepath.Join(targetDir, ".github", "workflows")); err == nil {
		info.HasWorkflows = true
	}

	langSet := make(map[string]bool)
	infraSet := make(map[string]bool)

	_ = filepath.Walk(targetDir, func(path string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(targetDir, path)
		if fileInfo.IsDir() {
			base := fileInfo.Name()
			if (strings.HasPrefix(base, ".") && base != ".") || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		name := strings.ToLower(fileInfo.Name())
		ext := strings.ToLower(filepath.Ext(fileInfo.Name()))

		switch {
		case name == "go.mod" || ext == ".go":
			langSet["Go"] = true
		case name == "package.json" || ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".jsx":
			langSet["JavaScript/TypeScript"] = true
		case name == "requirements.txt" || name == "pyproject.toml" || name == "pipfile" || ext == ".py":
			langSet["Python"] = true
		case name == "cargo.toml" || ext == ".rs":
			langSet["Rust"] = true
		case name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts" || ext == ".java" || ext == ".kt":
			langSet["Java/Kotlin"] = true
		case ext == ".cs" || name == "*.csproj":
			langSet["C#/.NET"] = true
		case ext == ".php":
			langSet["PHP"] = true
		case ext == ".rb" || name == "gemfile":
			langSet["Ruby"] = true
		case ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp":
			langSet["C/C++"] = true
		}

		switch {
		case name == "dockerfile" || name == "containerfile" || strings.HasPrefix(name, "docker-compose"):
			infraSet["Docker/Containers"] = true
		case ext == ".tf" || ext == ".tfvars":
			infraSet["Terraform"] = true
		case strings.Contains(relPath, "k8s") || strings.Contains(relPath, "helm") || name == "chart.yaml":
			infraSet["Kubernetes/Helm"] = true
		}

		return nil
	})

	for l := range langSet {
		info.Languages = append(info.Languages, l)
	}
	for i := range infraSet {
		info.Infrastructure = append(info.Infrastructure, i)
	}

	return info, nil
}

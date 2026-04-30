# Token-Saving Hints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add advisory messages to command responses that suggest token-saving alternatives when the user's command contains unnecessary `cd` to the current directory or uses absolute paths that could be relative.

**Architecture:** Create a `pkg/hint` package that analyzes commands against the current working directory and generates hint messages. The `service/server.go` `HandleRunCommand` method appends any hints to the formatted result before returning.

**Tech Stack:** Go, `mvdan.cc/sh/v3/syntax` (shell parser already in use)

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `pkg/hint/hint.go` | Core hint analysis: detect redundant `cd`, detect absolute paths convertible to relative |
| Create | `pkg/hint/hint_test.go` | Unit tests for hint generation |
| Modify | `service/server.go` | Call hint analysis before execution, append hints to response |
| Modify | `service/server_test.go` | Integration tests for hints appearing in tool results |

---

### Task 1: Create the hint package with redundant-cd detection

**Files:**
- Create: `pkg/hint/hint.go`
- Create: `pkg/hint/hint_test.go`

- [ ] **Step 1: Write failing tests for redundant-cd detection**

```go
// pkg/hint/hint_test.go
package hint

import (
	"testing"
)

func TestAnalyzeRedundantCd(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		workingDir string
		wantHint   bool
		wantMsg    string
	}{
		{
			name:       "cd to current dir with && is redundant",
			command:    "cd /home/user/project && ls",
			workingDir: "/home/user/project",
			wantHint:   true,
			wantMsg:    "ls",
		},
		{
			name:       "cd to current dir with semicolon is redundant",
			command:    "cd /home/user/project; ls",
			workingDir: "/home/user/project",
			wantHint:   true,
			wantMsg:    "ls",
		},
		{
			name:       "cd to different dir is not redundant",
			command:    "cd /other/dir && ls",
			workingDir: "/home/user/project",
			wantHint:   false,
		},
		{
			name:       "cd alone is not flagged",
			command:    "cd /home/user/project",
			workingDir: "/home/user/project",
			wantHint:   false,
		},
		{
			name:       "no cd at all",
			command:    "ls -la",
			workingDir: "/home/user/project",
			wantHint:   false,
		},
		{
			name:       "cd with trailing slash matches",
			command:    "cd /home/user/project/ && ls",
			workingDir: "/home/user/project",
			wantHint:   true,
			wantMsg:    "ls",
		},
		{
			name:       "multiple commands after cd",
			command:    "cd /home/user/project && ls && echo hello",
			workingDir: "/home/user/project",
			wantHint:   true,
			wantMsg:    "ls && echo hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hints := Analyze(tt.command, tt.workingDir)
			found := false
			for _, h := range hints {
				if h.Type == HintRedundantCd {
					found = true
					if tt.wantMsg != "" && !contains(h.Message, tt.wantMsg) {
						t.Errorf("expected hint message to contain %q, got %q", tt.wantMsg, h.Message)
					}
				}
			}
			if tt.wantHint && !found {
				t.Errorf("expected redundant cd hint, got none")
			}
			if !tt.wantHint && found {
				t.Errorf("did not expect redundant cd hint, but got one")
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race -run TestAnalyzeRedundantCd ./pkg/hint/`
Expected: FAIL — `Analyze` and `HintRedundantCd` not defined

- [ ] **Step 3: Write minimal implementation for redundant-cd detection**

```go
// pkg/hint/hint.go
package hint

import (
	"fmt"
	"path/filepath"
	"strings"
)

// HintType identifies the kind of token-saving hint.
type HintType int

const (
	// HintRedundantCd indicates an unnecessary cd to the current working directory.
	HintRedundantCd HintType = iota
	// HintAbsolutePathConvertible indicates an absolute path that could be relative.
	HintAbsolutePathConvertible
)

// Hint represents a single token-saving suggestion.
type Hint struct {
	Type    HintType
	Message string
}

// Analyze inspects a command string against the current working directory
// and returns any token-saving hints.
func Analyze(command string, workingDir string) []Hint {
	var hints []Hint

	if h, ok := checkRedundantCd(command, workingDir); ok {
		hints = append(hints, h)
	}

	hints = append(hints, checkAbsolutePaths(command, workingDir)...)

	return hints
}

// checkRedundantCd detects patterns like "cd /current/dir && cmd" or "cd /current/dir; cmd"
// where the cd target matches the current working directory.
func checkRedundantCd(command string, workingDir string) (Hint, bool) {
	if !strings.HasPrefix(command, "cd ") {
		return Hint{}, false
	}

	// Try to find the separator (&& or ;) after the cd command
	rest := command[3:] // after "cd "

	var cdTarget, remainder string
	if idx := strings.Index(rest, "&&"); idx != -1 {
		cdTarget = strings.TrimSpace(rest[:idx])
		remainder = strings.TrimSpace(rest[idx+2:])
	} else if idx := strings.Index(rest, ";"); idx != -1 {
		cdTarget = strings.TrimSpace(rest[:idx])
		remainder = strings.TrimSpace(rest[idx+1:])
	} else {
		// cd alone with no following command — not worth hinting
		return Hint{}, false
	}

	if remainder == "" {
		return Hint{}, false
	}

	// Normalize paths for comparison
	cleanTarget := filepath.Clean(cdTarget)
	cleanWorking := filepath.Clean(workingDir)

	if cleanTarget == cleanWorking {
		msg := fmt.Sprintf(
			"[Hint] The cd to %q is unnecessary — you are already in that directory. "+
				"You can save tokens by running just: %s",
			cdTarget, remainder,
		)
		return Hint{Type: HintRedundantCd, Message: msg}, true
	}

	return Hint{}, false
}

// checkAbsolutePaths is a placeholder — implemented in Task 2.
func checkAbsolutePaths(command string, workingDir string) []Hint {
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -race -run TestAnalyzeRedundantCd ./pkg/hint/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/hint/hint.go pkg/hint/hint_test.go
git commit -m "feat(hint): add redundant cd detection for token-saving hints"
```

---

### Task 2: Add absolute-path-to-relative detection

**Files:**
- Modify: `pkg/hint/hint.go` — implement `checkAbsolutePaths`
- Modify: `pkg/hint/hint_test.go` — add tests

- [ ] **Step 1: Write failing tests for absolute path detection**

Add to `pkg/hint/hint_test.go`:

```go
func TestAnalyzeAbsolutePath(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		workingDir string
		wantHint   bool
		wantMsg    string
	}{
		{
			name:       "absolute path as command can be relative",
			command:    "/home/user/project/bin/main",
			workingDir: "/home/user/project",
			wantHint:   true,
			wantMsg:    "./bin/main",
		},
		{
			name:       "absolute path as argument can be relative",
			command:    "cat /home/user/project/README.md",
			workingDir: "/home/user/project",
			wantHint:   true,
			wantMsg:    "./README.md",
		},
		{
			name:       "absolute path outside working dir is not flagged",
			command:    "cat /etc/hosts",
			workingDir: "/home/user/project",
			wantHint:   false,
		},
		{
			name:       "relative path is not flagged",
			command:    "cat ./README.md",
			workingDir: "/home/user/project",
			wantHint:   false,
		},
		{
			name:       "working dir path itself is flagged as .",
			command:    "ls /home/user/project",
			workingDir: "/home/user/project",
			wantHint:   true,
			wantMsg:    ".",
		},
		{
			name:       "multiple absolute paths generate hints",
			command:    "cp /home/user/project/a.txt /home/user/project/b.txt",
			workingDir: "/home/user/project",
			wantHint:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hints := Analyze(tt.command, tt.workingDir)
			found := false
			for _, h := range hints {
				if h.Type == HintAbsolutePathConvertible {
					found = true
					if tt.wantMsg != "" && !contains(h.Message, tt.wantMsg) {
						t.Errorf("expected hint message to contain %q, got %q", tt.wantMsg, h.Message)
					}
				}
			}
			if tt.wantHint && !found {
				t.Errorf("expected absolute path hint, got none")
			}
			if !tt.wantHint && found {
				t.Errorf("did not expect absolute path hint, but got one")
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race -run TestAnalyzeAbsolutePath ./pkg/hint/`
Expected: FAIL — `checkAbsolutePaths` returns nil (placeholder)

- [ ] **Step 3: Implement checkAbsolutePaths**

Replace the placeholder `checkAbsolutePaths` in `pkg/hint/hint.go`:

```go
// checkAbsolutePaths finds absolute paths in the command that are under workingDir
// and suggests shorter relative alternatives.
func checkAbsolutePaths(command string, workingDir string) []Hint {
	if workingDir == "" {
		return nil
	}

	cleanWorking := filepath.Clean(workingDir)
	// Ensure workingDir ends with separator for prefix matching
	prefix := cleanWorking + string(filepath.Separator)

	var hints []Hint
	seen := make(map[string]bool)

	// Split command into shell tokens (whitespace-separated).
	// This is a simple heuristic — does not handle quoting, but covers common cases.
	tokens := strings.Fields(command)
	for _, token := range tokens {
		if !filepath.IsAbs(token) {
			continue
		}

		cleanToken := filepath.Clean(token)

		if seen[cleanToken] {
			continue
		}
		seen[cleanToken] = true

		var relPath string
		if cleanToken == cleanWorking {
			relPath = "."
		} else if strings.HasPrefix(cleanToken, prefix) {
			relPath = "./" + cleanToken[len(prefix):]
		} else {
			continue
		}

		msg := fmt.Sprintf(
			"[Hint] %q can be shortened to %q (relative to current directory). "+
				"This saves tokens.",
			token, relPath,
		)
		hints = append(hints, Hint{Type: HintAbsolutePathConvertible, Message: msg})
	}

	return hints
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -race -run TestAnalyzeAbsolutePath ./pkg/hint/`
Expected: PASS

- [ ] **Step 5: Run all hint tests**

Run: `go test -race ./pkg/hint/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/hint/hint.go pkg/hint/hint_test.go
git commit -m "feat(hint): add absolute-to-relative path detection"
```

---

### Task 3: Integrate hints into server responses

**Files:**
- Modify: `service/server.go:172-224` — add hint generation and append to results

- [ ] **Step 1: Write failing integration test**

Add to `service/server_test.go`:

```go
func TestTokenSavingHints(t *testing.T) {
	srv, tmpDir := newTestServer(t)
	ctx := t.Context()

	// Set working directory first
	_, _ = srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
		"commands": []interface{}{"cd " + tmpDir},
		"mode":     "serial",
	}))

	t.Run("redundant cd shows hint", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + tmpDir + " && echo hello"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(result)
		if !strings.Contains(text, "[Hint]") {
			t.Fatalf("expected hint in output, got: %s", text)
		}
		if !strings.Contains(text, "echo hello") {
			t.Fatalf("expected suggested command in hint, got: %s", text)
		}
	})

	t.Run("absolute path shows hint", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo " + tmpDir},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(result)
		if !strings.Contains(text, "[Hint]") {
			t.Fatalf("expected hint in output, got: %s", text)
		}
	})

	t.Run("no hint when not needed", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo hello"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(result)
		if strings.Contains(text, "[Hint]") {
			t.Fatalf("did not expect hint, got: %s", text)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race -run TestTokenSavingHints ./service/`
Expected: FAIL — no hint logic in server yet

- [ ] **Step 3: Integrate hint generation into HandleRunCommand**

Modify `service/server.go`. Add the import:

```go
import (
	// ... existing imports ...
	"github.com/shimizu1995/secure-shell-server/pkg/hint"
)
```

Then modify `HandleRunCommand` to collect hints and append them. Replace the section after `var results` through `return formatResults(results), nil`:

```go
	// Collect token-saving hints for all commands
	var allHints []hint.Hint
	for _, cmd := range commands {
		allHints = append(allHints, hint.Analyze(cmd, workingDir)...)
	}

	var results []commandResult
	if mode == modeSerial {
		results = s.runSerial(ctx, commands, workingDir)
	} else {
		results = s.runParallel(ctx, commands, workingDir)
	}

	// Persist cd directory changes (existing logic unchanged)
	if mode == modeSerial || len(commands) == 1 {
		for i := len(results) - 1; i >= 0; i-- {
			if results[i].newWorkDir != "" {
				s.cmdMutex.Lock()
				s.workingDir = results[i].newWorkDir
				s.cmdMutex.Unlock()
				s.logger.LogInfof("Working directory updated by cd: %s", results[i].newWorkDir)
				break
			}
		}
	}

	return formatResultsWithHints(results, allHints), nil
```

Add the new `formatResultsWithHints` function:

```go
// formatResultsWithHints builds a tool result from command results, appending any token-saving hints.
func formatResultsWithHints(results []commandResult, hints []hint.Hint) *mcp.CallToolResult {
	result := formatResults(results)

	if len(hints) == 0 {
		return result
	}

	// Append hints to the existing text content
	var hintText strings.Builder
	hintText.WriteString("\n\n")
	for _, h := range hints {
		hintText.WriteString(h.Message)
		hintText.WriteString("\n")
	}

	// The result content is []mcp.Content; append a new text block
	result.Content = append(result.Content, mcp.TextContent{
		Type: "text",
		Text: hintText.String(),
	})

	return result
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -race -run TestTokenSavingHints ./service/`
Expected: PASS

- [ ] **Step 5: Run all tests**

Run: `go test -race ./...`
Expected: PASS

- [ ] **Step 6: Run linter**

Run: `make lint`
Expected: PASS (fix any issues if they arise)

- [ ] **Step 7: Commit**

```bash
git add service/server.go service/server_test.go
git commit -m "feat: integrate token-saving hints into run command responses"
```

---

### Task 4: Run full precommit validation

**Files:** None (validation only)

- [ ] **Step 1: Run make precommit**

Run: `make precommit`
Expected: PASS — build, lint, test, and vuln all green

- [ ] **Step 2: Fix any issues found**

If linter or tests fail, fix the issues and re-run.

- [ ] **Step 3: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: address lint/test issues from precommit"
```

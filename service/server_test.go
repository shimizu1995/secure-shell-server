package service_test

import (
	"os"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/service"
)

func TestNewServer(t *testing.T) {
	// Create a test configuration
	cfg := config.NewDefaultConfig()

	// Test with empty log path
	t.Run("with empty log path", func(t *testing.T) {
		server, err := service.NewServer(cfg, 8080, "")
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		if server == nil {
			t.Fatal("Server is nil")
		}
	})

	// Test with valid log path
	t.Run("with valid log path", func(t *testing.T) {
		// Create a temporary log file
		tmpDir := t.TempDir()
		logPath := tmpDir + "/server.log"

		server, err := service.NewServer(cfg, 8080, logPath)
		if err != nil {
			t.Fatalf("Failed to create server with log path: %v", err)
		}

		if server == nil {
			t.Fatal("Server is nil with log path")
		}
	})

	// Test with invalid log path
	t.Run("with invalid log path", func(t *testing.T) {
		// Use a path that shouldn't be writable
		logPath := "/nonexistent/directory/that/should/not/exist/server.log"

		_, err := service.NewServer(cfg, 8080, logPath)

		// This should fail
		if err == nil {
			t.Fatal("Expected error for invalid log path, but got nil")
		}
	})
}

// helper to build a CallToolRequest.
func makeToolRequest(args map[string]interface{}) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	return req
}

func newTestServer(t *testing.T) (*service.Server, string) {
	t.Helper()
	tmpDir := t.TempDir()

	cfg := &config.ShellCommandConfig{
		AllowedDirectories: []string{tmpDir},
		AllowCommands: []config.AllowCommand{
			{Command: "echo"},
			{Command: "pwd"},
			{Command: "ls"},
			{Command: "cd"},
		},
		DenyCommands:        []config.DenyCommand{},
		DefaultErrorMessage: "Command not allowed",
		MaxExecutionTime:    10,
		MaxOutputSize:       1024,
	}

	srv, err := service.NewServer(cfg, 0, "")
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	return srv, tmpDir
}

func TestPwd(t *testing.T) {
	srv, tmpDir := newTestServer(t)
	ctx := t.Context()

	t.Run("returns first allowed directory as default", func(t *testing.T) {
		// When no cd has been called and no useEnvPwd, pwd still works
		// because run defaults to the first allowed directory.
		// But pwd tool checks s.workingDir which is still empty initially.
		result, err := srv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "No working directory set")
	})

	t.Run("returns directory after cd via run", func(t *testing.T) {
		// Use cd within run (serial mode) to set working directory
		_, _ = srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + tmpDir},
			"mode":     "serial",
		}))
		result, err := srv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, tmpDir)
	})
}

func TestCdViaRun(t *testing.T) {
	srv, tmpDir := newTestServer(t)
	ctx := t.Context()

	t.Run("cd to allowed path succeeds", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + tmpDir},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, "")
	})

	t.Run("cd to disallowed path fails", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd /usr/local"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "not allowed")
	})

	t.Run("cd to nonexistent path fails", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + tmpDir + "/nonexistent"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "does not exist")
	})

	t.Run("cd without argument fails", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "directory argument required")
	})

	t.Run("cd - is blocked", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd -"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "not supported")
	})

	t.Run("cd persists across run calls in serial mode", func(t *testing.T) {
		// First call: cd to tmpDir in serial mode
		_, _ = srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + tmpDir},
			"mode":     "serial",
		}))

		// Second call: pwd should show tmpDir
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"pwd"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, tmpDir)
	})
}

func TestCdPersistence(t *testing.T) {
	ctx := t.Context()

	t.Run("cd with single command in parallel mode persists", func(t *testing.T) {
		freshSrv, freshTmpDir := newTestServer(t)

		// Single command in parallel mode — safe to persist
		_, _ = freshSrv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + freshTmpDir},
		}))

		result, err := freshSrv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, freshTmpDir)
	})

	t.Run("cd with multiple commands in parallel mode does not persist", func(t *testing.T) {
		freshSrv, freshTmpDir := newTestServer(t)
		subDir := freshTmpDir + "/parallel-sub"
		if err := makeDir(subDir); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}

		// Multiple commands in parallel mode — cd should not persist
		_, _ = freshSrv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + subDir, "echo hello"},
		}))

		// pwd should still show no working directory set
		result, err := freshSrv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "No working directory set")
	})

	t.Run("cd in serial mode persists", func(t *testing.T) {
		freshSrv, freshTmpDir := newTestServer(t)

		_, _ = freshSrv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + freshTmpDir},
			"mode":     "serial",
		}))

		result, err := freshSrv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, freshTmpDir)
	})

	t.Run("cd with relative path in serial mode", func(t *testing.T) {
		srv, tmpDir := newTestServer(t)
		subDir := tmpDir + "/subdir"
		if err := makeDir(subDir); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}

		// cd to tmpDir, then cd to relative subdir
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + tmpDir, "cd subdir", "pwd"},
			"mode":     "serial",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, subDir)
	})
}

func TestRunCommand(t *testing.T) {
	srv, tmpDir := newTestServer(t)
	ctx := t.Context()

	t.Run("run without explicit cd uses first allowed directory", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo hello"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, "hello")
	})

	t.Run("single command succeeds", func(t *testing.T) {
		_, _ = srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"cd " + tmpDir},
			"mode":     "serial",
		}))
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo hello"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, "hello")
	})

	t.Run("invalid mode returns error", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo hello"},
			"mode":     "invalid",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "Mode must be")
	})

	t.Run("empty commands array fails", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "non-empty array")
	})

	t.Run("empty string in commands fails", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{""},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "non-empty string")
	})

	t.Run("single string instead of array succeeds", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": "echo hello",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, "hello")
	})

	t.Run("empty single string instead of array fails", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": "",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "non-empty")
	})

	t.Run("directory persists across calls", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
				"commands": []interface{}{"echo persist"},
			}))
			if err != nil {
				t.Fatalf("run %d: unexpected error: %v", i, err)
			}
			assertToolSuccess(t, result, "persist")
		}
	})
}

func TestRunCommandMultiple(t *testing.T) {
	srv, tmpDir := newTestServer(t)
	ctx := t.Context()
	_, _ = srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
		"commands": []interface{}{"cd " + tmpDir},
		"mode":     "serial",
	}))

	t.Run("parallel default", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo aaa", "echo bbb"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(result)
		if !strings.Contains(text, "aaa") || !strings.Contains(text, "bbb") {
			t.Fatalf("expected both outputs, got: %s", text)
		}
	})

	t.Run("serial mode", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo first", "echo second"},
			"mode":     "serial",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(result)
		if !strings.Contains(text, "first") || !strings.Contains(text, "second") {
			t.Fatalf("expected both outputs, got: %s", text)
		}
	})

	t.Run("serial stops on first error", func(t *testing.T) {
		result, err := srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"rm forbidden", "echo should_not_run"},
			"mode":     "serial",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(result)
		if strings.Contains(text, "should_not_run") {
			t.Fatalf("serial mode should have stopped on first error, got: %s", text)
		}
		assertToolError(t, result, "Error")
	})
}

func TestUseEnvPwd(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := t.Context()

	t.Run("working directory set from PWD when useEnvPwd is true", func(t *testing.T) {
		t.Setenv("PWD", tmpDir)

		cfg := &config.ShellCommandConfig{
			AllowedDirectories: []string{tmpDir},
			AllowCommands: []config.AllowCommand{
				{Command: "echo"},
			},
			DenyCommands:        []config.DenyCommand{},
			DefaultErrorMessage: "Command not allowed",
			MaxExecutionTime:    10,
			MaxOutputSize:       1024,
			UseEnvPwd:           true,
		}

		srv, err := service.NewServer(cfg, 0, "")
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// pwd should return the directory without needing cd
		result, err := srv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, tmpDir)

		// run should work without needing cd
		result, err = srv.HandleRunCommand(ctx, makeToolRequest(map[string]interface{}{
			"commands": []interface{}{"echo hello"},
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolSuccess(t, result, "hello")
	})

	t.Run("PWD not in allowed directories is ignored", func(t *testing.T) {
		t.Setenv("PWD", "/usr/local/not-allowed")

		cfg := &config.ShellCommandConfig{
			AllowedDirectories: []string{tmpDir},
			AllowCommands: []config.AllowCommand{
				{Command: "echo"},
			},
			DenyCommands:        []config.DenyCommand{},
			DefaultErrorMessage: "Command not allowed",
			MaxExecutionTime:    10,
			MaxOutputSize:       1024,
			UseEnvPwd:           true,
		}

		srv, err := service.NewServer(cfg, 0, "")
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// pwd should return error since PWD was not in allowed dirs
		result, err := srv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "No working directory set")
	})

	t.Run("useEnvPwd false does not set working directory", func(t *testing.T) {
		t.Setenv("PWD", tmpDir)

		cfg := &config.ShellCommandConfig{
			AllowedDirectories: []string{tmpDir},
			AllowCommands: []config.AllowCommand{
				{Command: "echo"},
			},
			DenyCommands:        []config.DenyCommand{},
			DefaultErrorMessage: "Command not allowed",
			MaxExecutionTime:    10,
			MaxOutputSize:       1024,
			UseEnvPwd:           false,
		}

		srv, err := service.NewServer(cfg, 0, "")
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// pwd should return error since useEnvPwd is false
		result, err := srv.HandlePwd(ctx, makeToolRequest(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertToolError(t, result, "No working directory set")
	})
}

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
		if !strings.Contains(text, "unnecessary") {
			t.Fatalf("expected redundant cd hint, got: %s", text)
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

func assertToolError(t *testing.T, result *mcp.CallToolResult, contains string) {
	t.Helper()
	if !result.IsError {
		t.Fatalf("expected error result, got success")
	}
	text := extractText(result)
	if !strings.Contains(text, contains) {
		t.Fatalf("expected error containing %q, got: %s", contains, text)
	}
}

func assertToolSuccess(t *testing.T, result *mcp.CallToolResult, contains string) {
	t.Helper()
	if result.IsError {
		t.Fatalf("expected success, got error: %s", extractText(result))
	}
	text := extractText(result)
	if !strings.Contains(text, contains) {
		t.Fatalf("expected output containing %q, got: %s", contains, text)
	}
}

func extractText(result *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func makeDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

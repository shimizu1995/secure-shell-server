package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
	"github.com/shimizu1995/secure-shell-server/pkg/runner"
	"github.com/shimizu1995/secure-shell-server/pkg/validator"
)

func newTestRunner() *runner.SafeRunner {
	cfg := &config.ShellCommandConfig{
		AllowedDirectories: []string{"/tmp"},
		AllowCommands: []config.AllowCommand{
			{Command: "echo"},
			{Command: "ls"},
			{Command: "grep"},
		},
		DenyCommands: []config.DenyCommand{
			{Command: "rm", Message: "Remove command is not allowed"},
		},
		DefaultErrorMessage: "Command not allowed by security policy",
		MaxExecutionTime:    config.DefaultExecutionTimeout,
	}
	log := logger.New()
	return runner.New(cfg, validator.New(cfg, log), log)
}

func TestRunHookMode(t *testing.T) {
	tests := []struct {
		name        string
		stdin       string
		wantExit    int
		wantStderr  string
		stderrEmpty bool
	}{
		{
			name:        "AllowedCommand",
			stdin:       `{"tool_name":"Bash","tool_input":{"command":"echo hi","cwd":"/tmp"}}`,
			wantExit:    0,
			stderrEmpty: true,
		},
		{
			name:       "DeniedCommand",
			stdin:      `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x","cwd":"/tmp"}}`,
			wantExit:   2,
			wantStderr: "Blocked by secure-shell-server",
		},
		{
			name:       "NotInAllowList",
			stdin:      `{"tool_name":"Bash","tool_input":{"command":"chmod 777 a","cwd":"/tmp"}}`,
			wantExit:   2,
			wantStderr: "is not permitted",
		},
		{
			name:       "DeniedInPipeline",
			stdin:      `{"tool_name":"Bash","tool_input":{"command":"echo x | rm -rf /tmp/y","cwd":"/tmp"}}`,
			wantExit:   2,
			wantStderr: "command \"rm\" is denied",
		},
		{
			name:        "NonBashToolPassthrough",
			stdin:       `{"tool_name":"Read","tool_input":{"command":"rm -rf /","cwd":"/tmp"}}`,
			wantExit:    0,
			stderrEmpty: true,
		},
		{
			name:        "EmptyCommand",
			stdin:       `{"tool_name":"Bash","tool_input":{"command":"","cwd":"/tmp"}}`,
			wantExit:    0,
			stderrEmpty: true,
		},
		{
			name:       "InvalidJSON",
			stdin:      `not json`,
			wantExit:   1,
			wantStderr: "failed to parse stdin JSON",
		},
		{
			name:       "DirectoryNotAllowed",
			stdin:      `{"tool_name":"Bash","tool_input":{"command":"echo hi","cwd":"/etc"}}`,
			wantExit:   2,
			wantStderr: "directory validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRunner()
			var stderr bytes.Buffer
			exit := runHookMode(t.Context(), r, "", strings.NewReader(tt.stdin), &stderr)
			assert.Equal(t, tt.wantExit, exit)
			if tt.stderrEmpty {
				assert.Equal(t, "", stderr.String())
				return
			}
			assert.Contains(t, stderr.String(), tt.wantStderr)
		})
	}
}

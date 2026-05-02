package runner

import (
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/shimizu1995/secure-shell-server/pkg/logger"
	"github.com/shimizu1995/secure-shell-server/pkg/validator"
)

func TestSafeRunner_ValidateScript(t *testing.T) {
	cfg := setupCustomConfig()
	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)

	tests := []struct {
		name        string
		command     string
		wantErr     bool
		errContains string
	}{
		{name: "AllowedSimple", command: "echo hello", wantErr: false},
		{name: "AllowedPipeline", command: "echo hi | grep hi", wantErr: false},
		{name: "DeniedCommand", command: "rm -rf /tmp/x", wantErr: true, errContains: "command \"rm\" is denied"},
		{name: "NotInAllowList", command: "chmod 777 a", wantErr: true, errContains: "command \"chmod\" is not permitted"},
		{name: "DeniedInPipeline", command: "echo x | sudo cat", wantErr: true, errContains: "command \"sudo\" is denied"},
		{name: "ParseError", command: "echo 'unclosed", wantErr: true, errContains: "parse error"},
		{name: "EmptyCommand", command: "", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := safeRunner.ValidateScript(t.Context(), tt.command, "/tmp")
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestSafeRunner_ValidateScript_DoesNotExecute(t *testing.T) {
	cfg := setupCustomConfig()
	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)

	target := "/tmp/secure-shell-validate-marker.txt"
	_ = os.Remove(target)
	t.Cleanup(func() { _ = os.Remove(target) })

	err := safeRunner.ValidateScript(t.Context(), "echo hi > "+target, "/tmp")
	assert.NoError(t, err)

	_, statErr := os.Stat(target)
	assert.Error(t, statErr, "ValidateScript must not actually create files via redirection")
}

func TestSafeRunner_ValidateScript_DirectoryNotAllowed(t *testing.T) {
	cfg := setupCustomConfig()
	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)

	err := safeRunner.ValidateScript(t.Context(), "echo hi", "/etc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "directory validation failed")
}

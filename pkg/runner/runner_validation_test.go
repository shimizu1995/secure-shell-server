package runner

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
	"github.com/shimizu1995/secure-shell-server/pkg/validator"
)

func setupCustomConfig() *config.ShellCommandConfig {
	return &config.ShellCommandConfig{
		AllowedDirectories: []string{"/home", "/tmp"},
		AllowCommands: []config.AllowCommand{
			{Command: "ls"},
			{Command: "cat"},
			{Command: "echo"},
			{Command: "grep"},
			{Command: "find"},
			{Command: "git", SubCommands: []config.SubCommandRule{{Name: "status"}, {Name: "log"}, {Name: "diff"}}, DenySubCommands: []string{"push", "commit"}},
		},
		DenyCommands: []config.DenyCommand{
			{Command: "rm", Message: "Remove command is not allowed"},
			{Command: "sudo", Message: "Sudo is not allowed for security reasons"},
		},
		DefaultErrorMessage: "Command not allowed by security policy",
		MaxExecutionTime:    config.DefaultExecutionTimeout,
	}
}

func TestSafeRunner_CommandValidation(t *testing.T) {
	cfg := setupCustomConfig()
	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)

	// Set up the runner but don't capture output for validation tests
	// This avoids data races with concurrent command execution
	safeRunner.SetOutputs(io.Discard, io.Discard)

	// 基本的な許可されたコマンド
	t.Run("BasicAllowedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo hello", "/tmp")
		assert.NoError(t, result.Err)
	})

	// 複数行の許可されたコマンド
	t.Run("MultilineAllowedCommands", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo hello\nls -l", "/tmp")
		assert.NoError(t, result.Err)
	})

	// 明示的に拒否されたコマンド
	t.Run("ExplicitlyDeniedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "rm -rf /tmp/test", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"rm\" is denied: Remove command is not allowed")
	})

	// 許可リストにないコマンド
	t.Run("CommandNotInAllowList", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "chmod 777 file.txt", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"chmod\" is not permitted: Command not allowed by security policy")
	})

	// コマンドの構文エラー
	t.Run("SyntaxErrorInCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo 'unclosed string", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "parse error: ")
	})

	// リダイレクションを持つコマンド
	t.Run("CommandWithRedirection", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo hello > /tmp/test.txt", "/tmp")
		assert.NoError(t, result.Err)
	})

	// 空のコマンド
	t.Run("EmptyCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "", "/tmp")
		assert.NoError(t, result.Err)
	})
}

func TestSafeRunner_AbsolutePathCommandNormalization(t *testing.T) {
	cfg := setupCustomConfig()
	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)
	safeRunner.SetOutputs(io.Discard, io.Discard)

	// /usr/bin/rm should be blocked as "rm" (which is in denyCommands)
	t.Run("AbsolutePathDeniedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "/bin/rm -rf /tmp/test", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"rm\" is denied")
	})

	// /bin/echo should be allowed as "echo" (which is in allowCommands)
	t.Run("AbsolutePathAllowedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "/bin/echo hello", "/tmp")
		assert.NoError(t, result.Err)
	})

	// /usr/bin/wget should be blocked (not in allowCommands)
	t.Run("AbsolutePathUnlistedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "/usr/bin/wget https://example.com", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"wget\" is not permitted")
	})
}

func TestSafeRunner_CdDenyCommand(t *testing.T) {
	cfg := setupCustomConfig()
	cfg.AllowCommands = append(cfg.AllowCommands, config.AllowCommand{Command: "cd"})
	cfg.DenyCommands = append(cfg.DenyCommands, config.DenyCommand{
		Command: "cd",
		Message: "cd is not allowed, specify directory in arguments instead",
	})

	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)
	safeRunner.SetOutputs(io.Discard, io.Discard)

	// cd should be blocked when in denyCommands (deny takes precedence)
	t.Run("CdBlockedWhenDenied", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "cd /tmp", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"cd\" is denied")
	})

	// cd in a chain should also be blocked
	t.Run("CdInSerialCommandsBlockedWhenDenied", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "cd /tmp && echo hello", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"cd\" is denied")
	})
}

func TestSafeRunner_CdNotInAllowList(t *testing.T) {
	cfg := setupCustomConfig()
	// cd is not in allowCommands and not in denyCommands — should be blocked as "not permitted"
	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)
	safeRunner.SetOutputs(io.Discard, io.Discard)

	t.Run("CdBlockedWhenNotInAllowList", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "cd /tmp", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"cd\" is not permitted")
	})
}

func TestSafeRunner_CdAllowed(t *testing.T) {
	cfg := setupCustomConfig()
	cfg.AllowCommands = append(cfg.AllowCommands, config.AllowCommand{Command: "cd"})

	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)
	safeRunner.SetOutputs(io.Discard, io.Discard)

	t.Run("CdWorksWhenInAllowList", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "cd /tmp", "/tmp")
		assert.NoError(t, result.Err)
		expected, evalErr := filepath.EvalSymlinks("/tmp")
		assert.NoError(t, evalErr)
		assert.Equal(t, expected, result.NewWorkDir)
	})

	t.Run("CdBlockedForDisallowedDirectory", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "cd /etc", "/tmp")
		assert.Error(t, result.Err)
	})
}

func TestSafeRunner_PipelineValidation(t *testing.T) {
	cfg := setupCustomConfig()
	// パイプラインテスト用にprintf コマンドを許可リストに追加
	cfg.AllowCommands = append(cfg.AllowCommands, config.AllowCommand{Command: "printf"})

	log := logger.New()
	validatorObj := validator.New(cfg, log)
	safeRunner := New(cfg, validatorObj, log)

	// Set up the runner but don't capture output for validation tests
	safeRunner.SetOutputs(io.Discard, io.Discard)

	// すべて許可されたコマンドのパイプライン
	t.Run("AllAllowedCommands", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo 'hello' | grep hello", "/tmp")
		assert.NoError(t, result.Err)
	})

	// 1つの拒否されたコマンドを含むパイプライン
	t.Run("OneDisallowedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo 'hello world' | grep hello | sudo cat", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"sudo\" is denied")
	})

	// 中間に拒否されたコマンドを含む複雑なパイプライン
	t.Run("ComplexPipelineWithDisallowedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo 'test' | sudo grep test | cat", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"sudo\" is denied")
	})

	// 許可リストにないコマンドを含むパイプライン
	t.Run("CommandNotInAllowlist", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo 'test' | grep test | awk '{print $1}'", "/tmp")
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "command \"awk\" is not permitted")
	})

	// シンプルな許可されたコマンド
	t.Run("SimpleAllowedCommand", func(t *testing.T) {
		ctx := t.Context()
		result := safeRunner.RunCommand(ctx, "echo 'single command'", "/tmp")
		assert.NoError(t, result.Err)
	})
}

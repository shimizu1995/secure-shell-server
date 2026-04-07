package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/limiter"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
	"github.com/shimizu1995/secure-shell-server/pkg/validator"
)

// SafeRunner executes shell commands securely.
type SafeRunner struct {
	config    *config.ShellCommandConfig
	validator *validator.CommandValidator
	logger    *logger.Logger
	stdout    io.Writer
	stderr    io.Writer
	// Output limiters to track truncation
	stdoutLimiter *limiter.OutputLimiter
	stderrLimiter *limiter.OutputLimiter
}

// New creates a new SafeRunner.
func New(config *config.ShellCommandConfig, validator *validator.CommandValidator, logger *logger.Logger) *SafeRunner {
	return &SafeRunner{
		config:        config,
		validator:     validator,
		logger:        logger,
		stdout:        os.Stdout,
		stderr:        os.Stderr,
		stdoutLimiter: nil,
		stderrLimiter: nil,
	}
}

// SetOutputs sets the stdout and stderr writers.
func (r *SafeRunner) SetOutputs(stdout, stderr io.Writer) {
	// If MaxOutputSize is set, wrap the writers with limiters
	if r.config.MaxOutputSize > 0 {
		r.stdoutLimiter = limiter.NewOutputLimiter(stdout, r.config.MaxOutputSize)
		r.stderrLimiter = limiter.NewOutputLimiter(stderr, r.config.MaxOutputSize)
		r.stdout = r.stdoutLimiter
		r.stderr = r.stderrLimiter
	} else {
		// Use the writers directly if no limit is set
		r.stdout = stdout
		r.stderr = stderr
		r.stdoutLimiter = nil
		r.stderrLimiter = nil
	}
}

// RunCommand runs a shell command in the specified working directory.
// It enforces security constraints by validating commands and file access.
// WasOutputTruncated returns whether stdout or stderr was truncated due to size limits.
func (r *SafeRunner) WasOutputTruncated() bool {
	if r.stdoutLimiter != nil && r.stdoutLimiter.WasTruncated() {
		return true
	}
	if r.stderrLimiter != nil && r.stderrLimiter.WasTruncated() {
		return true
	}
	return false
}

// GetTruncationStatus returns detailed information about which outputs were truncated.
func (r *SafeRunner) GetTruncationStatus() (stdoutTruncated bool, stderrTruncated bool) {
	stdoutTruncated = r.stdoutLimiter != nil && r.stdoutLimiter.WasTruncated()
	stderrTruncated = r.stderrLimiter != nil && r.stderrLimiter.WasTruncated()
	return
}

// GetTruncationDetails returns detailed information about truncation, including which
// outputs were truncated and how many bytes remained unwritten for each.
func (r *SafeRunner) GetTruncationDetails() (stdoutTruncated bool, stderrTruncated bool, stdoutRemainingBytes int, stderrRemainingBytes int) {
	stdoutTruncated = r.stdoutLimiter != nil && r.stdoutLimiter.WasTruncated()
	stderrTruncated = r.stderrLimiter != nil && r.stderrLimiter.WasTruncated()

	stdoutRemainingBytes = 0
	if stdoutTruncated {
		stdoutRemainingBytes = r.stdoutLimiter.GetRemainingBytes()
	}

	stderrRemainingBytes = 0
	if stderrTruncated {
		stderrRemainingBytes = r.stderrLimiter.GetRemainingBytes()
	}

	return
}

// RunCommand runs a shell command in the specified working directory.
// It enforces security constraints by validating commands and file access.
// It returns the new working directory if cd was used (empty string if unchanged),
// and any execution error.
func (r *SafeRunner) RunCommand(ctx context.Context, command string, workingDir string) (string, error) {
	// Get absolute path of the working directory
	absWorkingDir, err := filepath.Abs(workingDir)
	if err != nil {
		r.logger.LogErrorf("Failed to get absolute path for working directory: %v", err)
		return "", fmt.Errorf("failed to get absolute path for working directory: %w", err)
	}

	// Validate that the working directory is allowed
	dirAllowed, dirMessage := r.validator.IsDirectoryAllowed(absWorkingDir)
	if !dirAllowed {
		r.logger.LogErrorf("Directory validation failed: %s", dirMessage)
		return "", fmt.Errorf("directory validation failed: %s", dirMessage)
	}

	// Parse the command
	parser := syntax.NewParser()
	prog, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		r.logger.LogErrorf("Parse error: %v", err)
		return "", fmt.Errorf("parse error: %w", err)
	}

	// Create a timeout context if MaxExecutionTime is set
	if r.config.MaxExecutionTime > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(r.config.MaxExecutionTime)*time.Second)
		defer cancel()
		ctx = timeoutCtx
	}

	// Track the last directory set by cd
	var lastCdDir string

	callFunc := func(callCtx context.Context, args []string) ([]string, error) {
		cmd := args[0]

		// Normalize absolute path commands to basename for validation
		// e.g., /usr/bin/rm → rm, so deny/allow rules match correctly
		cmdForValidation := cmd
		if filepath.IsAbs(cmd) {
			cmdForValidation = filepath.Base(cmd)
		}

		// Validate all commands (including cd) through the same pipeline
		allowed, errMsg := r.validator.ValidateCommand(cmdForValidation, args[1:], absWorkingDir)
		if !allowed {
			r.logger.LogCommandAttempt(cmd, args[1:], false)
			return args, fmt.Errorf("%s", errMsg)
		}

		// Handle cd as a shell builtin after validation passes
		if cmdForValidation == "cd" {
			return r.handleCdCall(callCtx, args, &lastCdDir)
		}

		r.logger.LogCommandAttempt(cmd, args[1:], true)

		return args, nil
	}

	// Create interpreter
	interpRunner, err := interp.New(
		interp.CallHandler(callFunc),
		interp.StdIO(nil, r.stdout, r.stderr),
		interp.Env(nil),
		interp.Dir(absWorkingDir),
		interp.OpenHandler(r.secureOpenHandler),
	)
	if err != nil {
		r.logger.LogErrorf("Interpreter creation error: %v", err)
		return "", fmt.Errorf("interpreter creation error: %w", err)
	}

	err = interpRunner.Run(ctx, prog)
	return lastCdDir, err
}

// ValidateScript parses the given shell script and validates every command
// against the configured allow/deny lists without executing anything.
// It returns nil if all commands are allowed, or an error describing the first
// disallowed command (matching the message produced by RunCommand).
func (r *SafeRunner) ValidateScript(ctx context.Context, command string, workingDir string) error {
	absWorkingDir, err := filepath.Abs(workingDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for working directory: %w", err)
	}

	dirAllowed, dirMessage := r.validator.IsDirectoryAllowed(absWorkingDir)
	if !dirAllowed {
		return fmt.Errorf("directory validation failed: %s", dirMessage)
	}

	parser := syntax.NewParser()
	prog, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	var lastCdDir string
	callFunc := func(callCtx context.Context, args []string) ([]string, error) {
		if len(args) == 0 {
			return args, nil
		}
		cmd := args[0]
		cmdForValidation := cmd
		if filepath.IsAbs(cmd) {
			cmdForValidation = filepath.Base(cmd)
		}
		allowed, errMsg := r.validator.ValidateCommand(cmdForValidation, args[1:], absWorkingDir)
		if !allowed {
			return args, fmt.Errorf("%s", errMsg)
		}
		if cmdForValidation == "cd" {
			return r.handleCdCall(callCtx, args, &lastCdDir)
		}
		return args, nil
	}

	// ExecHandler that performs no actual execution.
	noopExec := func(_ context.Context, _ []string) error { return nil }

	// OpenHandler that validates the directory but never opens real files.
	validateOnlyOpen := func(_ context.Context, path string, _ int, _ os.FileMode) (io.ReadWriteCloser, error) {
		absPath, absErr := filepath.Abs(path)
		if absErr != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: absErr}
		}
		if resolved, resolveErr := filepath.EvalSymlinks(absPath); resolveErr == nil {
			absPath = resolved
		}
		fileDir := filepath.Dir(absPath)
		allowed, msg := r.validator.IsDirectoryAllowed(fileDir)
		if !allowed {
			return nil, &os.PathError{
				Op:   "open",
				Path: path,
				Err:  fmt.Errorf("access denied: file is outside allowed directories: %s", msg),
			}
		}
		return discardRWC{}, nil
	}

	interpRunner, err := interp.New(
		interp.CallHandler(callFunc),
		interp.ExecHandlers(func(_ interp.ExecHandlerFunc) interp.ExecHandlerFunc { return noopExec }),
		interp.StdIO(nil, io.Discard, io.Discard),
		interp.Env(nil),
		interp.Dir(absWorkingDir),
		interp.OpenHandler(validateOnlyOpen),
	)
	if err != nil {
		return fmt.Errorf("interpreter creation error: %w", err)
	}

	if err := interpRunner.Run(ctx, prog); err != nil {
		return err
	}
	return nil
}

// discardRWC is an io.ReadWriteCloser that discards writes and returns EOF on read.
type discardRWC struct{}

func (discardRWC) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (discardRWC) Write(p []byte) (int, error) { return len(p), nil }
func (discardRWC) Close() error                { return nil }

// secureOpenHandler validates file access against allowed directories before opening.
func (r *SafeRunner) secureOpenHandler(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
	absPath, absErr := filepath.Abs(path)
	if absErr != nil {
		r.logger.LogErrorf("Failed to get absolute path for file %s: %v", path, absErr)
		return nil, &os.PathError{Op: "open", Path: path, Err: absErr}
	}

	// Resolve symlinks to prevent directory escape via symlinks
	if resolved, resolveErr := filepath.EvalSymlinks(absPath); resolveErr == nil {
		absPath = resolved
	}

	// Check if file's directory is in the allowed list
	fileDir := filepath.Dir(absPath)
	allowed, msg := r.validator.IsDirectoryAllowed(fileDir)
	if !allowed {
		r.logger.LogErrorf("File access attempted outside allowed directories: %s", absPath)
		return nil, &os.PathError{
			Op:   "open",
			Path: path,
			Err:  fmt.Errorf("access denied: file is outside allowed directories: %s", msg),
		}
	}

	return interp.DefaultOpenHandler()(ctx, path, flag, perm)
}

// handleCdCall validates a cd command against allowed directories.
// It resolves the target path relative to the interpreter's current directory,
// checks it against the allowlist, and tracks the resolved path.
func (r *SafeRunner) handleCdCall(ctx context.Context, args []string, lastCdDir *string) ([]string, error) {
	if len(args) < 2 { //nolint:mnd // cd requires at least one argument
		return args, errors.New("cd: directory argument required")
	}

	target := args[1]
	if target == "-" {
		return args, errors.New("cd: cd - is not supported for security reasons")
	}

	// Resolve relative paths against the interpreter's current directory
	currentDir := interp.HandlerCtx(ctx).Dir
	var absTarget string
	if filepath.IsAbs(target) {
		absTarget = filepath.Clean(target)
	} else {
		absTarget = filepath.Clean(filepath.Join(currentDir, target))
	}

	// Resolve symlinks to prevent directory escape
	if resolved, resolveErr := filepath.EvalSymlinks(absTarget); resolveErr == nil {
		absTarget = resolved
	}

	// Validate against allowed directories
	allowed, msg := r.validator.IsDirectoryAllowed(absTarget)
	if !allowed {
		r.logger.LogCommandAttempt("cd", args[1:], false)
		return args, fmt.Errorf("cd: %s", msg)
	}

	// Check directory exists
	info, err := os.Stat(absTarget)
	if err != nil || !info.IsDir() {
		return args, fmt.Errorf("cd: directory does not exist: %s", absTarget)
	}

	*lastCdDir = absTarget
	r.logger.LogCommandAttempt("cd", args[1:], true)
	return args, nil
}

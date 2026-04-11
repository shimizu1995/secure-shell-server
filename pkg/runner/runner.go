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
	"github.com/shimizu1995/secure-shell-server/pkg/hint"
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
	// hints collected during command execution, returned via RunResult
	hints []hint.Hint
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

// RunResult holds the result of a command execution.
type RunResult struct {
	// NewWorkDir is the new working directory if cd was used (empty if unchanged).
	NewWorkDir string
	// Hints contains token-saving suggestions collected during execution.
	Hints []hint.Hint
	// Err is the execution error, if any.
	Err error
}

// RunCommand runs a shell command in the specified working directory.
// It enforces security constraints by validating commands and file access.
func (r *SafeRunner) RunCommand(ctx context.Context, command string, workingDir string) RunResult {
	// Get absolute path of the working directory
	absWorkingDir, err := filepath.Abs(workingDir)
	if err != nil {
		r.logger.LogErrorf("Failed to get absolute path for working directory: %v", err)
		return RunResult{Err: fmt.Errorf("failed to get absolute path for working directory: %w", err)}
	}

	// Validate that the working directory is allowed
	dirAllowed, dirMessage := r.validator.IsDirectoryAllowed(absWorkingDir)
	if !dirAllowed {
		r.logger.LogErrorf("Directory validation failed: %s", dirMessage)
		return RunResult{Err: fmt.Errorf("directory validation failed: %s", dirMessage)}
	}

	// Parse the command
	parser := syntax.NewParser()
	prog, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		r.logger.LogErrorf("Parse error: %v", err)
		return RunResult{Err: fmt.Errorf("parse error: %w", err)}
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

		// Collect token-saving hints
		r.collectHints(cmdForValidation, args, absWorkingDir)

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
		return RunResult{Err: fmt.Errorf("interpreter creation error: %w", err)}
	}

	err = interpRunner.Run(ctx, prog)
	return RunResult{NewWorkDir: lastCdDir, Hints: r.hints, Err: err}
}

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

// collectHints checks the parsed command and arguments for token-saving opportunities.
func (r *SafeRunner) collectHints(cmd string, args []string, workingDir string) {
	cleanWorking := filepath.Clean(workingDir)
	prefix := cleanWorking + string(filepath.Separator)

	// Check for redundant cd (cd to current working directory)
	redundantCdTarget := ""
	if cmd == "cd" && len(args) > 1 {
		target := args[1]
		cleanTarget := filepath.Clean(target)
		if filepath.IsAbs(cleanTarget) && cleanTarget == cleanWorking {
			redundantCdTarget = cleanTarget
			r.hints = append(r.hints, hint.Hint{
				Type: hint.RedundantCd,
				Message: fmt.Sprintf(
					"[Hint] The cd to %q is unnecessary — you are already in that directory.",
					target,
				),
			})
		}
	}

	// Check for absolute paths that could be relative
	seen := make(map[string]bool)
	for _, arg := range args {
		if !filepath.IsAbs(arg) {
			continue
		}
		cleanArg := filepath.Clean(arg)

		// Skip if already covered by redundant cd hint
		if cleanArg == redundantCdTarget {
			continue
		}

		// Skip duplicates
		if seen[cleanArg] {
			continue
		}
		seen[cleanArg] = true

		var relPath string
		switch {
		case cleanArg == cleanWorking:
			relPath = "."
		case strings.HasPrefix(cleanArg, prefix):
			relPath = "./" + cleanArg[len(prefix):]
		default:
			continue
		}
		r.hints = append(r.hints, hint.Hint{
			Type: hint.AbsolutePathConvertible,
			Message: fmt.Sprintf(
				"[Hint] %q can be shortened to %q (relative to current directory).",
				arg, relPath,
			),
		})
	}
}

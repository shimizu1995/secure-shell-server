package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
	"github.com/shimizu1995/secure-shell-server/pkg/validator"
)

// SafeRunner executes shell commands securely.
type SafeRunner struct {
	config    *config.ShellConfig
	validator *validator.CommandValidator
	logger    *logger.Logger
	stdout    io.Writer
	stderr    io.Writer
}

// New creates a new SafeRunner.
func New(config *config.ShellConfig, validator *validator.CommandValidator, logger *logger.Logger) *SafeRunner {
	return &SafeRunner{
		config:    config,
		validator: validator,
		logger:    logger,
		stdout:    os.Stdout,
		stderr:    os.Stderr,
	}
}

// SetOutputs sets the stdout and stderr writers.
func (r *SafeRunner) SetOutputs(stdout, stderr io.Writer) {
	r.stdout = stdout
	r.stderr = stderr
}

// Run runs a shell command with args.
func (r *SafeRunner) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("no command provided")
	}

	cmd := args[0]
	if !r.config.IsCommandAllowed(cmd) {
		r.logger.LogCommandAttempt(cmd, args[1:], false)
		return fmt.Errorf("command %q is not permitted", cmd)
	}

	r.logger.LogCommandAttempt(cmd, args[1:], true)

	// Create a timeout context if MaxExecutionTime is set
	if r.config.MaxExecutionTime > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(r.config.MaxExecutionTime)*time.Second)
		defer cancel()
		ctx = timeoutCtx
	}

	// Execute the command
	command := exec.CommandContext(ctx, cmd, args[1:]...)

	// Set environment variables
	if len(r.config.RestrictedEnv) > 0 {
		env := make([]string, 0, len(r.config.RestrictedEnv))
		for k, v := range r.config.RestrictedEnv {
			env = append(env, k+"="+v)
		}
		command.Env = env
	}

	// Set working directory if specified
	if r.config.WorkingDir != "" {
		command.Dir = r.config.WorkingDir
	}

	// Set output streams
	command.Stdout = r.stdout
	command.Stderr = r.stderr

	// Run the command
	err := command.Run()
	if err != nil {
		r.logger.LogErrorf("Command execution error: %v", err)
		return fmt.Errorf("command execution error: %w", err)
	}

	return nil
}

// RunScript runs a shell script.
func (r *SafeRunner) RunScript(ctx context.Context, script string) error {
	// Validate script
	valid, err := r.validator.ValidateScript(script)
	if !valid || err != nil {
		return fmt.Errorf("script validation failed: %w", err)
	}

	// Parse the script
	parser := syntax.NewParser()
	prog, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		r.logger.LogErrorf("Parse error: %v", err)
		return fmt.Errorf("parse error: %w", err)
	}

	// Create a custom runner for interp
	execHandler := func(ctx context.Context, args []string) error {
		return r.Run(ctx, args)
	}

	// Set a timeout context if MaxExecutionTime is set
	if r.config.MaxExecutionTime > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(r.config.MaxExecutionTime)*time.Second)
		defer cancel()
		ctx = timeoutCtx
	}

	// Convert map to environment string pairs
	envPairs := make([]string, 0, len(r.config.RestrictedEnv))
	for k, v := range r.config.RestrictedEnv {
		envPairs = append(envPairs, k+"="+v)
	}

	// Run the script with proper options
	runner, err := interp.New(
		interp.ExecHandlers(func(_ interp.ExecHandlerFunc) interp.ExecHandlerFunc {
			return execHandler
		}),
		interp.StdIO(nil, r.stdout, r.stderr),
		interp.Env(expand.ListEnviron(envPairs...)),
	)
	// Run the script
	if err != nil {
		r.logger.LogErrorf("Interpreter creation error: %v", err)
		return fmt.Errorf("interpreter creation error: %w", err)
	}

	err = runner.Run(ctx, prog)
	if err != nil {
		r.logger.LogErrorf("Script execution error: %v", err)
		return fmt.Errorf("script execution error: %w", err)
	}

	return nil
}

// RunScriptFile runs a shell script from a reader.
func (r *SafeRunner) RunScriptFile(ctx context.Context, reader io.Reader) error {
	// Read the script first to validate it
	scriptBytes, err := io.ReadAll(reader)
	if err != nil {
		r.logger.LogErrorf("Script reading error: %v", err)
		return fmt.Errorf("script reading error: %w", err)
	}

	script := string(scriptBytes)

	// Now run the script
	return r.RunScript(ctx, script)
}

package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/hint"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
	"github.com/shimizu1995/secure-shell-server/pkg/runner"
	"github.com/shimizu1995/secure-shell-server/pkg/validator"
)

// createRunTool creates the run tool for executing shell commands.
func createRunTool() mcp.Tool {
	desc := "Run shell commands. Only allowlisted commands and directories are permitted. " +
		"cd only persists in serial mode or with a single command."

	return mcp.NewTool("run",
		mcp.WithDescription(desc),
		mcp.WithArray("commands",
			mcp.Required(),
			mcp.Description("Commands to execute."),
			mcp.Items(map[string]interface{}{"type": "string"}),
		),
		mcp.WithString("mode",
			mcp.Description("\"parallel\" (default) or \"serial\" (stops on first error)."),
		),
	)
}

// createPwdTool creates the pwd tool for displaying the current working directory.
func createPwdTool() mcp.Tool {
	return mcp.NewTool("pwd",
		mcp.WithDescription("Print the current working directory."),
	)
}

// Execution mode constants.
const (
	modeParallel = "parallel"
	modeSerial   = "serial"
)

// Server is the MCP server for secure shell execution.
type Server struct {
	config    *config.ShellCommandConfig
	validator *validator.CommandValidator
	runner    *runner.SafeRunner
	logger    *logger.Logger
	mcpServer *server.MCPServer
	port      int
	// Mutex to protect shared resources (config, runner, validator) during command execution
	cmdMutex sync.Mutex
	// workingDir holds the session's current working directory. Empty means not yet set.
	workingDir string
}

// NewServer creates a new MCP server instance.
func NewServer(cfg *config.ShellCommandConfig, port int, logPath string) (*Server, error) {
	// Create logger with optional path
	loggerObj, err := logger.NewWithPath(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	validatorObj := validator.New(cfg, loggerObj)
	runnerObj := runner.New(cfg, validatorObj, loggerObj)

	mcpServer := server.NewMCPServer(
		"Secure Shell Server",
		"1.0.0",
		server.WithLogging(),
		server.WithRecovery(),
	)

	s := &Server{
		config:    cfg,
		validator: validatorObj,
		runner:    runnerObj,
		logger:    loggerObj,
		mcpServer: mcpServer,
		port:      port,
	}

	// Initialize working directory from PWD environment variable if configured
	if cfg.UseEnvPwd {
		if pwd := os.Getenv("PWD"); pwd != "" {
			absDir, err := filepath.Abs(pwd)
			if err == nil {
				if allowed, _ := validatorObj.IsDirectoryAllowed(absDir); allowed {
					info, statErr := os.Stat(absDir)
					if statErr == nil && info.IsDir() {
						s.workingDir = absDir
						loggerObj.LogInfof("Default working directory set from PWD: %s", absDir)
					}
				}
			}
		}
	}

	return s, nil
}

// Start initializes and starts the MCP server.
func (s *Server) Start() error {
	// Register tools
	s.mcpServer.AddTool(createRunTool(), s.HandleRunCommand)
	s.mcpServer.AddTool(createPwdTool(), s.HandlePwd)

	// Start the server
	address := fmt.Sprintf(":%d", s.port)
	s.logger.LogInfof("Starting MCP server on %s", address)

	// Create HTTP server to serve the MCP server
	handler := http.NewServeMux()
	handler.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// TODO: Implement proper HTTP handler for MCP
		_, err := w.Write([]byte("MCP server running"))
		if err != nil {
			s.logger.LogErrorf("Failed to write response: %v", err)
		}
	}))

	// Timeout constants
	const (
		readTimeoutSeconds  = 10
		writeTimeoutSeconds = 10
	)

	// Create a server with timeouts
	server := &http.Server{
		Addr:         address,
		Handler:      handler,
		ReadTimeout:  readTimeoutSeconds * time.Second,
		WriteTimeout: writeTimeoutSeconds * time.Second,
	}

	return server.ListenAndServe()
}

// HandlePwd handles the pwd tool execution.
func (s *Server) HandlePwd(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.cmdMutex.Lock()
	workingDir := s.workingDir
	s.cmdMutex.Unlock()

	if workingDir == "" {
		return mcp.NewToolResultError("No working directory set. Use the cd command via run to set a working directory."), nil
	}

	return mcp.NewToolResultText(workingDir), nil
}

// commandResult holds the output of a single command execution.
type commandResult struct {
	command    string
	output     string
	err        error
	newWorkDir string // non-empty if cd changed the working directory
	hints      []hint.Hint
}

// HandleRunCommand handles the run tool execution.
func (s *Server) HandleRunCommand(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	commands, err := parseCommands(request.Params.Arguments["commands"])
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	mode := modeParallel
	if m, ok := request.Params.Arguments["mode"].(string); ok && m != "" {
		if m != modeParallel && m != modeSerial {
			return mcp.NewToolResultError("Mode must be \"parallel\" or \"serial\""), nil
		}
		mode = m
	}

	s.cmdMutex.Lock()
	workingDir := s.workingDir
	s.cmdMutex.Unlock()

	if workingDir == "" {
		// Use the first allowed directory as default when no directory is set.
		// This allows the initial cd command to work without a pre-set directory.
		if len(s.config.AllowedDirectories) > 0 {
			workingDir = s.config.AllowedDirectories[0]
		} else {
			return mcp.NewToolResultError(
				"No working directory set and no allowed directories configured. Use cd command to set a working directory."), nil
		}
	}

	var results []commandResult
	if mode == modeSerial {
		results = s.runSerial(ctx, commands, workingDir)
	} else {
		results = s.runParallel(ctx, commands, workingDir)
	}

	// Persist cd directory changes from serial execution, or parallel with a single command.
	// In parallel mode with multiple commands, cd results are non-deterministic and should not be persisted.
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

	// Collect token-saving hints from runner results
	var allHints []hint.Hint
	for _, r := range results {
		allHints = append(allHints, r.hints...)
	}

	return formatResultsWithHints(results, allHints), nil
}

// parseCommands extracts and validates the commands array from the request arguments.
func parseCommands(raw interface{}) ([]string, error) {
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return nil, errors.New("commands parameter must be a non-empty array of strings")
	}
	commands := make([]string, 0, len(arr))
	for i, v := range arr {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("commands[%d] must be a non-empty string", i)
		}
		commands = append(commands, s)
	}
	return commands, nil
}

// runSerial executes commands one by one, stopping on first error.
// Directory changes from cd are propagated to subsequent commands.
func (s *Server) runSerial(ctx context.Context, commands []string, workingDir string) []commandResult {
	results := make([]commandResult, 0, len(commands))
	currentDir := workingDir
	for _, cmd := range commands {
		r := s.executeOne(ctx, cmd, currentDir)
		results = append(results, r)
		if r.newWorkDir != "" {
			currentDir = r.newWorkDir
		}
		if r.err != nil {
			break
		}
	}
	return results
}

// runParallel executes all commands concurrently.
func (s *Server) runParallel(ctx context.Context, commands []string, workingDir string) []commandResult {
	results := make([]commandResult, len(commands))
	var wg sync.WaitGroup
	for i, cmd := range commands {
		wg.Add(1)
		go func(idx int, c string) {
			defer wg.Done()
			results[idx] = s.executeOne(ctx, c, workingDir)
		}(i, cmd)
	}
	wg.Wait()
	return results
}

// executeOne runs a single command and returns its result.
func (s *Server) executeOne(ctx context.Context, command, workingDir string) commandResult {
	s.logger.LogInfof("Command attempt: %s in directory: %s", command, workingDir)

	r := runner.New(s.config, s.validator, s.logger)
	buf := new(strings.Builder)
	r.SetOutputs(buf, buf)

	result := r.RunCommand(ctx, command, workingDir)
	if result.Err != nil {
		s.logger.LogErrorf("Command execution failed: %v", result.Err)
	}
	return commandResult{command: command, output: buf.String(), err: result.Err, newWorkDir: result.NewWorkDir, hints: result.Hints}
}

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

// formatResults builds a tool result from command results.
func formatResults(results []commandResult) *mcp.CallToolResult {
	hasError := false
	var sb strings.Builder

	for i, r := range results {
		if len(results) > 1 {
			fmt.Fprintf(&sb, "--- [%d] %s ---\n", i, r.command)
		}
		if r.err != nil {
			hasError = true
			fmt.Fprintf(&sb, "Error: %v\n", r.err)
		}
		sb.WriteString(r.output)
		if len(results) > 1 && i < len(results)-1 {
			sb.WriteString("\n")
		}
	}

	if hasError {
		return mcp.NewToolResultError(sb.String())
	}
	return mcp.NewToolResultText(sb.String())
}

// ServeStdio starts an MCP server using stdin/stdout for communication.
func (s *Server) ServeStdio() error {
	// Register tools
	s.mcpServer.AddTool(createRunTool(), s.HandleRunCommand)
	s.mcpServer.AddTool(createPwdTool(), s.HandlePwd)

	// Start the server using stdio
	s.logger.LogInfof("Starting MCP server using stdin/stdout")
	return server.ServeStdio(s.mcpServer)
}

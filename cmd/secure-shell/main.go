package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
	"github.com/shimizu1995/secure-shell-server/pkg/runner"
	"github.com/shimizu1995/secure-shell-server/pkg/utils"
	"github.com/shimizu1995/secure-shell-server/pkg/validator"
)

func main() {
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	// Define command-line flags
	scriptStr := flag.String("script", "", "Script string to execute")
	maxTime := flag.Int("timeout", config.DefaultExecutionTimeout, "Maximum execution time in seconds")
	workingDir := flag.String("dir", "", "Working directory for command execution")
	logPath := flag.String("log", "", "Path to the log file (if empty, no logging occurs)")
	configPath := flag.String("config", "", "Path to the configuration file (if empty, uses default configuration)")

	flag.Parse()

	// Ensure log directory exists if log path is specified
	if *logPath != "" {
		if err := utils.EnsureLogDirectory(*logPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating log directory: %v\n", err)
			return 1
		}
	}

	// Create logger with optional path
	var log *logger.Logger

	log, logErr := logger.NewWithPath(*logPath)
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "Error creating logger: %v\n", logErr)
		return 1
	}
	defer log.Close()

	// Create config from file or use default
	var cfg *config.ShellCommandConfig
	var configErr error

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Error: Configuration file must be specified with -config flag\n")
		return 1
	}

	// Load configuration from file
	cfg, configErr = config.LoadConfigFromFile(*configPath)
	if configErr != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration file: %v\n", configErr)
		return 1
	}

	// Override config with command-line flags if specified
	cfg.MaxExecutionTime = *maxTime

	// Create validator and runner
	validatorObj := validator.New(cfg, log)
	safeRunner := runner.New(cfg, validatorObj, log)

	// Create a context with timeout for the entire execution
	ctx := context.Background()
	var cancel context.CancelFunc
	if *maxTime > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*maxTime)*time.Second)
		defer cancel()
	}

	// Execute the requested operation
	var result runner.RunResult

	switch {
	case *scriptStr != "":
		// Execute a script string
		result = safeRunner.RunCommand(ctx, *scriptStr, *workingDir)

	default:
		fmt.Fprintf(os.Stderr, "Error: No command or script specified\n")
		flag.Usage()
		return 1
	}

	if err := result.Err; err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}

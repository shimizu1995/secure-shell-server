// Secure Shell Server - A tool to execute shell commands securely.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/utils"
	"github.com/shimizu1995/secure-shell-server/service"
)

func main() {
	exitCode := run()
	os.Exit(exitCode)
}

// configEnvVar is the environment variable used to specify the configuration file path
// when the -config flag is not provided.
const configEnvVar = "MCP_SHELL_SERVER_CONFIG"

func run() int {
	// Define command-line flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Secure Shell Server - MCP Server mode\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	// Default port for HTTP server
	const defaultPort = 8080

	// Define server-specific flags
	port := flag.Int("port", defaultPort, "Port to listen on")
	configFile := flag.String("config", "", "Path to configuration file (overrides "+configEnvVar+")")
	stdio := flag.Bool("stdio", true, "Use stdin/stdout for MCP communication")
	logPath := flag.String("log", "", "Path to the log file (if empty, no logging occurs)")

	// Parse the flags
	flag.Parse()

	// Resolve config path: -config flag takes precedence over the environment variable.
	configPath := *configFile
	if configPath == "" {
		configPath = os.Getenv(configEnvVar)
	}

	if configPath == "" {
		fmt.Fprintf(os.Stderr, "Error: Configuration file must be specified with -config flag or %s environment variable\n", configEnvVar)
		return 1
	}

	// Load configuration from file
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		return 1
	}

	// Ensure log directory exists if log path is specified
	if *logPath != "" {
		if dirErr := utils.EnsureLogDirectory(*logPath); dirErr != nil {
			fmt.Fprintf(os.Stderr, "Error creating log directory: %v\n", dirErr)
			return 1
		}
	}

	// Create server with optional log path
	mcpServer, err := service.NewServer(cfg, *port, *logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
		return 1
	}

	// Start the server using stdio or HTTP
	if *stdio {
		if err := mcpServer.ServeStdio(); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			return 1
		}
	} else {
		fmt.Printf("Starting MCP server on port %d...\n", *port)
		if err := mcpServer.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			return 1
		}
	}

	return 0
}

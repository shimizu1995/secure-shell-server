package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Default execution timeout in seconds.
const DefaultExecutionTimeout = 30

// Default max output size in bytes (50KB).
const DefaultMaxOutputSize = 50 * 1024

// DenyCommand represents a command that is explicitly denied.
type DenyCommand struct {
	Command string `json:"command"`
	Message string `json:"message,omitempty"`
}

// AllowCommand represents a command that is explicitly allowed with optional subcommand specifications.
type AllowCommand struct {
	Command         string   `json:"command"`
	SubCommands     []string `json:"subCommands,omitempty"`
	DenySubCommands []string `json:"denySubCommands,omitempty"`
}

// ShellCommandConfig holds the configuration for shell command permissions.
type ShellCommandConfig struct {
	AllowedDirectories  []string       `json:"allowedDirectories"`
	AllowCommands       []AllowCommand `json:"allowCommands"`
	DenyCommands        []DenyCommand  `json:"denyCommands"`
	DefaultErrorMessage string         `json:"defaultErrorMessage"`
	BlockLogPath        string         `json:"blockLogPath,omitempty"`
	// MaxExecutionTime is the maximum execution time in seconds
	MaxExecutionTime int `json:"maxExecutionTime,omitempty"`
	// MaxOutputSize is the maximum size of command output in bytes
	MaxOutputSize int `json:"maxOutputSize,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for ShellCommandConfig.
func (c *ShellCommandConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		AllowedDirectories  []string        `json:"allowedDirectories"`
		AllowCommands       json.RawMessage `json:"allowCommands"`
		DenyCommands        json.RawMessage `json:"denyCommands"`
		DefaultErrorMessage string          `json:"defaultErrorMessage"`
		BlockLogPath        string          `json:"blockLogPath,omitempty"`
		MaxExecutionTime    int             `json:"maxExecutionTime,omitempty"`
		MaxOutputSize       int             `json:"maxOutputSize,omitempty"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Handle AllowCommands with custom unmarshaling
	allowCommands, err := UnmarshalAllowCommands(raw.AllowCommands)
	if err != nil {
		return fmt.Errorf("error unmarshaling allow commands: %w", err)
	}

	// Handle DenyCommands with custom unmarshaling
	denyCommands, err := UnmarshalDenyCommands(raw.DenyCommands)
	if err != nil {
		return fmt.Errorf("error unmarshaling deny commands: %w", err)
	}

	c.AllowedDirectories = raw.AllowedDirectories
	c.AllowCommands = allowCommands
	c.DenyCommands = denyCommands

	// Use default values if not specified
	if raw.DefaultErrorMessage != "" {
		c.DefaultErrorMessage = raw.DefaultErrorMessage
	} else {
		c.DefaultErrorMessage = "Command not allowed by security policy"
	}

	c.BlockLogPath = raw.BlockLogPath

	// Use default execution time if not specified or invalid
	if raw.MaxExecutionTime > 0 {
		c.MaxExecutionTime = raw.MaxExecutionTime
	} else {
		c.MaxExecutionTime = DefaultExecutionTimeout
	}

	// Use default output size if not specified or invalid
	if raw.MaxOutputSize > 0 {
		c.MaxOutputSize = raw.MaxOutputSize
	} else {
		c.MaxOutputSize = DefaultMaxOutputSize
	}

	return nil
}

// NewDefaultConfig returns a default configuration.
func NewDefaultConfig() *ShellCommandConfig {
	return &ShellCommandConfig{
		AllowedDirectories: []string{"/home", "/tmp"},
		AllowCommands: []AllowCommand{
			{Command: "ls"},
			{Command: "cat"},
			{Command: "echo"},
		},
		DenyCommands:        []DenyCommand{{Command: "rm", Message: "Remove command is not allowed"}},
		DefaultErrorMessage: "Command not allowed by security policy",
		MaxExecutionTime:    DefaultExecutionTimeout,
		MaxOutputSize:       DefaultMaxOutputSize,
	}
}

// LoadConfigFromFile loads the configuration from a JSON file.
func LoadConfigFromFile(filePath string) (*ShellCommandConfig, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ShellCommandConfig
	if err := json.Unmarshal(fileBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return &config, nil
}

// UnmarshalDenyCommands processes the raw JSON for deny commands which can be either strings or objects.
func UnmarshalDenyCommands(data []byte) ([]DenyCommand, error) {
	var rawCommands []json.RawMessage
	if err := json.Unmarshal(data, &rawCommands); err != nil {
		return nil, err
	}

	result := make([]DenyCommand, 0, len(rawCommands))

	for _, raw := range rawCommands {
		// Try to unmarshal as string first
		var cmdStr string
		if err := json.Unmarshal(raw, &cmdStr); err == nil {
			// It's a string
			result = append(result, DenyCommand{Command: cmdStr})
			continue
		}

		// If not a string, try as object
		var cmdObj DenyCommand
		if err := json.Unmarshal(raw, &cmdObj); err != nil {
			return nil, err
		}
		result = append(result, cmdObj)
	}

	return result, nil
}

// UnmarshalAllowCommands processes the raw JSON for allow commands which can be either strings or objects.
func UnmarshalAllowCommands(data []byte) ([]AllowCommand, error) {
	var rawCommands []json.RawMessage
	if err := json.Unmarshal(data, &rawCommands); err != nil {
		return nil, err
	}

	result := make([]AllowCommand, 0, len(rawCommands))

	for _, raw := range rawCommands {
		// Try to unmarshal as string first
		var cmdStr string
		if err := json.Unmarshal(raw, &cmdStr); err == nil {
			// It's a string
			result = append(result, AllowCommand{Command: cmdStr})
			continue
		}

		// If not a string, try as object
		var cmdObj AllowCommand
		if err := json.Unmarshal(raw, &cmdObj); err != nil {
			return nil, err
		}
		result = append(result, cmdObj)
	}

	return result, nil
}

// IsCommandAllowed checks if a command is allowed.
func (c *ShellCommandConfig) IsCommandAllowed(cmd string) bool {
	for _, allowed := range c.AllowCommands {
		if allowed.Command == cmd {
			return true
		}
	}
	return false
}

// AddAllowedCommand adds a new command to the allowed commands list.
func (c *ShellCommandConfig) AddAllowedCommand(cmd string) {
	if !c.IsCommandAllowed(cmd) {
		c.AllowCommands = append(c.AllowCommands, AllowCommand{Command: cmd})
	}
}

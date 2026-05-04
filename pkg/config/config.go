package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Default execution timeout in seconds.
const DefaultExecutionTimeout = 120

// Default max output size in bytes (50KB).
const DefaultMaxOutputSize = 50 * 1024

// DenyCommand represents a command that is explicitly denied.
type DenyCommand struct {
	Command string `json:"command"`
	Message string `json:"message,omitempty"`
}

// SubCommandRule represents a recursive subcommand rule node.
// It can be deserialized from a JSON string (name only) or an object (full rule).
type SubCommandRule struct {
	Name            string           `json:"name"`
	DenyFlags       []string         `json:"denyFlags,omitempty"`
	SubCommands     []SubCommandRule `json:"subCommands,omitempty"`
	DenySubCommands []string         `json:"denySubCommands,omitempty"`
	Message         string           `json:"message,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for SubCommandRule.
// It accepts both a JSON string (treated as name only) and a full JSON object.
func (r *SubCommandRule) UnmarshalJSON(data []byte) error {
	// Try string first
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		r.Name = name
		return nil
	}

	// Otherwise, unmarshal as object (use an alias to avoid infinite recursion)
	type subCommandRuleAlias SubCommandRule
	var alias subCommandRuleAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*r = SubCommandRule(alias)
	return nil
}

// GlobalFlag represents a flag that can appear before any subcommand
// (e.g. `git -C /path status`). It is used in both the allow and deny lists
// at the AllowCommand level so that callers can permit value-bearing flags
// like `-C <path>` or block dangerous ones like `--exec-path` regardless
// of the subcommand that follows.
type GlobalFlag struct {
	Name       string `json:"name"`
	TakesValue bool   `json:"takesValue,omitempty"`
	Message    string `json:"message,omitempty"`
}

// UnmarshalJSON accepts either a JSON string (treated as name only) or a full object.
func (g *GlobalFlag) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		g.Name = name
		return nil
	}

	type globalFlagAlias GlobalFlag
	var alias globalFlagAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*g = GlobalFlag(alias)
	return nil
}

// AllowCommand represents a command that is explicitly allowed with optional subcommand specifications.
type AllowCommand struct {
	Command         string           `json:"command"`
	SubCommands     []SubCommandRule `json:"subCommands,omitempty"`
	DenySubCommands []string         `json:"denySubCommands,omitempty"`
	GlobalFlags     []GlobalFlag     `json:"globalFlags,omitempty"`
	DenyGlobalFlags []GlobalFlag     `json:"denyGlobalFlags,omitempty"`
}

// ShellCommandConfig holds the configuration for shell command permissions.
type ShellCommandConfig struct {
	AllowedDirectories  []string       `json:"allowedDirectories"`
	AllowCommands       []AllowCommand `json:"allowCommands"`
	DenyCommands        []DenyCommand  `json:"denyCommands"`
	DefaultErrorMessage string         `json:"defaultErrorMessage"`
	BlockLogPath        string         `json:"blockLogPath,omitempty"`
	// MaxExecutionTime is the maximum execution time in seconds (0 means unlimited)
	MaxExecutionTime int `json:"maxExecutionTime,omitempty"`
	// MaxOutputSize is the maximum size of command output in bytes (0 means unlimited)
	MaxOutputSize int `json:"maxOutputSize,omitempty"`
	// UseEnvPwd uses the PWD environment variable as the default working directory when true
	UseEnvPwd bool `json:"useEnvPwd,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for ShellCommandConfig.
func (c *ShellCommandConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		AllowedDirectories  []string        `json:"allowedDirectories"`
		AllowCommands       json.RawMessage `json:"allowCommands"`
		DenyCommands        json.RawMessage `json:"denyCommands"`
		DefaultErrorMessage string          `json:"defaultErrorMessage"`
		BlockLogPath        string          `json:"blockLogPath,omitempty"`
		MaxExecutionTime    *int            `json:"maxExecutionTime"`
		MaxOutputSize       *int            `json:"maxOutputSize"`
		UseEnvPwd           *bool           `json:"useEnvPwd,omitempty"`
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

	// UseEnvPwd defaults to true unless explicitly set to false
	if raw.UseEnvPwd != nil {
		c.UseEnvPwd = *raw.UseEnvPwd
	} else {
		c.UseEnvPwd = true
	}

	// Use default execution time if not specified; 0 means unlimited
	if raw.MaxExecutionTime != nil {
		c.MaxExecutionTime = *raw.MaxExecutionTime
	} else {
		c.MaxExecutionTime = DefaultExecutionTimeout
	}

	// Use default output size if not specified; 0 means unlimited
	if raw.MaxOutputSize != nil {
		c.MaxOutputSize = *raw.MaxOutputSize
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
		UseEnvPwd:           true,
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

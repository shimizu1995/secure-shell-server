package config

import (
	"encoding/json"
	"testing"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()

	// Verify default allowed commands are present
	expectedCommands := []string{"ls", "cat", "echo"}
	for _, cmd := range expectedCommands {
		if !cfg.IsCommandAllowed(cmd) {
			t.Errorf("IsCommandAllowed(%q) = false, want true", cmd)
		}
	}

	// Verify disallowed commands
	disallowedCommands := []string{"wget", "curl", "cp"}
	for _, cmd := range disallowedCommands {
		if cfg.IsCommandAllowed(cmd) {
			t.Errorf("IsCommandAllowed(%q) = true, want false", cmd)
		}
	}

	// Verify default execution time
	if cfg.MaxExecutionTime != 120 {
		t.Errorf("MaxExecutionTime = %d, want %d", cfg.MaxExecutionTime, 120)
	}
}

func TestIsCommandAllowed(t *testing.T) {
	cfg := NewDefaultConfig()

	tests := []struct {
		name    string
		cmd     string
		allowed bool
	}{
		{"allowed - ls", "ls", true},
		{"allowed - echo", "echo", true},
		{"allowed - cat", "cat", true},
		{"denied - rm", "rm", false},
		{"denied - empty", "", false},
		{"denied - nonexistent", "nonexistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.IsCommandAllowed(tt.cmd); got != tt.allowed {
				t.Errorf("IsCommandAllowed() = %v, want %v", got, tt.allowed)
			}
		})
	}
}

func TestSubCommandRuleDeserialization(t *testing.T) {
	tests := []struct {
		name          string
		json          string
		wantName      string
		wantDenyFlags []string
		wantSubCmds   int
		wantDenySubs  []string
		wantMessage   string
		wantErr       bool
	}{
		{
			name:     "string value becomes SubCommandRule with name only",
			json:     `"status"`,
			wantName: "status",
		},
		{
			name:          "object with denyFlags",
			json:          `{"name": "push", "denyFlags": ["-f", "--force"]}`,
			wantName:      "push",
			wantDenyFlags: []string{"-f", "--force"},
		},
		{
			name:        "object with nested subCommands",
			json:        `{"name": "compose", "subCommands": ["up", "down"]}`,
			wantName:    "compose",
			wantSubCmds: 2,
		},
		{
			name:         "object with denySubCommands",
			json:         `{"name": "branch", "denySubCommands": ["--set-upstream"]}`,
			wantName:     "branch",
			wantDenySubs: []string{"--set-upstream"},
		},
		{
			name:          "object with message",
			json:          `{"name": "push", "denyFlags": ["-f"], "message": "Force push is not allowed"}`,
			wantName:      "push",
			wantDenyFlags: []string{"-f"},
			wantMessage:   "Force push is not allowed",
		},
		{
			name: "deeply nested subCommands",
			json: `{
				"name": "compose",
				"subCommands": [
					{
						"name": "up",
						"denyFlags": ["--force-recreate"]
					},
					"down"
				]
			}`,
			wantName:    "compose",
			wantSubCmds: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule SubCommandRule
			err := json.Unmarshal([]byte(tt.json), &rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if rule.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", rule.Name, tt.wantName)
			}
			if len(rule.DenyFlags) != len(tt.wantDenyFlags) {
				t.Errorf("DenyFlags length = %d, want %d", len(rule.DenyFlags), len(tt.wantDenyFlags))
			}
			for i, f := range tt.wantDenyFlags {
				if i < len(rule.DenyFlags) && rule.DenyFlags[i] != f {
					t.Errorf("DenyFlags[%d] = %q, want %q", i, rule.DenyFlags[i], f)
				}
			}
			if tt.wantSubCmds > 0 && len(rule.SubCommands) != tt.wantSubCmds {
				t.Errorf("SubCommands length = %d, want %d", len(rule.SubCommands), tt.wantSubCmds)
			}
			if len(rule.DenySubCommands) != len(tt.wantDenySubs) {
				t.Errorf("DenySubCommands length = %d, want %d", len(rule.DenySubCommands), len(tt.wantDenySubs))
			}
			if rule.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", rule.Message, tt.wantMessage)
			}
		})
	}
}

func TestAllowCommandWithDenyFlags(t *testing.T) {
	const configJSON = `{
		"allowedDirectories": ["/home"],
		"allowCommands": [
			{
				"command": "git",
				"subCommands": [
					"status",
					"log",
					{
						"name": "push",
						"denyFlags": ["-f", "--force", "--force-with-lease"],
						"message": "Force push is not allowed"
					},
					{
						"name": "branch",
						"denyFlags": ["-D"]
					}
				],
				"denySubCommands": ["reset"]
			}
		],
		"denyCommands": [],
		"defaultErrorMessage": "Not allowed"
	}`

	var cfg ShellCommandConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	git := cfg.AllowCommands[0]
	if git.Command != "git" {
		t.Fatalf("Expected 'git', got %q", git.Command)
	}
	if len(git.SubCommands) != 4 {
		t.Fatalf("Expected 4 subCommands, got %d", len(git.SubCommands))
	}

	// "status" should be a simple rule
	if git.SubCommands[0].Name != "status" {
		t.Errorf("SubCommands[0].Name = %q, want 'status'", git.SubCommands[0].Name)
	}

	// "push" should have denyFlags
	push := git.SubCommands[2]
	if push.Name != "push" {
		t.Errorf("SubCommands[2].Name = %q, want 'push'", push.Name)
	}
	if len(push.DenyFlags) != 3 {
		t.Errorf("push.DenyFlags length = %d, want 3", len(push.DenyFlags))
	}
	if push.Message != "Force push is not allowed" {
		t.Errorf("push.Message = %q, want 'Force push is not allowed'", push.Message)
	}

	// "branch" should have denyFlags with -D
	branch := git.SubCommands[3]
	if branch.Name != "branch" {
		t.Errorf("SubCommands[3].Name = %q, want 'branch'", branch.Name)
	}
	if len(branch.DenyFlags) != 1 || branch.DenyFlags[0] != "-D" {
		t.Errorf("branch.DenyFlags = %v, want [\"-D\"]", branch.DenyFlags)
	}

	// denySubCommands should still work at top level
	if len(git.DenySubCommands) != 1 || git.DenySubCommands[0] != "reset" {
		t.Errorf("DenySubCommands = %v, want [\"reset\"]", git.DenySubCommands)
	}
}

func TestGlobalFlagDeserialization(t *testing.T) {
	tests := []struct {
		name           string
		json           string
		wantName       string
		wantTakesValue bool
		wantMessage    string
		wantErr        bool
	}{
		{
			name:     "string value becomes GlobalFlag with name only",
			json:     `"--no-pager"`,
			wantName: "--no-pager",
		},
		{
			name:           "object with takesValue",
			json:           `{"name": "-C", "takesValue": true}`,
			wantName:       "-C",
			wantTakesValue: true,
		},
		{
			name:        "object with message",
			json:        `{"name": "--exec-path", "message": "Custom exec-path is dangerous"}`,
			wantName:    "--exec-path",
			wantMessage: "Custom exec-path is dangerous",
		},
		{
			name:           "object with both takesValue and message",
			json:           `{"name": "--git-dir", "takesValue": true, "message": "blocked"}`,
			wantName:       "--git-dir",
			wantTakesValue: true,
			wantMessage:    "blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gf GlobalFlag
			err := json.Unmarshal([]byte(tt.json), &gf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if gf.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", gf.Name, tt.wantName)
			}
			if gf.TakesValue != tt.wantTakesValue {
				t.Errorf("TakesValue = %v, want %v", gf.TakesValue, tt.wantTakesValue)
			}
			if gf.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", gf.Message, tt.wantMessage)
			}
		})
	}
}

func TestAllowCommandWithGlobalFlags(t *testing.T) {
	const configJSON = `{
		"allowedDirectories": ["/home"],
		"allowCommands": [
			{
				"command": "git",
				"globalFlags": [
					"--no-pager",
					{"name": "-C", "takesValue": true},
					{"name": "--git-dir", "takesValue": true}
				],
				"denyGlobalFlags": [
					"--exec-path",
					{"name": "--upload-pack", "message": "upload-pack is dangerous"}
				],
				"subCommands": ["status", "log"]
			}
		],
		"denyCommands": [],
		"defaultErrorMessage": "Not allowed"
	}`

	var cfg ShellCommandConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	git := cfg.AllowCommands[0]
	if len(git.GlobalFlags) != 3 {
		t.Fatalf("GlobalFlags length = %d, want 3", len(git.GlobalFlags))
	}

	// "--no-pager" simple form
	if git.GlobalFlags[0].Name != "--no-pager" {
		t.Errorf("GlobalFlags[0].Name = %q, want '--no-pager'", git.GlobalFlags[0].Name)
	}
	if git.GlobalFlags[0].TakesValue {
		t.Errorf("GlobalFlags[0].TakesValue = true, want false")
	}

	// "-C" with takesValue
	if git.GlobalFlags[1].Name != "-C" {
		t.Errorf("GlobalFlags[1].Name = %q, want '-C'", git.GlobalFlags[1].Name)
	}
	if !git.GlobalFlags[1].TakesValue {
		t.Errorf("GlobalFlags[1].TakesValue = false, want true")
	}

	// DenyGlobalFlags
	if len(git.DenyGlobalFlags) != 2 {
		t.Fatalf("DenyGlobalFlags length = %d, want 2", len(git.DenyGlobalFlags))
	}
	if git.DenyGlobalFlags[0].Name != "--exec-path" {
		t.Errorf("DenyGlobalFlags[0].Name = %q, want '--exec-path'", git.DenyGlobalFlags[0].Name)
	}
	if git.DenyGlobalFlags[1].Message != "upload-pack is dangerous" {
		t.Errorf("DenyGlobalFlags[1].Message = %q, want 'upload-pack is dangerous'", git.DenyGlobalFlags[1].Message)
	}
}

func TestUseEnvPwdConfig(t *testing.T) {
	t.Run("useEnvPwd true", func(t *testing.T) {
		const configJSON = `{
			"allowedDirectories": ["/home"],
			"allowCommands": ["ls"],
			"denyCommands": [],
			"defaultErrorMessage": "Not allowed",
			"useEnvPwd": true
		}`

		var cfg ShellCommandConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if !cfg.UseEnvPwd {
			t.Error("UseEnvPwd should be true")
		}
	})

	t.Run("useEnvPwd defaults to true", func(t *testing.T) {
		const configJSON = `{
			"allowedDirectories": ["/home"],
			"allowCommands": ["ls"],
			"denyCommands": [],
			"defaultErrorMessage": "Not allowed"
		}`

		var cfg ShellCommandConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if !cfg.UseEnvPwd {
			t.Error("UseEnvPwd should default to true")
		}
	})

	t.Run("useEnvPwd explicit false", func(t *testing.T) {
		const configJSON = `{
			"allowedDirectories": ["/home"],
			"allowCommands": ["ls"],
			"denyCommands": [],
			"defaultErrorMessage": "Not allowed",
			"useEnvPwd": false
		}`

		var cfg ShellCommandConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if cfg.UseEnvPwd {
			t.Error("UseEnvPwd should be false when explicitly set")
		}
	})
}

func TestMixedCommandFormats(t *testing.T) {
	const configJSON = `{
		"allowedDirectories": ["/home", "/tmp"],
		"allowCommands": [
			"ls",
			{"command": "git", "subCommands": ["status", "pull"], "denySubCommands": ["push"]},
			"cat"
		],
		"denyCommands": [
			"rm",
			{"command": "sudo", "message": "Elevated privileges not allowed"},
			"vi"
		],
		"defaultErrorMessage": "Command not allowed",
		"maxExecutionTime": 60
	}`

	var config ShellCommandConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify allow commands count
	if len(config.AllowCommands) != 3 {
		t.Errorf("Expected 3 allow commands, got %d", len(config.AllowCommands))
	}

	// Verify a string-only allow command
	if config.AllowCommands[0].Command != "ls" {
		t.Errorf("Expected first command to be 'ls', got %q", config.AllowCommands[0].Command)
	}

	// Verify a structured allow command
	if config.AllowCommands[1].Command != "git" {
		t.Errorf("Expected second command to be 'git', got %q", config.AllowCommands[1].Command)
	}
	if len(config.AllowCommands[1].SubCommands) != 2 {
		t.Errorf("Expected 2 subcommands for 'git', got %d", len(config.AllowCommands[1].SubCommands))
	}
	if len(config.AllowCommands[1].DenySubCommands) != 1 {
		t.Errorf("Expected 1 deny subcommand for 'git', got %d", len(config.AllowCommands[1].DenySubCommands))
	}

	// Verify deny commands count
	if len(config.DenyCommands) != 3 {
		t.Errorf("Expected 3 deny commands, got %d", len(config.DenyCommands))
	}

	// Verify a string-only deny command
	if config.DenyCommands[0].Command != "rm" {
		t.Errorf("Expected first deny command to be 'rm', got %q", config.DenyCommands[0].Command)
	}
	if config.DenyCommands[0].Message != "" {
		t.Errorf("Expected empty message for 'rm', got %q", config.DenyCommands[0].Message)
	}

	// Verify a structured deny command
	if config.DenyCommands[1].Command != "sudo" {
		t.Errorf("Expected second deny command to be 'sudo', got %q", config.DenyCommands[1].Command)
	}
	if config.DenyCommands[1].Message != "Elevated privileges not allowed" {
		t.Errorf("Expected specific message for 'sudo', got %q", config.DenyCommands[1].Message)
	}
}

func TestUnmarshalZeroMeansUnlimited(t *testing.T) {
	configJSON := `{
		"allowedDirectories": ["/tmp"],
		"allowCommands": ["ls"],
		"denyCommands": [],
		"maxExecutionTime": 0,
		"maxOutputSize": 0
	}`

	var cfg ShellCommandConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if cfg.MaxExecutionTime != 0 {
		t.Errorf("MaxExecutionTime = %d, want 0 (unlimited)", cfg.MaxExecutionTime)
	}
	if cfg.MaxOutputSize != 0 {
		t.Errorf("MaxOutputSize = %d, want 0 (unlimited)", cfg.MaxOutputSize)
	}
}

func TestUnmarshalOmittedUsesDefaults(t *testing.T) {
	configJSON := `{
		"allowedDirectories": ["/tmp"],
		"allowCommands": ["ls"],
		"denyCommands": []
	}`

	var cfg ShellCommandConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if cfg.MaxExecutionTime != DefaultExecutionTimeout {
		t.Errorf("MaxExecutionTime = %d, want %d", cfg.MaxExecutionTime, DefaultExecutionTimeout)
	}
	if cfg.MaxOutputSize != DefaultMaxOutputSize {
		t.Errorf("MaxOutputSize = %d, want %d", cfg.MaxOutputSize, DefaultMaxOutputSize)
	}
}

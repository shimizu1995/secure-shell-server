package validator

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
)

// TestIsPathInAllowedDirectory tests the IsPathInAllowedDirectory function.
func TestIsPathInAllowedDirectory(t *testing.T) {
	// Create temporary directories for testing
	tempHomeDir := t.TempDir()
	tempWorkDir := filepath.Join(t.TempDir(), "workdir")

	// Create the workdir subdirectory
	err := os.Mkdir(tempWorkDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temp work directory: %v", err)
	}

	// Setup test config with temp directories
	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{tempHomeDir, tempWorkDir},
		DefaultErrorMessage: "Path not allowed by security policy",
	}

	// Create a logger with a buffer
	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)

	// Create the validator
	v := New(cfg, log)

	// Create a subdirectory for testing inside workdir
	tempSubDir := filepath.Join(tempWorkDir, "subdir")
	err = os.Mkdir(tempSubDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temp subdirectory: %v", err)
	}

	// Test cases
	tests := []struct {
		name      string
		path      string
		baseDir   string
		allowed   bool
		wantError bool
	}{
		// Absolute paths tests
		{name: "AllowedAbsolutePath", path: filepath.Join(tempHomeDir, "file.txt"), baseDir: tempWorkDir, allowed: true, wantError: false},
		{name: "AllowedAbsolutePathInSubdir", path: filepath.Join(tempWorkDir, "subdir", "file.txt"), baseDir: tempHomeDir, allowed: true, wantError: false},
		{name: "DisallowedAbsolutePath", path: "/etc/passwd", baseDir: tempWorkDir, allowed: false, wantError: true},

		// Relative paths tests
		{name: "RelativePathToAllowed", path: "./file.txt", baseDir: tempHomeDir, allowed: true, wantError: false},
		{name: "RelativePathWithinAllowed", path: "subdir/file.txt", baseDir: tempWorkDir, allowed: true, wantError: false},
		{name: "SimpleRelativePath", path: "./file.txt", baseDir: tempWorkDir, allowed: true, wantError: false},
		{name: "DotDotRelativePath", path: "../file.txt", baseDir: tempSubDir, allowed: true, wantError: false},
		{name: "RelativePathToDisallowed", path: "../../etc/passwd", baseDir: tempSubDir, allowed: false, wantError: true},

		// Edge cases
		{name: "EmptyPath", path: "", baseDir: tempWorkDir, allowed: false, wantError: true},
		{name: "PathWithDots", path: filepath.Join(tempWorkDir, "..", filepath.Base(tempWorkDir), "file.txt"), baseDir: tempHomeDir, allowed: true, wantError: false},
		{name: "EscapeAttempt", path: filepath.Join(tempWorkDir, "..", "etc", "passwd"), baseDir: tempHomeDir, allowed: false, wantError: true},
	}

	// Separate test for /dev/null as a specific allowed path (not a directory)
	t.Run("DevNullAllowedWhenConfigured", func(t *testing.T) {
		devNullCfg := &config.ShellCommandConfig{
			AllowedDirectories:  []string{tempHomeDir, "/dev/null"},
			DefaultErrorMessage: "Path not allowed by security policy",
		}
		var buf bytes.Buffer
		devNullLog := logger.NewWithWriter(&buf)
		devNullV := New(devNullCfg, devNullLog)

		allowed, errMsg := devNullV.IsPathInAllowedDirectory("/dev/null", tempWorkDir)
		if !allowed {
			t.Errorf("IsPathInAllowedDirectory(/dev/null) should be allowed when /dev/null is in allowedDirectories, got error: %s", errMsg)
		}
	})

	t.Run("DevNullBlockedWhenNotConfigured", func(t *testing.T) {
		noDevNullCfg := &config.ShellCommandConfig{
			AllowedDirectories:  []string{tempHomeDir, tempWorkDir},
			DefaultErrorMessage: "Path not allowed by security policy",
		}
		var buf bytes.Buffer
		noDevNullLog := logger.NewWithWriter(&buf)
		noDevNullV := New(noDevNullCfg, noDevNullLog)

		allowed, _ := noDevNullV.IsPathInAllowedDirectory("/dev/null", tempWorkDir)
		if allowed {
			t.Error("IsPathInAllowedDirectory(/dev/null) should be blocked when /dev/null is not in allowedDirectories")
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset log buffer for each test
			logBuffer.Reset()

			gotAllowed, errMsg := v.IsPathInAllowedDirectory(tt.path, tt.baseDir)

			if gotAllowed != tt.allowed {
				t.Errorf("IsPathInAllowedDirectory() allowed = %v, want %v", gotAllowed, tt.allowed)
			}

			if (errMsg != "") != tt.wantError {
				t.Errorf("IsPathInAllowedDirectory() error = %q, wantError %v", errMsg, tt.wantError)
			}
		})
	}
}

// TestIsPathLike tests the isPathLike function.
func TestIsPathLike(t *testing.T) {
	// Setup test config and validator
	cfg := &config.ShellCommandConfig{}
	log := logger.New()
	v := New(cfg, log)

	// Test cases
	tests := []struct {
		name   string
		arg    string
		isPath bool
	}{
		{name: "AbsolutePath", arg: "/tmp/file.txt", isPath: true},
		{name: "RelativePath", arg: "./file.txt", isPath: true},
		{name: "ParentDirPath", arg: "../file.txt", isPath: true},
		{name: "HomeDirPath", arg: "~/file.txt", isPath: true},
		{name: "HiddenFile", arg: ".config", isPath: true},
		{name: "WindowsPath", arg: "C:\\Users\\file.txt", isPath: true},
		{name: "NotAPath", arg: "hello", isPath: false},
		{name: "Flag", arg: "-la", isPath: false},
		{name: "LongFlag", arg: "--recursive", isPath: false},
		{name: "EmptyString", arg: "", isPath: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isPathLike(tt.arg)
			if got != tt.isPath {
				t.Errorf("isPathLike() = %v, want %v", got, tt.isPath)
			}
		})
	}
}

// TestValidatePathArguments tests the validatePathArguments function.
func TestValidatePathArguments(t *testing.T) {
	// Create temporary directories for testing
	tempHomeDir := t.TempDir()
	tempWorkDir := filepath.Join(t.TempDir(), "workdir")

	// Create the workdir subdirectory
	err := os.Mkdir(tempWorkDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temp work directory: %v", err)
	}

	// Setup test config with temp directories
	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{tempHomeDir, tempWorkDir},
		DefaultErrorMessage: "Path not allowed by security policy",
	}

	// Create a logger with a buffer
	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)

	// Create the validator
	v := New(cfg, log)

	// Test cases
	tests := []struct {
		name    string
		cmd     string
		args    []string
		workDir string
		allowed bool
	}{
		{name: "AllPathsAllowed", cmd: "cp", args: []string{filepath.Join(tempWorkDir, "file1.txt"), filepath.Join(tempWorkDir, "file2.txt")}, workDir: tempHomeDir, allowed: true},
		{name: "OnePathDisallowed", cmd: "cp", args: []string{filepath.Join(tempWorkDir, "file.txt"), "/etc/passwd"}, workDir: tempHomeDir, allowed: false},
		{name: "RelativePathsAllowed", cmd: "mv", args: []string{"./file1.txt", "./file2.txt"}, workDir: tempWorkDir, allowed: true},
		{name: "MixedPathsWithDisallowed", cmd: "ln", args: []string{filepath.Join(tempWorkDir, "file.txt"), "/var/log/test.log"}, workDir: tempHomeDir, allowed: false},
		{name: "NoPathArguments", cmd: "echo", args: []string{"hello", "world"}, workDir: tempHomeDir, allowed: true},
		{name: "FlagsWithPaths", cmd: "ls", args: []string{"-la", tempWorkDir}, workDir: tempHomeDir, allowed: true},
		{name: "DisallowedRelativePath", cmd: "cat", args: []string{"../etc/passwd"}, workDir: "/var", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset log buffer for each test
			logBuffer.Reset()

			gotAllowed, _ := v.validatePathArguments(tt.cmd, tt.args, tt.workDir)
			if gotAllowed != tt.allowed {
				t.Errorf("validatePathArguments() allowed = %v, want %v", gotAllowed, tt.allowed)
			}
		})
	}
}

// TestValidateCommand tests the ValidateCommand function with various scenarios.
func TestValidateCommand(t *testing.T) {
	// Create temporary directories for testing
	tempHomeDir := t.TempDir()
	tempWorkDir := filepath.Join(t.TempDir(), "workdir")

	// Create the workdir subdirectory
	err := os.Mkdir(tempWorkDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temp work directory: %v", err)
	}

	// Setup test config with temp directories
	cfg := &config.ShellCommandConfig{
		AllowedDirectories: []string{tempHomeDir, tempWorkDir},
		AllowCommands: []config.AllowCommand{
			{Command: "ls"}, // Command with no subcommand restrictions
			{Command: "cat"},
			{Command: "echo"},
			{Command: "grep"},
			{Command: "find"},
			{Command: "git", SubCommands: []config.SubCommandRule{{Name: "status"}, {Name: "log"}, {Name: "diff"}}, DenySubCommands: []string{"push", "commit"}},
			{Command: "docker", DenySubCommands: []string{"rm", "exec", "run"}},                                                             // Command with denied subcommands
			{Command: "npm", SubCommands: []config.SubCommandRule{{Name: "install"}, {Name: "update"}}, DenySubCommands: []string{"audit"}}, // Command with both allowed and denied subcommands
		},
		DenyCommands: []config.DenyCommand{
			{Command: "rm", Message: "Remove command is not allowed"},
			{Command: "sudo", Message: "Sudo is not allowed for security reasons"}, // With custom error message
		},
		DefaultErrorMessage: "Command not allowed by security policy",
		BlockLogPath:        "", // Don't write to a log file in tests
	}

	// Create a logger with a buffer
	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)

	// Create the validator
	v := New(cfg, log)

	// Test cases
	tests := []struct {
		name    string
		cmd     string
		args    []string
		allowed bool
		message string
	}{
		// Test additional allowed commands
		{name: "LsCommand", cmd: "ls", args: []string{"-la"}, allowed: true, message: ""},
		{name: "EchoCommand", cmd: "echo", args: []string{"hello"}, allowed: true, message: ""},
		{name: "CatCommand", cmd: "cat", args: []string{filepath.Join(tempWorkDir, "file.txt")}, allowed: true, message: ""},
		{name: "GrepCommand", cmd: "grep", args: []string{"pattern", filepath.Join(tempWorkDir, "file.txt")}, allowed: true, message: ""},
		{name: "FindCommand", cmd: "find", args: []string{tempWorkDir, "-name", "*.txt"}, allowed: true, message: ""},

		// Test denied commands
		{name: "ExplicitlyDeniedCommand", cmd: "rm", args: []string{"-rf", tempWorkDir}, allowed: false, message: "command \"rm\" is denied: Remove command is not allowed"},
		{name: "DeniedCommandWithCustomMessage", cmd: "sudo", args: []string{"apt-get", "update"}, allowed: false, message: "command \"sudo\" is denied: Sudo is not allowed for security reasons"},
		{name: "UnlistedCommand", cmd: "wget", args: []string{"https://example.com"}, allowed: false, message: "command \"wget\" is not permitted: Command not allowed by security policy"},
		{name: "ChmodNotInAllowList", cmd: "chmod", args: []string{"777", filepath.Join(tempWorkDir, "file.txt")}, allowed: false, message: "command \"chmod\" is not permitted: Command not allowed by security policy"},

		// Test git-specific subcommands
		{name: "GitStatusAllowed", cmd: "git", args: []string{"status"}, allowed: true, message: ""},
		{name: "GitLogAllowed", cmd: "git", args: []string{"log"}, allowed: true, message: ""},
		{name: "GitDiffAllowed", cmd: "git", args: []string{"diff"}, allowed: true, message: ""},
		{name: "GitPushDenied", cmd: "git", args: []string{"push"}, allowed: false, message: "subcommand \"push\" is denied for command \"git\""},
		{name: "GitCommitDenied", cmd: "git", args: []string{"commit"}, allowed: false, message: "subcommand \"commit\" is denied for command \"git\""},
		{name: "GitCloneNotAllowed", cmd: "git", args: []string{"clone", "https://github.com/example/repo.git"}, allowed: false, message: "subcommand \"clone\" is not allowed for command \"git\""},

		// Test docker subcommand handling
		{name: "DeniedSubcommand", cmd: "docker", args: []string{"rm"}, allowed: false, message: "subcommand \"rm\" is denied for command \"docker\""},
		{name: "AllowedDockerSubcommand", cmd: "docker", args: []string{"ps"}, allowed: true, message: ""},

		// Test command with both allowed and denied subcommands
		{name: "NpmWithAllowedSubcommand", cmd: "npm", args: []string{"install"}, allowed: true, message: ""},
		{name: "NpmWithDeniedSubcommand", cmd: "npm", args: []string{"audit"}, allowed: false, message: "subcommand \"audit\" is denied for command \"npm\""},
		{name: "NpmWithDisallowedSubcommand", cmd: "npm", args: []string{"run"}, allowed: false, message: "subcommand \"run\" is not allowed for command \"npm\""},

		// Test edge cases
		{name: "EmptyCommand", cmd: "", args: []string{}, allowed: false, message: "command \"\" is not permitted: Command not allowed by security policy"},
		{name: "AllowedCommandWithNoArgs", cmd: "ls", args: []string{}, allowed: true, message: ""},
		{name: "CommandWithAllowedSubcommandsNoArgs", cmd: "git", args: []string{}, allowed: true, message: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset log buffer for each test
			logBuffer.Reset()

			// Use current working directory for test
			wd, err := os.Getwd()
			if err != nil {
				t.Fatalf("Failed to get working directory: %v", err)
			}

			gotAllowed, gotMessage := v.ValidateCommand(tt.cmd, tt.args, wd)
			if gotAllowed != tt.allowed {
				t.Errorf("ValidateCommand() allowed = %v, want %v", gotAllowed, tt.allowed)
			}
			if gotMessage != tt.message {
				t.Errorf("ValidateCommand() message = %q, want %q", gotMessage, tt.message)
			}
		})
	}
}

// TestValidateCommandWithDenyFlags tests recursive denyFlags validation.
func TestValidateCommandWithDenyFlags(t *testing.T) {
	// Setup test config
	cfg := &config.ShellCommandConfig{
		AllowedDirectories: []string{"/home", "/tmp"},
		AllowCommands: []config.AllowCommand{
			{
				Command: "git",
				SubCommands: []config.SubCommandRule{
					{Name: "status"},
					{Name: "log"},
					{
						Name:      "push",
						DenyFlags: []string{"-f", "--force", "--force-with-lease"},
						Message:   "Force push is not allowed",
					},
					{
						Name:      "branch",
						DenyFlags: []string{"-D"},
					},
				},
				DenySubCommands: []string{"reset"},
			},
			{
				Command: "docker",
				SubCommands: []config.SubCommandRule{
					{Name: "ps"},
					{Name: "logs"},
					{
						Name: "compose",
						SubCommands: []config.SubCommandRule{
							{
								Name:      "up",
								DenyFlags: []string{"--force-recreate", "--no-deps"},
							},
							{Name: "down"},
							{Name: "logs"},
						},
					},
				},
			},
		},
		DenyCommands:        []config.DenyCommand{},
		DefaultErrorMessage: "Command not allowed",
		BlockLogPath:        "",
	}

	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)
	v := New(cfg, log)

	tests := []struct {
		name    string
		cmd     string
		args    []string
		allowed bool
		message string
	}{
		// git push: allowed without force flags
		{name: "GitPushAllowed", cmd: "git", args: []string{"push"}, allowed: true, message: ""},
		{name: "GitPushOriginMain", cmd: "git", args: []string{"push", "origin", "main"}, allowed: true, message: ""},
		// git push -f: denied
		{name: "GitPushForceDenied", cmd: "git", args: []string{"push", "-f"}, allowed: false, message: `flag "-f" is not allowed for command "git push": Force push is not allowed`},
		{name: "GitPushForceLongDenied", cmd: "git", args: []string{"push", "--force"}, allowed: false, message: `flag "--force" is not allowed for command "git push": Force push is not allowed`},
		{name: "GitPushForceWithLeaseDenied", cmd: "git", args: []string{"push", "--force-with-lease"}, allowed: false, message: `flag "--force-with-lease" is not allowed for command "git push": Force push is not allowed`},
		// git push with force flag not at position 1
		{name: "GitPushOriginForce", cmd: "git", args: []string{"push", "origin", "main", "-f"}, allowed: false, message: `flag "-f" is not allowed for command "git push": Force push is not allowed`},

		// git branch: -d allowed, -D denied
		{name: "GitBranchDeleteAllowed", cmd: "git", args: []string{"branch", "-d", "feature"}, allowed: true, message: ""},
		{name: "GitBranchForceDeleteDenied", cmd: "git", args: []string{"branch", "-D", "feature"}, allowed: false, message: `flag "-D" is not allowed for command "git branch"`},

		// git status: no restrictions
		{name: "GitStatusAllowed", cmd: "git", args: []string{"status"}, allowed: true, message: ""},

		// git reset: denied by denySubCommands
		{name: "GitResetDenied", cmd: "git", args: []string{"reset"}, allowed: false, message: `subcommand "reset" is denied for command "git"`},

		// docker compose up: allowed without denied flags
		{name: "DockerComposeUp", cmd: "docker", args: []string{"compose", "up"}, allowed: true, message: ""},
		{name: "DockerComposeUpDetach", cmd: "docker", args: []string{"compose", "up", "-d"}, allowed: true, message: ""},
		// docker compose up --force-recreate: denied
		{name: "DockerComposeUpForceRecreate", cmd: "docker", args: []string{"compose", "up", "--force-recreate"}, allowed: false, message: `flag "--force-recreate" is not allowed for command "docker compose up"`},
		{name: "DockerComposeUpNoDeps", cmd: "docker", args: []string{"compose", "up", "--no-deps"}, allowed: false, message: `flag "--no-deps" is not allowed for command "docker compose up"`},

		// docker compose down: allowed (no restrictions)
		{name: "DockerComposeDown", cmd: "docker", args: []string{"compose", "down"}, allowed: true, message: ""},

		// docker ps: allowed
		{name: "DockerPs", cmd: "docker", args: []string{"ps"}, allowed: true, message: ""},

		// docker unknown subcommand: denied (allowlist mode)
		{name: "DockerUnknownSubcommand", cmd: "docker", args: []string{"run"}, allowed: false, message: `subcommand "run" is not allowed for command "docker"`},

		// docker compose unknown: denied (allowlist mode)
		{name: "DockerComposeUnknown", cmd: "docker", args: []string{"compose", "build"}, allowed: false, message: `subcommand "build" is not allowed for command "docker compose"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logBuffer.Reset()
			gotAllowed, gotMessage := v.ValidateCommand(tt.cmd, tt.args, "/home")
			if gotAllowed != tt.allowed {
				t.Errorf("ValidateCommand() allowed = %v, want %v (message: %q)", gotAllowed, tt.allowed, gotMessage)
			}
			if gotMessage != tt.message {
				t.Errorf("ValidateCommand() message = %q, want %q", gotMessage, tt.message)
			}
		})
	}
}

// TestDenyFlagsCombinedShortFlags tests that combined short flags like -fv are detected.
func TestDenyFlagsCombinedShortFlags(t *testing.T) {
	cfg := &config.ShellCommandConfig{
		AllowedDirectories: []string{"/home", "/tmp"},
		AllowCommands: []config.AllowCommand{
			{
				Command: "git",
				SubCommands: []config.SubCommandRule{
					{
						Name:      "push",
						DenyFlags: []string{"-f", "--force", "--force-with-lease"},
					},
					{
						Name:      "branch",
						DenyFlags: []string{"-D"},
					},
				},
			},
		},
		DefaultErrorMessage: "Command not allowed",
	}

	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)
	v := New(cfg, log)

	tests := []struct {
		name    string
		cmd     string
		args    []string
		allowed bool
	}{
		// Combined short flag containing denied flag
		{name: "CombinedFlagContainingDenied_fv", cmd: "git", args: []string{"push", "-fv"}, allowed: false},
		{name: "CombinedFlagContainingDenied_vf", cmd: "git", args: []string{"push", "-vf"}, allowed: false},
		{name: "CombinedFlagWithoutDenied_va", cmd: "git", args: []string{"push", "-va"}, allowed: true},
		// Exact match still works
		{name: "ExactDenyFlag_f", cmd: "git", args: []string{"push", "-f"}, allowed: false},
		{name: "ExactDenyFlag_force", cmd: "git", args: []string{"push", "--force"}, allowed: false},
		// --flag=value format
		{name: "FlagEqualsValue_force", cmd: "git", args: []string{"push", "--force=true"}, allowed: false},
		{name: "FlagEqualsValue_forceWithLease", cmd: "git", args: []string{"push", "--force-with-lease=origin/main"}, allowed: false},
		// Should NOT match partial long flag names
		{name: "PartialLongFlagNotMatched", cmd: "git", args: []string{"push", "--forced"}, allowed: true},
		// Multi-char short denied flag (-D) should only exact match, not expand
		{name: "MultiCharDenyFlagExact", cmd: "git", args: []string{"branch", "-D"}, allowed: false},
		{name: "MultiCharDenyFlagNotExpanded", cmd: "git", args: []string{"branch", "-Da"}, allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logBuffer.Reset()
			gotAllowed, _ := v.ValidateCommand(tt.cmd, tt.args, "/home")
			if gotAllowed != tt.allowed {
				t.Errorf("ValidateCommand(%s %v) allowed = %v, want %v", tt.cmd, tt.args, gotAllowed, tt.allowed)
			}
		})
	}
}

// TestCommandLogging tests the command logging functionality.
func TestCommandLogging(t *testing.T) {
	// Create temporary directories for testing
	tempHomeDir := t.TempDir()
	tempWorkDir := filepath.Join(t.TempDir(), "workdir")

	// Create the workdir subdirectory
	err := os.Mkdir(tempWorkDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temp work directory: %v", err)
	}

	// Create a temporary directory for the log file
	tempDir := t.TempDir()

	// Create log file path
	logPath := filepath.Join(tempDir, "blocked.log")

	// Setup test config with log path
	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{tempHomeDir, tempWorkDir},
		AllowCommands:       []config.AllowCommand{{Command: "ls"}},
		DenyCommands:        []config.DenyCommand{{Command: "rm"}},
		DefaultErrorMessage: "Command not allowed",
		BlockLogPath:        logPath,
	}

	// Create a logger
	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)

	// Create the validator
	v := New(cfg, log)

	// Test blocked command to trigger logging
	wd, _ := os.Getwd()
	v.ValidateCommand("rm", []string{"-rf", tempWorkDir}, wd)

	// Check if log file was created and contains the expected content
	logContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logStr := string(logContent)
	if !strings.Contains(logStr, "[BLOCKED] Command: rm [-rf ") || !strings.Contains(logStr, filepath.Base(tempWorkDir)) {
		t.Errorf("Expected blocked command log entry, got: %s", logStr)
	}
}

// TestLogBlockedCommandError tests error handling in logBlockedCommand.
func TestLogBlockedCommandError(t *testing.T) {
	// Create temporary directories for testing
	tempHomeDir := t.TempDir()
	tempWorkDir := filepath.Join(t.TempDir(), "workdir")

	// Create the workdir subdirectory
	err := os.Mkdir(tempWorkDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temp work directory: %v", err)
	}

	// Create a non-existent directory path
	testDir := "/non-existent-dir-" + tempDirSuffix()

	// Setup test config with invalid log path
	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{tempHomeDir, tempWorkDir},
		AllowCommands:       []config.AllowCommand{{Command: "ls"}},
		DenyCommands:        []config.DenyCommand{{Command: "rm"}},
		DefaultErrorMessage: "Command not allowed",
		BlockLogPath:        filepath.Join(testDir, "blocked.log"), // Path that likely can't be written to
	}

	// Create a logger with a buffer to capture error logs
	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)

	// Create the validator
	v := New(cfg, log)

	// Test blocked command to trigger logging attempt
	wd, _ := os.Getwd()
	v.ValidateCommand("rm", []string{"-rf", tempWorkDir}, wd)

	// Check if error was logged
	if !strings.Contains(logBuffer.String(), "Failed to create directory for block log") {
		// This is a bit tricky since we're testing with a non-existent path that might
		// actually be writable on some systems. If the test fails, it might be because
		// the non-existent directory was creatable.
		if _, err := os.Stat(testDir); os.IsNotExist(err) {
			t.Errorf("Expected error log about directory creation, got: %s", logBuffer.String())
		}
	}
}

// Helper to generate a unique temp directory suffix.
func tempDirSuffix() string {
	return filepath.Base(os.TempDir()) + "-" + filepath.Base(filepath.Join("validator", "test"))
}

// TestSymlinkDirectoryEscape tests that symlinks pointing outside allowed directories are rejected.
func TestSymlinkDirectoryEscape(t *testing.T) {
	// Create allowed directory and a target directory outside of it
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create a file in the outside directory
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("Failed to create outside file: %v", err)
	}

	// Create a symlink inside the allowed directory pointing to the outside directory
	symlinkPath := filepath.Join(allowedDir, "escape_link")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{allowedDir},
		DefaultErrorMessage: "Path not allowed",
	}

	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)
	v := New(cfg, log)

	tests := []struct {
		name    string
		path    string
		baseDir string
		allowed bool
	}{
		{
			name:    "SymlinkToOutsideDir",
			path:    symlinkPath,
			baseDir: allowedDir,
			allowed: false, // symlink resolves to outsideDir which is not allowed
		},
		{
			name:    "FileViaSymlinkToOutsideDir",
			path:    filepath.Join(symlinkPath, "secret.txt"),
			baseDir: allowedDir,
			allowed: false, // resolves to outsideDir/secret.txt
		},
		{
			name:    "DirectPathToOutsideDir",
			path:    outsideDir,
			baseDir: allowedDir,
			allowed: false,
		},
		{
			name:    "DirectPathInsideAllowed",
			path:    filepath.Join(allowedDir, "normal.txt"),
			baseDir: allowedDir,
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAllowed, _ := v.IsPathInAllowedDirectory(tt.path, tt.baseDir)
			if gotAllowed != tt.allowed {
				t.Errorf("IsPathInAllowedDirectory(%q) allowed = %v, want %v", tt.path, gotAllowed, tt.allowed)
			}
		})
	}
}

// TestSymlinkInAllowedDirectoryConfig tests symlink resolution in the allowed directory list itself.
func TestSymlinkInAllowedDirectoryConfig(t *testing.T) {
	// Create real target directory
	realDir := t.TempDir()

	// Create a symlink that will be used as an allowed directory
	symlinkDir := filepath.Join(t.TempDir(), "linked_allowed")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{symlinkDir},
		DefaultErrorMessage: "Path not allowed",
	}

	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)
	v := New(cfg, log)

	// A file in the real directory should be allowed since the symlink points to it
	allowed, _ := v.IsPathInAllowedDirectory(filepath.Join(realDir, "file.txt"), realDir)
	if !allowed {
		t.Error("File in real directory should be allowed when allowed dir is a symlink pointing to it")
	}
}

// TestIsDirectoryAllowedWithSymlink tests IsDirectoryAllowed with symlinked directories.
func TestIsDirectoryAllowedWithSymlink(t *testing.T) {
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create a symlink inside allowed dir pointing outside
	symlinkPath := filepath.Join(allowedDir, "escape")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{allowedDir},
		DefaultErrorMessage: "Not allowed",
	}

	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)
	v := New(cfg, log)

	// The symlink path resolves to outsideDir — should be denied
	allowed, _ := v.IsDirectoryAllowed(symlinkPath)
	if allowed {
		t.Error("IsDirectoryAllowed() should deny symlink that resolves outside allowed directories")
	}

	// The real allowed dir should still be allowed
	allowed, _ = v.IsDirectoryAllowed(allowedDir)
	if !allowed {
		t.Error("IsDirectoryAllowed() should allow the real allowed directory")
	}
}

// TestMultiLevelSymlink tests that chained symlinks are fully resolved.
func TestMultiLevelSymlink(t *testing.T) {
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create chain: allowedDir/link1 -> allowedDir/link2 -> outsideDir
	intermediateLink := filepath.Join(allowedDir, "link2")
	if err := os.Symlink(outsideDir, intermediateLink); err != nil {
		t.Fatalf("Failed to create intermediate symlink: %v", err)
	}

	topLink := filepath.Join(allowedDir, "link1")
	if err := os.Symlink(intermediateLink, topLink); err != nil {
		t.Fatalf("Failed to create top-level symlink: %v", err)
	}

	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{allowedDir},
		DefaultErrorMessage: "Not allowed",
	}

	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)
	v := New(cfg, log)

	// Multi-level symlink should resolve to outsideDir — denied
	allowed, _ := v.IsPathInAllowedDirectory(filepath.Join(topLink, "file.txt"), allowedDir)
	if allowed {
		t.Error("Multi-level symlink resolving outside should be denied")
	}
}

// TestNoLogPathSet tests that no logging occurs when BlockLogPath is empty.
func TestNoLogPathSet(t *testing.T) {
	// Create temporary directories for testing
	tempHomeDir := t.TempDir()
	tempWorkDir := filepath.Join(t.TempDir(), "workdir")

	// Create the workdir subdirectory
	err := os.Mkdir(tempWorkDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temp work directory: %v", err)
	}

	// Setup test config with no log path
	cfg := &config.ShellCommandConfig{
		AllowedDirectories:  []string{tempHomeDir, tempWorkDir},
		AllowCommands:       []config.AllowCommand{{Command: "ls"}},
		DenyCommands:        []config.DenyCommand{{Command: "rm"}},
		DefaultErrorMessage: "Command not allowed",
		BlockLogPath:        "", // Empty log path
	}

	// Create a logger with a buffer to capture logs
	var logBuffer bytes.Buffer
	log := logger.NewWithWriter(&logBuffer)

	// Create the validator
	v := New(cfg, log)

	// Test blocked command
	wd, _ := os.Getwd()
	v.ValidateCommand("rm", []string{"-rf", tempWorkDir}, wd)

	// Verify no errors about log file creation were logged
	if strings.Contains(logBuffer.String(), "Failed to create directory for block log") {
		t.Errorf("Unexpected log message about log directory: %s", logBuffer.String())
	}

	if strings.Contains(logBuffer.String(), "Failed to open block log file") {
		t.Errorf("Unexpected log message about log file: %s", logBuffer.String())
	}

	if strings.Contains(logBuffer.String(), "Failed to write to block log file") {
		t.Errorf("Unexpected log message about writing to log: %s", logBuffer.String())
	}
}

package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shimizu1995/secure-shell-server/pkg/config"
	"github.com/shimizu1995/secure-shell-server/pkg/logger"
)

const (
	// DirPermissions represents the permission bits for directories.
	DirPermissions = 0o755
	// FilePermissions represents the permission bits for files.
	FilePermissions = 0o644
)

// CommandValidator validates shell commands.
type CommandValidator struct {
	config *config.ShellCommandConfig
	logger *logger.Logger
}

// New creates a new CommandValidator.
func New(config *config.ShellCommandConfig, logger *logger.Logger) *CommandValidator {
	return &CommandValidator{
		config: config,
		logger: logger,
	}
}

// IsDirectoryAllowed checks if a given directory is allowed to run commands in.
func (v *CommandValidator) IsDirectoryAllowed(dir string) (bool, string) {
	// If the directory is empty, it cannot be validated
	if dir == "" {
		return false, "empty directory path is not allowed"
	}

	// Resolve symlinks to get the real path
	resolvedDir := resolveSymlinksPath(dir)

	// Check if the directory is in the allowed directories list or is a subdirectory of an allowed directory
	for _, allowedDir := range v.config.AllowedDirectories {
		resolvedAllowed := resolveSymlinksPath(allowedDir)
		if strings.HasPrefix(resolvedDir, resolvedAllowed) {
			return true, ""
		}
	}

	return false, fmt.Sprintf("directory %q is not allowed: %s", dir, v.config.DefaultErrorMessage)
}

// IsPathInAllowedDirectory checks if a given path (absolute or relative) is within any of the allowed directories.
func (v *CommandValidator) IsPathInAllowedDirectory(path string, baseDir string) (bool, string) {
	// Handle empty path
	if path == "" {
		return false, "empty path is not allowed"
	}

	// Determine if the path is absolute or relative
	var absPath string
	var err error
	if filepath.IsAbs(path) {
		absPath = path
	} else {
		// For relative paths, join with the base directory
		absPath = filepath.Join(baseDir, path)
	}

	// Clean the path to resolve any . or .. components
	absPath = filepath.Clean(absPath)

	// Get absolute path to ensure proper comparison
	absPath, err = filepath.Abs(absPath)
	if err != nil {
		return false, fmt.Sprintf("failed to resolve absolute path: %v", err)
	}

	// Resolve symlinks to get the real path
	absPath = resolveSymlinksPath(absPath)

	// Check if the resolved path is within any allowed directory
	for _, allowedDir := range v.config.AllowedDirectories {
		// Get absolute path of allowed directory for proper comparison
		allowedAbsDir, err := filepath.Abs(allowedDir)
		if err != nil {
			continue // Skip directories that can't be resolved
		}

		// Resolve symlinks in the allowed directory as well
		allowedAbsDir = resolveSymlinksPath(allowedAbsDir)

		// Check if path is within the allowed directory
		if strings.HasPrefix(absPath, allowedAbsDir) {
			return true, ""
		}
	}

	msg := fmt.Sprintf("path %q is outside of allowed directories: %s", path, v.config.DefaultErrorMessage)
	if looksLikeEmptyVarPrefix(path) {
		msg += ` (hint: looks like "$VAR/..." with VAR empty; use "${VAR:-/tmp}" or set VAR)`
	}
	return false, msg
}

// looksLikeEmptyVarPrefix reports whether path is a single-segment absolute
// path (e.g. "/file.log"), which is the typical shape of "$EMPTY/file.log".
func looksLikeEmptyVarPrefix(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	rest := path[1:]
	return rest != "" && !strings.Contains(rest, "/")
}

// resolveSymlinksPath resolves symlinks in a path.
// If the full path doesn't exist, it walks up to the deepest existing ancestor,
// resolves symlinks there, and appends the remaining components.
func resolveSymlinksPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}

	// Path doesn't fully exist — resolve the deepest existing ancestor
	parent := filepath.Dir(path)
	if parent == path {
		// Reached root without resolving — return as-is
		return path
	}

	resolvedParent := resolveSymlinksPath(parent)
	return filepath.Join(resolvedParent, filepath.Base(path))
}

// isPathLike checks if an argument looks like a file path.
func (v *CommandValidator) isPathLike(arg string) bool {
	// Check if the argument contains path separators or starts with common path prefixes
	return strings.Contains(arg, string(os.PathSeparator)) ||
		strings.Contains(arg, "/") || // For Unix paths
		strings.Contains(arg, "\\") || // For Windows paths
		strings.HasPrefix(arg, "./") ||
		strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "~") ||
		strings.HasPrefix(arg, ".")
}

// ValidateCommand checks if a command is allowed based on the configuration.
func (v *CommandValidator) ValidateCommand(cmd string, args []string, workDir string) (bool, string) {
	// Special handling for xargs command
	if cmd == "xargs" {
		return v.validateXargsCommand(args, workDir)
	}

	// Special handling for find command with -exec
	if cmd == "find" {
		return v.validateFindCommand(args, workDir)
	}

	// Special handling for awk commands (awk, gawk, mawk, nawk)
	if IsAwkCommand(cmd) {
		return v.validateAwkCommand(cmd, args, workDir)
	}

	// Special handling for sed commands (sed, gsed)
	if IsSedCommand(cmd) {
		return v.validateSedCommand(cmd, args, workDir)
	}

	// Check if the command is explicitly denied
	if denied, message := v.isCommandExplicitlyDenied(cmd); denied {
		v.logBlockedCommand(cmd, args, message)
		return false, message
	}

	// Check if the command is explicitly allowed
	for _, allowed := range v.config.AllowCommands {
		if allowed.Command == cmd {
			// Deny global flags are checked across all args before anything else.
			if denied, message := v.checkDenyGlobalFlags(cmd, args, allowed.DenyGlobalFlags); denied {
				return false, message
			}

			// If there are no subcommands specified, the command is allowed without restrictions
			if len(allowed.SubCommands) == 0 && len(allowed.DenySubCommands) == 0 {
				// Check path-like arguments even for fully allowed commands
				return v.validatePathArguments(cmd, args, workDir)
			}

			// Strip leading global flags before subcommand matching.
			subArgs := stripLeadingGlobalFlags(args, allowed.GlobalFlags)

			// Check subcommand permissions
			if ok, message := v.checkSubCommandRule(cmd, subArgs, allowed.SubCommands, allowed.DenySubCommands, nil, ""); !ok {
				return false, message
			}

			// If subcommand is allowed, also validate any path-like arguments
			return v.validatePathArguments(cmd, args, workDir)
		}
	}

	// If command was not found in the allow list, it's denied
	deniedMessage := fmt.Sprintf("command %q is not permitted: %s", cmd, v.config.DefaultErrorMessage)
	v.logBlockedCommand(cmd, args, deniedMessage)
	return false, deniedMessage
}

// validatePathArguments checks if any path-like arguments are within allowed directories.
func (v *CommandValidator) validatePathArguments(cmd string, args []string, workDir string) (bool, string) {
	for _, arg := range args {
		pathArg := arg

		// `--flag=value` form: extract the value portion so its embedded path is
		// validated. Without this, `--git-dir=/etc/.git` would skip path checks
		// because the whole arg starts with `-`.
		if strings.HasPrefix(arg, "-") {
			eq := strings.IndexByte(arg, '=')
			if eq < 0 {
				continue
			}
			pathArg = arg[eq+1:]
		}

		if !v.isPathLike(pathArg) {
			continue
		}

		allowed, message := v.IsPathInAllowedDirectory(pathArg, workDir)
		if !allowed {
			v.logBlockedCommand(cmd, args, message)
			return false, message
		}
	}

	return true, ""
}

// isCommandExplicitlyDenied checks if a command is explicitly denied in the configuration.
func (v *CommandValidator) isCommandExplicitlyDenied(cmd string) (bool, string) {
	for _, denied := range v.config.DenyCommands {
		if denied.Command == cmd {
			message := v.config.DefaultErrorMessage
			if denied.Message != "" {
				message = denied.Message
			}
			return true, fmt.Sprintf("command %q is denied: %s", cmd, message)
		}
	}
	return false, ""
}

// stripLeadingGlobalFlags returns args with leading global flags (and their
// values when TakesValue is true) removed. It stops at the first arg that
// does not match any allowed global flag, leaving the rest for subcommand
// matching.
func stripLeadingGlobalFlags(args []string, globalFlags []config.GlobalFlag) []string {
	if len(globalFlags) == 0 {
		return args
	}
	i := 0
	for i < len(args) {
		gf, matched := matchGlobalFlag(args[i], globalFlags)
		if !matched {
			break
		}
		// `--name=value` already bundles the value in args[i].
		hasInlineValue := strings.Contains(args[i], "=")
		i++
		if gf.TakesValue && !hasInlineValue && i < len(args) {
			i++
		}
	}
	return args[i:]
}

// matchGlobalFlag reports whether arg matches one of globalFlags by exact
// name (`-C`) or `--name=value` form. Returns the matched flag spec.
func matchGlobalFlag(arg string, globalFlags []config.GlobalFlag) (config.GlobalFlag, bool) {
	for _, gf := range globalFlags {
		if arg == gf.Name {
			return gf, true
		}
		if strings.HasPrefix(arg, gf.Name+"=") {
			return gf, true
		}
	}
	return config.GlobalFlag{}, false
}

// checkDenyGlobalFlags scans every arg and returns true with an error message
// if any matches a denyGlobalFlag. Matches anywhere in args, not just leading.
func (v *CommandValidator) checkDenyGlobalFlags(cmd string, args []string, denyFlags []config.GlobalFlag) (bool, string) {
	if len(denyFlags) == 0 {
		return false, ""
	}
	for _, arg := range args {
		gf, matched := matchGlobalFlag(arg, denyFlags)
		if !matched {
			continue
		}
		message := fmt.Sprintf("flag %q is not allowed for command %q", gf.Name, cmd)
		if gf.Message != "" {
			message += ": " + gf.Message
		}
		v.logBlockedCommand(cmd, args, message)
		return true, message
	}
	return false, ""
}

// checkSubCommandRule recursively validates args against a SubCommandRule tree.
// cmdPath is the command path so far (e.g. "git" or "docker compose") for error messages.
// subCommands is the list of allowed sub-command rules at this level.
// denySubCommands is the list of denied sub-commands at this level.
// denyFlags is the list of denied flags at this level.
// message is a custom error message for denied flags at this level.
func (v *CommandValidator) checkSubCommandRule(cmdPath string, args []string, subCommands []config.SubCommandRule, denySubCommands []string, denyFlags []string, message string) (bool, string) {
	// If no more args, nothing to deny
	if len(args) == 0 {
		return true, ""
	}

	// Check denied subcommands at this level
	for _, denied := range denySubCommands {
		if args[0] == denied {
			deniedMessage := fmt.Sprintf("subcommand %q is denied for command %q", args[0], cmdPath)
			v.logBlockedCommand(cmdPath, args, deniedMessage)
			return false, deniedMessage
		}
	}

	// If there are subcommand rules, try to match args[0] against them
	if len(subCommands) > 0 {
		for _, rule := range subCommands {
			if rule.Name == args[0] {
				// Found a matching rule — recurse into it
				nextPath := cmdPath + " " + args[0]
				return v.checkSubCommandRule(nextPath, args[1:], rule.SubCommands, rule.DenySubCommands, rule.DenyFlags, rule.Message)
			}
		}

		// args[0] not found in allowed subcommands (allowlist mode) — deny
		deniedMessage := fmt.Sprintf("subcommand %q is not allowed for command %q", args[0], cmdPath)
		v.logBlockedCommand(cmdPath, args, deniedMessage)
		return false, deniedMessage
	}

	// No subcommand rules at this level — check denyFlags against all remaining args
	return v.checkDenyFlags(cmdPath, args, denyFlags, message)
}

// checkDenyFlags scans args for any flag in denyFlags.
func (v *CommandValidator) checkDenyFlags(cmdPath string, args []string, denyFlags []string, message string) (bool, string) {
	for _, arg := range args {
		for _, denied := range denyFlags {
			if isDenyFlagMatch(arg, denied) {
				deniedMessage := fmt.Sprintf("flag %q is not allowed for command %q", denied, cmdPath)
				if message != "" {
					deniedMessage += ": " + message
				}
				v.logBlockedCommand(cmdPath, args, deniedMessage)
				return false, deniedMessage
			}
		}
	}
	return true, ""
}

// isDenyFlagMatch checks if an argument matches a denied flag.
// It supports:
//   - Exact match: "-f" == "-f"
//   - Combined short flags: "-fv" contains denied "-f" (single-char short flag)
//   - --flag=value format: "--force=true" matches denied "--force"
func isDenyFlagMatch(arg, denied string) bool {
	// Exact match
	if arg == denied {
		return true
	}

	// --flag=value format: denied is "--xyz", arg is "--xyz=something"
	if strings.HasPrefix(denied, "--") && strings.HasPrefix(arg, denied+"=") {
		return true
	}

	// Combined short flags: denied is "-X" (single hyphen + 1 char),
	// arg is "-XY..." (single hyphen, not "--")
	if len(denied) == 2 && denied[0] == '-' && denied[1] != '-' &&
		len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
		// Check if the denied character appears in the combined flags
		deniedChar := denied[1]
		for _, c := range arg[1:] {
			if byte(c) == deniedChar {
				return true
			}
		}
	}

	return false
}

// validateXargsCommand checks if the command executed by xargs is allowed.
func (v *CommandValidator) validateXargsCommand(args []string, workDir string) (bool, string) {
	// First check if xargs itself is allowed
	if denied, message := v.isCommandExplicitlyDenied("xargs"); denied {
		v.logBlockedCommand("xargs", args, message)
		return false, message
	}

	// Check if xargs is explicitly allowed
	if !v.config.IsCommandAllowed("xargs") {
		deniedMessage := fmt.Sprintf("command %q is not permitted: %s", "xargs", v.config.DefaultErrorMessage)
		v.logBlockedCommand("xargs", args, deniedMessage)
		return false, deniedMessage
	}

	// Parse the xargs command to extract the actual command
	parser := NewXargsParser()
	xargsCmd, xargsArgs, valid, errMsg := parser.ParseXargsCommand(args)

	if !valid {
		v.logBlockedCommand("xargs", args, errMsg)
		return false, errMsg
	}

	// Now validate the command that xargs will execute
	allowed, message := v.ValidateCommand(xargsCmd, xargsArgs, workDir)
	if !allowed {
		// Add context that this is from an xargs command
		message = "xargs would execute disallowed command: " + message
		v.logBlockedCommand("xargs", args, message)
		return false, message
	}

	return true, ""
}

// validateFindCommand checks if find command has -exec with allowed commands only.
func (v *CommandValidator) validateFindCommand(args []string, workDir string) (bool, string) {
	// First check if find itself is allowed
	if denied, message := v.isCommandExplicitlyDenied("find"); denied {
		v.logBlockedCommand("find", args, message)
		return false, message
	}

	// Check if find is explicitly allowed
	if !v.config.IsCommandAllowed("find") {
		deniedMessage := fmt.Sprintf("command %q is not permitted: %s", "find", v.config.DefaultErrorMessage)
		v.logBlockedCommand("find", args, deniedMessage)
		return false, deniedMessage
	}

	// Check for -exec commands in find args
	parser := NewFindParser()
	execCommands, hasExec, errMsg := parser.ParseFindExecArgs(args)

	if errMsg != "" {
		v.logBlockedCommand("find", args, errMsg)
		return false, errMsg
	}

	// If no -exec found, the find command is allowed (we still need to validate paths)
	if !hasExec {
		// Filter out special characters used by find -exec syntax before path validation
		filteredArgs := parser.FilterFindSpecialArgs(args)
		return v.validatePathArguments("find", filteredArgs, workDir)
	}

	// Validate each -exec command with its full arguments
	for _, execCmd := range execCommands {
		allowed, message := v.ValidateCommand(execCmd.Name, execCmd.Args, workDir)
		if !allowed {
			message = "find command contains disallowed -exec: " + message
			v.logBlockedCommand("find", args, message)
			return false, message
		}
	}

	// If all -exec commands are allowed, validate path arguments
	// Filter out special characters used by find -exec syntax before path validation
	filteredArgs := parser.FilterFindSpecialArgs(args)
	return v.validatePathArguments("find", filteredArgs, workDir)
}

// validateAwkCommand checks if an awk command contains dangerous patterns.
func (v *CommandValidator) validateAwkCommand(cmd string, args []string, workDir string) (bool, string) {
	// Check if the command is explicitly denied
	if denied, message := v.isCommandExplicitlyDenied(cmd); denied {
		v.logBlockedCommand(cmd, args, message)
		return false, message
	}

	// Check if the command is explicitly allowed
	if !v.config.IsCommandAllowed(cmd) {
		deniedMessage := fmt.Sprintf("command %q is not permitted: %s", cmd, v.config.DefaultErrorMessage)
		v.logBlockedCommand(cmd, args, deniedMessage)
		return false, deniedMessage
	}

	// Check for dangerous patterns in awk script
	awkValidator := NewAwkValidator()
	if hasDanger, description := awkValidator.ValidateAwkArgs(args); hasDanger {
		message := fmt.Sprintf("%s command blocked: %s", cmd, description)
		v.logBlockedCommand(cmd, args, message)
		return false, message
	}

	// Validate path arguments, filtering out the awk script and flags
	filteredArgs := filterAwkNonPathArgs(args)
	return v.validatePathArguments(cmd, filteredArgs, workDir)
}

// validateSedCommand checks if a sed command contains dangerous patterns.
func (v *CommandValidator) validateSedCommand(cmd string, args []string, workDir string) (bool, string) {
	// Check if the command is explicitly denied
	if denied, message := v.isCommandExplicitlyDenied(cmd); denied {
		v.logBlockedCommand(cmd, args, message)
		return false, message
	}

	// Check if the command is explicitly allowed
	if !v.config.IsCommandAllowed(cmd) {
		deniedMessage := fmt.Sprintf("command %q is not permitted: %s", cmd, v.config.DefaultErrorMessage)
		v.logBlockedCommand(cmd, args, deniedMessage)
		return false, deniedMessage
	}

	// Check for dangerous patterns in sed script
	sedValidator := NewSedValidator()
	if hasDanger, description := sedValidator.ValidateSedArgs(args); hasDanger {
		message := fmt.Sprintf("%s command blocked: %s", cmd, description)
		v.logBlockedCommand(cmd, args, message)
		return false, message
	}

	// Validate path arguments, filtering out sed scripts and expressions
	filteredArgs := filterSedNonPathArgs(args)
	return v.validatePathArguments(cmd, filteredArgs, workDir)
}

// logBlockedCommand logs blocked commands to the specified file.
func (v *CommandValidator) logBlockedCommand(cmd string, args []string, reason string) {
	if v.config.BlockLogPath == "" {
		return
	}

	// Ensure the directory exists
	dir := filepath.Dir(v.config.BlockLogPath)
	if err := os.MkdirAll(dir, DirPermissions); err != nil {
		v.logger.LogErrorf("Failed to create directory for block log: %v", err)
		return
	}

	// Open the log file in append mode
	f, err := os.OpenFile(v.config.BlockLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, FilePermissions)
	if err != nil {
		v.logger.LogErrorf("Failed to open block log file: %v", err)
		return
	}
	defer f.Close()

	// Create log entry
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("%s [BLOCKED] Command: %s %v, Reason: %s\n", timestamp, cmd, args, reason)

	// Write to log file
	if _, err := f.WriteString(logEntry); err != nil {
		v.logger.LogErrorf("Failed to write to block log file: %v", err)
	}
}

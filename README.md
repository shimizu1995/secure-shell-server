# Secure Shell Server

A Go-based MCP (Model Context Protocol) server designed to prevent Large Language Models (LLMs) from executing dangerous shell commands. The server provides a sandboxed environment that validates all commands against an allowlist, restricting operations to only those explicitly permitted.

## Important Security Notice

While this server implements multiple security measures, it cannot guarantee complete protection against all malicious commands or sophisticated attacks. Users should:

- Carefully configure the allowlist to include only necessary commands
- Regularly review logs for suspicious activity
- Use this as one layer in a comprehensive security strategy
- Not rely solely on this tool for high-security environments

## Features

- **Command Allowlisting**: Parses user-provided shell scripts and validates that only allowed commands are used.
- **Secure Execution**: Uses a custom runner to enforce the allowlist during command execution.
- **Subcommand Validation**: Supports recursive subcommand rules with fine-grained control over allowed subcommands.
- **Flag Denial**: Blocks dangerous flags on commands and subcommands at any nesting level (e.g., preventing `git push --force`).
- **Directory Restrictions**: Limits file system access to only explicitly allowed directories.
- **Path Validation**: Verifies all path arguments to prevent access to unauthorized directories.
- **Timeout Enforcement**: Automatically terminates long-running commands to prevent resource exhaustion.
- **Detailed Logging**: Logs all command attempts and execution results for auditing and debugging.
- **MCP Server Mode**: Functions as a Model Context Protocol (MCP) server for secure command execution.

## Installation

```bash
go get /path/to/secure-shell-server
cd /path/to/secure-shell-server
make build
```

The binaries will be available in the `bin/` directory.

## Usage

### Starting the MCP Server

```bash
./bin/server -config=/path/to/config.json
```

### Command-Line Options for server

- `-config`: Path to configuration file
- `-stdio`: Use stdin/stdout for MCP communication
- `-port`: Port to listen on (default: 8080, when not using stdio)

### Claude Code PreToolUse Hook Mode

`secure-shell` can also run as a Claude Code [PreToolUse hook](https://docs.claude.com/en/docs/claude-code/hooks) that validates `Bash` tool calls *before* they execute. The hook reads Claude Code's JSON payload from stdin, validates the command against the same allowlist used by the MCP server, and exits with code `2` to block the call (Claude Code surfaces stderr back to the model).

```bash
./bin/secure-shell -hook -config /path/to/config.json
```

Configure it in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/bin/secure-shell -hook -config /absolute/path/to/config.json"
          }
        ]
      }
    ]
  }
}
```

Behavior:

- `tool_name != "Bash"` → exit `0` (allow, no validation)
- Command passes validation → exit `0`
- Command denied → exit `2` with `Blocked by secure-shell-server: <reason>` on stderr

The working directory is taken from `tool_input.cwd` / `cwd` in the JSON payload (or `-dir` if you pass it explicitly). No commands are executed and no files are written — validation only.

## Claude Desktop Setup

To use secure-shell-server with Claude Desktop:

1. Edit your Claude Desktop configuration file located at:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
2. Add the following to your configuration under the `tools` section:

```json
"shell": {
  "command": "/path/to/secure-shell-server/bin/server",
  "args": [
    "-config",
    "~/path/to/your/config.json"
  ]
}
```

3. Create a configuration file at a location of your choice (such as `~/.mcp_shell_config.json` on macOS or appropriate path on Windows) with your desired settings
4. Restart Claude Desktop to apply the changes

## MCP Tools

The server exposes two MCP tools:

### `run`

Run one or more shell commands in the current working directory. Only allowed commands within allowed paths are permitted. Use the `cd` command to change directories (only within `allowedDirectories`). Directory changes from `cd` persist across subsequent `run` calls.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `commands` | Yes | List of commands to execute. Use `cd` to change directories within allowed paths. |
| `mode` | No | `"parallel"` (default) or `"serial"` |

### `pwd`

Print the current working directory.

### Usage Flow

```
1. run(commands: ["cd /home/user/project"])             -> Set working directory
2. run(commands: ["ls -la"])                            -> Execute command
3. run(commands: ["echo hello"])                        -> Directory persists
4. pwd()                                               -> Check current directory
5. run(commands: ["cd /tmp"])                           -> Change directory
6. run(commands: ["pwd"])                               -> Now in /tmp
7. run(commands: ["cd subdir", "ls -la"], mode: "serial") -> cd + command in one call
```

## Configuration

The security policy is defined in a JSON configuration file. This section explains the key configuration options, particularly the subcommand and flag denial features.

### Basic Structure

```json
{
  "allowedDirectories": ["/home", "/tmp"],
  "allowCommands": [...],
  "denyCommands": [...],
  "defaultErrorMessage": "Command not allowed",
  "maxExecutionTime": 120,
  "maxOutputSize": 51200
}
```

| Field | Description | Default |
|---|---|---|
| `allowedDirectories` | Directories where commands can operate | None (required) |
| `allowCommands` | List of allowed commands | `[]` |
| `denyCommands` | List of denied commands | `[]` |
| `defaultErrorMessage` | Default message when command is denied | `""` |
| `maxExecutionTime` | Maximum execution time in seconds. `0` for unlimited | `120` |
| `maxOutputSize` | Maximum output size in bytes. `0` for unlimited | `51200` |

### Subcommand Validation

Commands can specify allowed subcommands. Each subcommand can be:
- A simple string (bare subcommand name)
- A full object with additional restrictions

**Simple subcommand:**
```json
{
  "command": "git",
  "subCommands": ["status", "pull", "fetch"]
}
```

### Flag Denial (denyFlags)

You can deny specific flags on commands and subcommands at any nesting level. This is useful for preventing dangerous operations like force-push or force-recreate.

**Example: Deny dangerous flags on git push**
```json
{
  "command": "git",
  "subCommands": [
    {
      "name": "push",
      "denyFlags": ["-f", "--force", "--force-with-lease"],
      "message": "Force push is not allowed"
    }
  ]
}
```

When a user runs `git push -f`, the command will be blocked with the custom message.

### Recursive Subcommands

Subcommands can be nested to arbitrary depth, each with its own `denyFlags`. This allows fine-grained control over deeply nested command structures.

**Example: Recursive Docker Compose validation**
```json
{
  "command": "docker",
  "subCommands": [
    "ps",
    "logs",
    {
      "name": "compose",
      "subCommands": [
        {
          "name": "up",
          "denyFlags": ["--force-recreate"],
          "message": "Force recreate is not allowed"
        },
        "down",
        "logs"
      ]
    }
  ]
}
```

This configuration allows `docker compose up` but blocks `docker compose up --force-recreate`.

### Deny Subcommands

You can also explicitly deny specific subcommands using `denySubCommands`:

```json
{
  "command": "git",
  "subCommands": ["status", "pull", "push"],
  "denySubCommands": ["reset", "revert"]
}
```

### Complete Configuration Example

See `sample-config.json` for a comprehensive example covering:
- Simple allowed commands
- Commands with subcommand restrictions
- Subcommands with `denyFlags`
- Nested subcommands (e.g., `docker compose`)
- Explicit denied commands with custom messages

## Design and Implementation

The Secure Shell Server follows a modular design with the following components:

1. **Validator**: Parses and validates shell commands against an allowlist.
2. **Runner**: Executes validated commands using a secure custom runner.
3. **Config**: Manages allowlist configuration and runtime settings.
4. **Logger**: Provides detailed logging of all command attempts and results.
5. **Server**: MCP interface for secure shell execution service.

## Security Considerations

- Only explicitly allowlisted commands can be executed.
- File system access is restricted to specified directories.
- Command execution is constrained by a configurable timeout.
- Scripts are validated before execution to prevent dangerous operations.
- Special handling for commands like `find` and `xargs` that could execute other commands.
- Path arguments are validated to prevent access to restricted areas.
- Dangerous flags can be blocked at any subcommand level using `denyFlags`.

### Limitations

- Cannot prevent all sophisticated attacks or command chaining techniques.
- Command injection may still be possible in certain edge cases.
- Security effectiveness depends heavily on proper configuration.
- **Flag Matching**: Flag denial uses exact matching only:
  - Combined short flags (e.g., `-fv` containing `-f`) are not detected
  - `--flag=value` format requires exact match on the flag name part
  - Consider these patterns when designing your policy

## Development

### Prerequisites

- Go 1.20 or later
- `mvdan.cc/sh/v3` package

### Building

```bash
make build
```

### Testing

```bash
make test
```

### Linting

```bash
make lint
```

## License

This project is licensed under the terms found in the LICENSE file.

### Third-Party Licenses

This project uses the following third-party libraries:

- `mvdan.cc/sh/v3`: Licensed under the BSD-3-Clause license.

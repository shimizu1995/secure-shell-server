# Secure Shell Server

A Go-based tool for secure execution of shell commands using the `mvdan.cc/sh/v3` package. The tool validates and restricts commands to a predefined allowlist, enforcing secure shell operations while preventing unauthorized or potentially harmful commands.

## Features

- **Command Validation**: Parses user-provided shell scripts using the `syntax` package and validates that only allowed commands are used.
- **Secure Execution**: Uses a custom runner to enforce the allowlist during command execution.
- **Environment Restrictions**: Limits access to the file system, environment variables, and system resources.
- **Detailed Logging**: Logs all command attempts and execution results for auditing and debugging.

## Installation

```bash
go get github.com/shimizu1995/secure-shell-server
```

## Usage

### Running a Command

```bash
secure-shell-server run -cmd="ls -l"
```

### Running a Script

```bash
secure-shell-server run -script="echo 'Hello, World!'; ls -l"
```

### Reading a Script from a File

```bash
secure-shell-server run -file="/path/to/script.sh"
```

### Custom Configuration

```bash
secure-shell-server run -cmd="grep pattern file.txt" -allow="ls,echo,cat,grep" -timeout=60 -dir="/safe/directory"
```

### Command-Line Options

- `-cmd`: Command to execute
- `-script`: Script string to execute
- `-file`: Script file to execute
- `-allow`: Comma-separated list of allowed commands (default: "ls,echo,cat")
- `-timeout`: Maximum execution time in seconds (default: 30)
- `-dir`: Working directory for command execution

## Design and Implementation

The Secure Shell Server follows a modular design with the following components:

1. **Validator**: Parses and validates shell commands against an allowlist.
2. **Runner**: Executes validated commands using a secure custom runner.
3. **Config**: Manages allowlist configuration and runtime settings.
4. **Logger**: Provides detailed logging of all command attempts and results.

## Security Considerations

- Only explicitly allowlisted commands can be executed.
- Environment variables are restricted to a predefined set.
- Command execution is constrained by a configurable timeout.
- Scripts are validated before execution to prevent harmful operations.

## Development

### Prerequisites

- Go 1.24 or later
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

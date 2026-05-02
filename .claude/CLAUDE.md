# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Secure Shell Server is a Go MCP (Model Context Protocol) server that prevents LLMs from executing dangerous shell commands. It validates all commands against a configurable allowlist before execution. Commands not explicitly allowed are denied by default.

Two binaries:

- `cmd/server/main.go` — MCP server (stdio or HTTP mode) for Claude Desktop integration
- `cmd/secure-shell/main.go` — CLI tool for direct command execution with validation

## Build & Test Commands

```bash
make build        # Build both binaries to bin/
make test         # Run tests with race detector + coverage report
make lint         # Run golangci-lint with auto-fix
make spell        # Check spelling in markdown files
make vuln         # Run govulncheck
make precommit    # Full validation: build + lint + test + vuln
make ci           # precommit + git diff check (used in CI)
```

Run a single test:

```bash
go test -race -run TestName ./pkg/validator/
```

## Architecture

### Core Flow

1. **Shell parsing** — Uses `mvdan.cc/sh/v3` to parse commands in-process (no external /bin/sh)
2. **Validation** — `pkg/validator` checks every command/subcommand/flag against the allowlist config
3. **Execution** — `pkg/runner` executes validated commands via the Go shell interpreter with a custom `callFunc` that intercepts each command call for validation
4. **Output limiting** — `pkg/limiter` wraps stdout/stderr to enforce max output size

### Key Packages

- **`pkg/config`** — Loads JSON config with allowlists, deny lists, directory restrictions. Supports recursive subcommand rules with per-level flag denial. Commands can be simple strings or objects with nested subcommand rules.
- **`pkg/validator`** — Core security logic. Validates commands against allowlist, checks denied flags recursively, resolves symlinks to prevent path bypass, validates all path arguments against allowed directories. Has special-purpose validators for dangerous commands:
  - `find.go` — Validates commands inside `-exec`/`-execdir` clauses
  - `xargs.go` — Validates piped commands
  - `sed.go` — Blocks `e` command (shell execution)
  - `awk.go` — Blocks `system()`, pipes, `@load`
- **`pkg/runner`** — Wraps `mvdan.cc/sh/v3` interpreter. Parses the full script, intercepts every command via `interp.CallHandler`, validates before allowing execution. Handles pipes, redirects, subshells. The `cd` shell builtin is intercepted and validated against allowed directories, with directory changes propagated back to the server.
- **`service/server.go`** — MCP server exposing `run` and `pwd` tools. Uses `sync.Mutex` for thread safety. Holds session state (`workingDir`) that persists across `run` calls. Directory changes via `cd` command within `run` are tracked and persisted.

### Security Model

- Deny-all by default: only explicitly allowed commands execute
- Recursive subcommand validation with flag denial at any nesting level
- Symlink resolution prevents directory allowlist bypass
- All path arguments validated against allowed directories
- Special handlers block command injection via find -exec, xargs, sed e, awk system()

## Development Guidelines

After making changes, always run `make precommit` to catch issues locally before pushing. This runs build + lint + test + vuln in one command and mirrors what CI checks.

```bash
make precommit    # MUST pass before pushing — catches lint, test, and build errors locally
```

If you only want to run individual steps:

1. `make lint` — linting issues (golangci-lint with goconst, gosec, dupl, mnd, etc.)
2. `make test` — all tests pass with race detector
3. `make build` — both binaries compile

Keep code testable through appropriate file separation and function extraction. Avoid excessive nesting.

### Linting Notes

- `//nolint:dupl` is acceptable on test functions where structural similarity is intentional (e.g., table-driven tests for awk vs sed that test different commands but share the same pattern). Always add an explanation comment.

### Configuration

See `sample-config.json` for the full format. Key fields:

- `allowedDirectories` — Directories where commands can operate
- `allowCommands` — Allowlist (strings or objects with subCommands/denyFlags)
- `denyCommands` — Explicit deny with custom messages
- `maxExecutionTime` — Timeout in seconds (default: 120)
- `maxOutputSize` — Output limit in bytes (default: 51200)

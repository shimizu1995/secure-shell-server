# Development Instructions

When modifying or adding programs, please use the dev tool for development.

**When changing or adding files**, please use the sequentialthinking tool to organize your approach. A totalThoughts value of around 2 is sufficient. This tool is not necessary for other tasks like creating pull requests or documentation.

When writing code, please pay attention to the following points:

- Avoid excessive nesting
- Make code testable through appropriate file separation and function extraction
- Always add unit tests for non-UI code

For searching within the codebase, use the git grep command while in the project directory.

After completing your modifications, run `make test` and `make build` to confirm there are no issues.


Finally, please run the linter(`make lint`) to ensure code quality after the above commands don't raise any issues.

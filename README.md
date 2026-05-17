# ip6-automatisierte-sicherheitseval

Vulnerability validation framework with an MCP server for AI assistants (like Claude Desktop).

## Requirements
- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- Node.js (required for MCP-Filesystem-Server in Claude Desktop Chat, not required for Claude Code)
    Windows: `scoop install nodejs-lts` or Installer from nodejs.org
    Mac/Linux: `brew install node`
- Claude Desktop


## Quick start
1. Clone the repository.
2. Install dependencies and the local package:

```bash
uv sync
```

3. Verify package import (recommended, quick check):

```bash
uv run python -c "import vuln_validator; print('ok')"
```

## Binary compilation (Linux)
For reliable exploit analysis, binaries **must** be compiled without protections using the flags below.

**C**
```bash
gcc ./binary.c -o binary -fno-stack-protector -z execstack -no-pie -g
```

**C++**
```bash
g++ ./binary.cpp -o ./binary -fno-stack-protector -z execstack -fno-exceptions -fno-rtti -no-pie -g
```


## Claude Desktop integration (Windows)
For Claude to bei able to read and analyze your source-files, MCP-Server musst be configured.

1. Locate config file:
   - Windows: Press Win + R, enter: %APPDATA%\Claude\claude_desktop_config.json

2. Configure servers:
Copy the `mcpServers` block from `config/claude_desktop_config.example` and enter in `claude_desktop_config`. Replace both the project path and the path to your code files.<br>
**Note**: You don't need to define exact path for code files but Claude Code will have access to all files in your provided path

3. Activate:
   - Restart Claude Desktop after saving the config.

4. In Claude chat:
   - Click +, then Connectors.
   - Choose Add from VulnValidator.
   - Select Find vulnerability workflow.
   - Enter the target path and send.

## How it works

The framework uses an LLM to analyze code, identify the vulnerable function, and estimate buffer sizes for symbolic execution.

### Argument Types
When defining inputs for the target function, arguments are classified into three types:

| Type	| Description	| Required Property |
| ----- | ------------- | ----------------- |
| symbolic_pointer	| A pointer referencing a memory region to be filled with symbolic data.	| size (bytes) |
| symbolic_value	| A primitive value (integer, char) to be treated as symbolic input.	| size (bits) |
| concrete	| A fixed, constant value passed directly.	| value |

Note: If the target function takes no arguments, the argument list is empty.

## Local usage without Claude Desktop
Run the direct analysis script:

```bash
uv run python tests/mcp_client.py <path_to_source> <entry_point> <vulnerable_function> '<json_args>'
```

Parameters:

    <path_to_source>: Path to the source file.
    <vulnerable_function>: Function name containing the unsafe operation.
    '<json_args>': JSON array of argument definitions (see types above).


Examples:

```bash
uv run python tests/mcp_client.py tests/fixtures/stack_overflow/gets_local.c vulnerable_function

uv run python tests/mcp_client.py tests/fixtures/stack_overflow/strcpy_pointer.c copy_input '[{"type": "symbolic_pointer", "size": 64}]'
```

## Developer

### Setup
Install runtime and dev dependencies:

```bash
uv sync --group dev
```

Install local git hooks (once per clone):

```bash
uv run pre-commit install
uv run pre-commit install --hook-type pre-push
```

### Quality checks
Run all configured pre-commit hooks manually:

```bash
uv run pre-commit run --all-files
```

### Tests
Run full test suite:

```bash
uv run pytest tests/
```

### Troubleshooting
- Error: ModuleNotFoundError: No module named vuln_validator
   - Run `uv sync` in the repository root.

Get last audit-log:
```bash
Get-Content logs/audit_log.json -Tail 1 | ConvertFrom-Json
# Linux/Mac
tail -n 1 logs/audit_log.json | jq
```
Get all audit-logs:
```bash
Get-Content logs/audit_log.json | ForEach-Object { ConvertFrom-Json $_ }
# Linux/Mac
cat logs/audit_log.json | jq -s '.'
```
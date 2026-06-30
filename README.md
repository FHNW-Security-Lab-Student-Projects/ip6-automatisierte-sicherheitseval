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
For reliable exploit analysis, binaries **must** be compiled without protections using the flags below (see **Flag Overview** table).

**C**
```bash
gcc ./binary.c -o binary -O0 -fno-omit-frame-pointer -fno-stack-protector -z execstack -no-pie -g -fno-optimize-sibling-calls
```

**C++**
```bash
g++ ./binary.cpp -o ./binary -O0 -fno-omit-frame-pointer -fno-stack-protector -z execstack -fno-exceptions -fno-rtti -no-pie -g fno-optimize-sibling-calls
```

### Flag Overview
| Flag | Purpose |
| --- | --- |
| -O0 | Disables optimizations, keeps code structure identical to source. |
| -fno-omit-frame-pointer | Preserves RBP for reliable stack frame traversal and variable location. |
| -fno-stack-protector | Disables stack canaries to allow overflow simulation. |
| -z execstack | Marks stack as executable (required for shellcode execution). |
| -no-pie | Disables ASLR, ensures fixed memory addresses for the binary. |
| -g | Includes DWARF debug symbols for precise variable/struct identification. |
| -fno-exceptions | (C++) Removes exception handling overhead and complex control flow. |
| -fno-rtti | (C++) Removes runtime type information to simplify class analysis. |
| -fno-optimize-sibling-calls | Prevents tail-call optimization to preserve distinct stack frames. |


## Claude Desktop integration (Windows)
For Claude to bei able to read and analyze your source-files, MCP-Server musst be configured.

**Note:** Claude Desktop **Code** does **not** need the filesystem MCP server, only the `VulnValidator` MCP server.  
The filesystem server is only required for **Claude Desktop Chat**.

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
| pointer	| A pointer referencing a memory region to be filled with symbolic data.	| size (bytes) |
| variable	| A primitive value (integer, char) to be treated as symbolic input.	| size (bits) |
| concrete	| A fixed, constant value passed directly.	| value |

Note: If the target function takes no arguments, the argument list is empty.

## Local usage without Claude Desktop
Run the direct analysis script:

```bash
uv run python tests/mcp_client.py <path_to_source> <vulnerable_function> <vulnerability_type> '<json_args>' '<structs>'
```

Parameters:

    <path_to_source>: Path to the source file.
    <vulnerable_function>: Function name containing the unsafe operation.
    <vulnerability_type>: suspected type (stack_overflow, heap_overflow or auto)
    '<json_args>': JSON array of argument definitions (see types above).
    '<structs>': JSON array of structs (stored in stack or heap, or passed as arg but then with arg_index)


Examples:

```bash
uv run python tests/mcp_client.py tests/fixtures/stack_overflow/gets_local.c vulnerable_function stack_overflow

uv run python tests/mcp_client.py tests/fixtures/stack_overflow/strcpy_pointer.c copy_input stack_overflow '[{"type": "pointer", "size": 64}]'

uv run python tests/mcp_client.py tests/fixtures/heap_overflow/simple_overflow_before_canary create_user heap_overflow '[{"type": "pointer", "size": 64}]' '[{"type": "struct", "name": "u", "location": "stack","size": 20,"fields": [{"type": "variable", "offset": 0, "size": 16, "is_input": true},{"type": "variable", "offset": 16, "size": 4, "is_critical": true}]}]'

# struct passed in arg
uv run python tests/mcp_client.py tests/fixtures/stack_overflow/struct_in_pointer.c create_user auto '[{"type": "pointer", "size": 64},{"type": "pointer", "size": 916, "is_struct": true}]' '[{"type": "struct", "name": "u", "location": "arg", "arg_index":1,"size": 20,"fields": [{"size": 16, "is_input": true},{"size": 4, "is_critical": true}]}]'
```

## Configuration
The framework reads `config.toml` from the repository root.

- `max_steps`: Upper bound on simulation steps (limits exploration time).
- `step_size`: Steps per iteration (every iteration VulnValidator checks checks how many states are active/unconstrained/errored).
- `symbolic_stdin_bytes`: Size of symbolic stdin buffer (too small may miss bugs).
- `heap_start`: Start address for fake heap (change if it collides with mapped regions).
- `auto_stop_on_first_found`: In `auto` mode, stop after first positive result.
- `specific_stop_on_first_found`: For a specific type, stop when a vulnerability is found.
- `specific_continue_on_no_find`: For a specific type, continue when no vulnerability is found.

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
# ip6-automatisierte-sicherheitseval


Vulnerability validation framework for **C and C++** projects. It uses LLMs to detect potential vulnerabilities in source code and verifies them using symbolic execution (`angr`) on compiled Linux binaries. The framework eliminates false positives by providing mathematical proof of exploitability.

## Requirements
- **Python 3.12**
- **[uv](https://github.com/astral-sh/uv)** package manager
- **Node.js** (required for MCP-Filesystem-Server in **Claude Desktop Chat**, not required for **Claude Code**)
    - Windows: `scoop install nodejs-lts` or Installer from nodejs.org
    - Mac/Linux: `brew install node`
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

## Critical Prerequisite: Binary Compilation
The LLM analyzes your **source code** (`.c` / `.cpp`), but the framework executes and verifies the vulnerability on a **compiled binary**.
- The binary **must** be located in the **same directory** as the source file.
- The binary **must** have the **same name** as the source file (e.g., `exploit.c` → `exploit`).
- The binary **must** be compiled for **Linux (ELF format)**.

> **Windows Users:** You must compile your code inside **WSL2**. Native Windows `.exe` files are not supported.

## Binary compilation (Linux/Mac)

For reliable exploit analysis, binaries **must** be compiled without protections using the flags below (see **Flag Overview** table).

**C**
```bash
gcc ./binary.c -o binary -O0 -fno-omit-frame-pointer -fno-stack-protector -no-pie -g -fno-optimize-sibling-calls
```

**C++**
```bash
# clang++ for mac
g++ ./binary.cpp -o ./binary -O0 -fno-omit-frame-pointer -fno-stack-protector -fno-exceptions -fno-rtti -no-pie -g -fno-optimize-sibling-calls
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
To allow Claude to read and analyze your source files, MCP servers **must** be configured.

**Note:** **Claude Desktop Code** does **not** need the `filesystem` MCP server, only the `VulnValidator` MCP server.  
The `filesystem` MCP server is only required for **Claude Desktop Chat**.

1. Locate config file:
   - Windows: Press Win + R, enter: `%APPDATA%\Claude\claude_desktop_config.json` or go in Claude Desktop to `Settings` -> `Developer` -> `Edit Config`
   - Open `claude_desktop_config.json`

2. Configure MCP servers:
   - To add the MCP servers to Claude Desktop: Copy the `mcpServers` block from this repository under `config/claude_desktop_config.example` into your `claude_desktop_config.json`. 
   - Replace <project_path> with the absolute path to this repository.
   - Replace <code_files_path> with the path to your source code files you want Claude to analyze.

**Note**: You don't need to define exact path for code files but Claude Code will have access to all files in your provided path

3. Activate:
   - Restart Claude Desktop after saving the config.

4. Run analysis:
   
   **If you use Claude Code:**
   - Select the folder containing your source code and binaries.
   - Copy the content of `prompt.md` (from the repository root) and paste it into the chat.
   - Start your analysis request.

   **If you use Claude Chat:**
   - Copy the content of `prompt.md` (from the repository root) and paste it into the chat (it will appear as attachement).
   - Enter the path to your source code files you want to analyze also into the chat.
   - Finally add the following instruction also into the chat:  
     `"Use the MCP-Server filesystem to access the files in the provided path."`
   - Start your analysis request.

## Local usage without Claude Desktop (Linux/Mac/WSL)
You can run the analysis directly via the test client script.

Command Syntax
```bash
uv run python tests/mcp_client.py <path_to_source> <vulnerable_function> <vulnerability_type> '<json_args>' '<structs>'
```

Parameters:
| Parameter	| Description	|
| ----- | ------------- |
| <path_to_source>	| Path to the source file (.c or .cpp). The binary is auto-detected in the same folder. |
| <vulnerable_function> | Name of the function containing the unsafe operation. |
| <vulnerability_type> | Suspected type: stack_overflow, heap_overflow, use_after_free, format_string, or auto (if unsure). |
| '<json_args>' | JSON array of argument definitions (see types above). Use single quotes to escape. |
| '<structs_>' | JSON array of struct definitions (location: stack, heap, or arg). |


### Examples:

1. Simple Stack Overflow (no args)
```bash
uv run python tests/mcp_client.py tests/fixtures/stack_overflow/gets_local.c vulnerable_function stack_overflow
```
2. Stack Overflow with Pointer Argument
```bash
uv run python tests/mcp_client.py tests/fixtures/stack_overflow/strcpy_pointer.c copy_input stack_overflow '[{"type": "pointer", "size": 64}]'
```
3. Heap Overflow with Struct
```bash
uv run python tests/mcp_client.py tests/fixtures/heap_overflow/struct_in_heap.c create_user heap_overflow '[{"type": "pointer", "size": 64}]' '[{"type": "struct", "name": "u", "location": "heap","size": 20,"fields": [{"type": "variable", "size": 16, "is_input": true},{"type": "variable", "size": 4, "is_critical": true}]}]'
```
4. Struct Passed as Argument
```bash
uv run python tests/mcp_client.py tests/fixtures/stack_overflow/struct_in_pointer.c create_user auto '[{"type": "pointer", "size": 64},{"type": "pointer", "size": 916, "is_struct": true}]' '[{"type": "struct", "name": "u", "location": "arg", "arg_index":1,"size": 20,"fields": [{"size": 16, "is_input": true},{"size": 4, "is_critical": true}]}]'
```

## Supported Solvers

The framework currently supports verification for the following vulnerability classes:

- stack_overflow: Buffer overflows on the stack.
- heap_overflow: Buffer overflows on the heap.
- use_after_free: Accessing freed memory regions.
- format_string: Vulnerabilities via format specifiers (e.g., %n, %s).
- auto: Automatically attempts all available solvers sequentially.


## Configuration
The framework reads `config.toml` from the repository root. There you can adjust simulation limits and behavior.

| Parameter	| Description	|
| ----- | ------------- |
| max_steps	| Upper bound on simulation steps to limit exploration time |
| step_size | Number of steps executed per iteration before checking state status. |
| loop_bound | Loop bound for LocalLoopSeer to prevent infinite loops during symbolic execution |
| symbolic_stdin_bytes | Size of the symbolic stdin buffer (if too small may miss bugs, but smaller is faster). |
| heap_start | Start address for the fake heap (adjust if it collides with mapped regions). |
| arg_start | Start address for symbolic argument data (adjust if it collides with mapped regions). |
| auto_stop_on_first_found | In auto mode: Stop analysis immediately after the first positive result. |
| specific_stop_on_first_found | In specific mode: Stop when the requested vulnerability type is found. |
| specific_continue_on_no_find | 	In specific mode: Continue checking other types if the requested one is not found. |
| continue_on_error | Ignore internal solver errors and continue analysis with next solver instead of aborting. |
| log_level | Log granularity (DEBUG, INFO, WARNING, ERROR, CRITICAL). |

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
**Error**: ModuleNotFoundError: No module named vuln_validator
   - Run `uv sync` in the repository root.

**Inspecting Audit Logs**: The framework logs every analysis run to logs/audit_log.json (one JSON object per line).

Windows (PowerShell):
```bash
# Get last entry
Get-Content logs/audit_log.json -Tail 1 | ConvertFrom-Json

# Get all entries formatted
Get-Content logs/audit_log.json | ForEach-Object { ConvertFrom-Json $_ }
```

Linux / macOS:
```bash
# Get last entry
tail -n 1 logs/audit_log.json | jq

# Get all entries formatted
cat logs/audit_log.json | jq -s '.'
```
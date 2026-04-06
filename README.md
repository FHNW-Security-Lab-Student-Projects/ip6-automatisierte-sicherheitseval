# ip6-automatisierte-sicherheitseval

Vulnerability validation framework with an MCP server for AI assistants (like Claude Desktop).

## Requirements
- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- Node.js (needed for MCP-Filesystem-Server in Claude Desktop)
    Windows: `scoop install nodejs-lts` or Installer from nodejs.org
    Mac/Linux: `brew install node`
- Claude Desktop (optional)


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

## Claude Desktop integration (Windows)
For Claude to bei able to read and analyze your source-files, MCP-Server musst be configured.

1. Open config file:
   - Windows: Press Win + R, enter: %APPDATA%\Claude\claude_desktop_config.json
   - Mac: ~/Library/Application Support/Claude/claude_desktop_config.json # TODO: Verify

2. Copy the `mcpServers` block from `config/claude_desktop_config.example` and enter in `claude_desktop_config`. Replace both the project path and the path to your code files.<br>
**Note**: You don't need to define exact path for code files but Claude Code will have access to all files in your provided path

3. Restart Claude Desktop after saving the config.

4. In Claude chat:
   - Click +, then Connectors.
   - Choose Add from VulnValidator.
   - Select Find vulnerability workflow.
   - Enter the target path and send.

## Local usage without Claude Desktop
Run the direct analysis script:

```bash
uv run python scripts/run_direct_analysis.py <path_to_binary> <target_function>
```

Example:

```bash
uv run python scripts/run_direct_analysis.py tests/fixtures/5_my_vuln vulnerable_function
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
uv run pytest
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
# ip6-automatisierte-sicherheitseval

Vulnerability validation framework with an MCP server for AI assistants (like Claude Desktop).

## Requirements
- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- Claude Desktop (optional, if you want MCP integration)

## Quick start
1. Clone the repository.
2. Install dependencies and the local package:

   uv sync

3. Verify package import (recommended, quick check):

   uv run python -c "import vuln_validator; print('ok')"

## Claude Desktop integration (Windows)
Open the Claude Desktop config file:

code $env:AppData\Claude\claude_desktop_config.json

Copy the server block from `config/claude_desktop_config.example` and adjust only the project path.
You can copy only the mcpServers section. The preferences section is optional and not required for VulnValidator.

Restart Claude Desktop after saving the config.

In Claude chat:
1. Click +, then Connectors.
2. Choose Add from VulnValidator.
3. Select Find vulnerability workflow.
4. Enter the target path and send.

## Local usage without Claude Desktop
Run the direct analysis script:

uv run python scripts/run_direct_analysis.py <path_to_binary>

Example:

uv run python scripts/run_direct_analysis.py tests/fixtures/2_buffer_overflow

## Developer

### Setup
Install runtime and dev dependencies:

```bash
uv sync --extra dev
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
   - Run uv sync in the repository root.

# ip6-automatisierte-sicherheitseval (vulnerability validation framework)

This project includes a Model Context Protocol (MCP) server to allow AI assistants (like Claude Desktop) to safely interact with the vulnerability validation framework.

### Setup for Claude Desktop
1. Ensure `uv` and Python are installed on your host.
2. Clone this repository
3. Initialize the environment:
```bash
uv sync
```
4. Open claude_desktop_config.json and add the MCP-server:

```bash
# For windows
code $env:AppData\Claude\claude_desktop_config.json
```
```bash
# enter this in claude_desktop_config.json
{
  "mcpServers": {
    "VulnValidator": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\Users\\marko\\PycharmProjects\\ip6-automatisierte-sicherheitseval",
        "run",
        "src/vuln_validator/mcp_server.py"
      ]
    }
  }
}
```

5. Restart Claude Desktop. The new tools will appear in the "Connectors" menu.
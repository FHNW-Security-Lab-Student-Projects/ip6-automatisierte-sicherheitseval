## [0.3.0] - 2026-04-23

### 🚀 Features

- Show input for overflow in audit log and to the user
- Make steps dynamic
- Differ between pointer and value
- Add new prompt
- Add canaries for pointers from arg

### 🐛 Bug Fixes

- Offset for args
- Update prompt

### 🚜 Refactor

- Simplify and remove option for analyzing whole binary

### 📚 Documentation

- Update Readme
- Fix Readme

### ⚡ Performance

- Optimize prompt with clearer instuctions

### 🧪 Testing

- Add test-cases for safe binaries
- Add more binaries with stackbufferoverflow
- Add stackbufferoverflow binaries to test
- Add binaries with nested function

### ⚙️ Miscellaneous Tasks

- Rename testbinaries
- Add more binaries
- Measure time of analysis
- Remove unnecessary tests
- Unified result (symbolic rip and canary)
- Remove unnecessary logs and code
- *(merge)* Merge pull request #4 from FHNW-Security-Lab-Student-Projects/dev
## [0.2.0] - 2026-04-10

### 🚀 Features

- Add audit-logs
- Analyze at target_function
- Edit structure of result
- Extend return json
- Claude access to read code files
- Add mcp-client
- Call target_function with or without arguments

### 🐛 Bug Fixes

- Make sure logs folder exists

### 🚜 Refactor

- Build result method

### 📚 Documentation

- Update Readme (audit-log commands)
- Update Readme (nodejs)
- Update Readme for mcp-client

### 🧪 Testing

- Add test_audit_logger
- Add tests for StackOverflowSolver
- Tests for understanding angr call function
- Add tests for target_function
- Add and edit tests for extended structure of result
- Edit tests for extended return json
- Add more tests for exception handling
- Add tests for solver with function arguments

### ⚙️ Miscellaneous Tasks

- Remove unused files and cleanup folder structure
- Tests for understanding args
- Cleanup test folder.
- *(merge)* Merge pull request #2 from FHNW-Security-Lab-Student-Projects/dev
- Update changelog
## [0.1.0] - 2026-03-30

### 🚀 Features

- Add uv files
- Test mcp server on claude
- First working call from claude with binary
- Use framwork without LLM
- Add AngrAnalyzer with execution logic and add StackOverflowSolver
- Add logging
- Stackoverflowsolver detects symbolic rip

### 🐛 Bug Fixes

- Set target version for black
- Command to sync dev dependencies

### 🚜 Refactor

- Structure project and set config for mcp_server.py

### 📚 Documentation

- Test angr framework
- Start Readme
- Update Readme
- Update Readme

### 🎨 Styling

- Run black and ruff on code
- Sync for ci

### 🧪 Testing

- Add test scripts
- Add test_mcp_server
- Adjust test_mcp_server
- Add test_angr_engine.py
- Simple angr test for understanding
- More angr tests for understanding
- Last few angr tests for understanding
- Update tests

### ⚙️ Miscellaneous Tasks

- Update dependencies
- Update dependencies
- Remove weather.py example
- Add pre-commit-config and github actions
- Update dependecies for code style
- Prettify Readme
- Add more example code
- Initialize repository with MCP server, solver baseline, and CI pipeline
- Update changelog

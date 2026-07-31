## [0.7.0] - 2026-07-31

### 🚀 Features

- Add first working draft of UAF-Solver
- Extend prompt for LLM to to error handling, suggest compile command and limit LLM output
- Add Double-Free warning
- Make loop_bound configurable
- First draft solver timeout
- Make timeout global
- Make timeout configurable
- Save logs in file (for windows usage)
- First draft of async polling
- Add more details to analysis Result (file and time)
- First draft of evaluation prompt
- Use queue instead of semaphore
- Update audit logging for async
- Add script to compare evaluation results

### 🐛 Bug Fixes

- Timeout limit (only for server side)
- Remove double line in config
- Optimize prompt (buffer size) and extend error message in AngrAnalyzer
- Save jobs as file to prevent unknown states
- Fix vulnerability in safe code (testset)

### 🚜 Refactor

- UAF-Solver inherits from HeapSolver

### 📚 Documentation

- Add class diagram
- Complete Readme
- Specify local usage
- Clarify instructions and precise version of python
- Add evaluation results

### 🧪 Testing

- Adjust angr_analyzer test to accept stop_event arg
- Adjust tests to run async

### ⚙️ Miscellaneous Tasks

- Add uaf binaries
- Add ctf source code and binaries
- Remove unused file
- *(merge)* Updates from dev
- Extend Prompt
- Prompt optimization and waiting time for response
- Adjust evaluation prompt for clearer results
- Add testset for evaluation
- Update evaluation prompt (more useful result to compare)
- Add dependencies for evaluation
- Update evluation script
- Update safe binary
- *(merge)* Merge pull request #8 from FHNW-Security-Lab-Student-Projects/dev
## [0.6.0] - 2026-07-14

### 🚀 Features

- Add log_level to config
- Define vuln_type in cli instead of hardcoded for mcp_client
- Make address for stored pointer args configurable
- Accept .out binaries
- Provide stdin as angr.SimFile for scanf compatibility
- Use entry_state to initialize global variabels
- First working draft of FormatStringSolver
- FormatStringHooks also for fprintf, sprintf, etc.
- Add config variable for stopping ananlysis if solver throws error
- Add scanf-hook
- Add warning when simulation not completed (active states remaining)
- Add LocalLoopSeer to prevent path explosion when loops

### 🐛 Bug Fixes

- Handle if stack_solver but heap struct defined (no hooks)
- Also show stdin if symbolic_args exist (don't repot all-zeros
- Check if found_vuln is true at correct places
- Get solver time also when it fails
- Write variable in register
- Not associated variable binary_candidate removed
- Heap addr completely dynamic
- Update config in tests
- Call_state on found state from simgr.explore but with base_state
- Initialize var msg

### 💼 Other

- Remove duplicate _set_config in tests

### 🚜 Refactor

- Check if struct addr already found before looping trough states
- All heap-hooks consistent
- Remove unused fallback logic for hooks since binaries are not stripped
- Show scanf output as little endian
- Return config in one methode

### 📚 Documentation

- Add diagrams
- Add flowchart
- Adjust mcp-client command in Readme
- Add diagrams for documentation
- Add examples for request and response
- Update Readme (compilation only Linux)
- Add diagram for FormatStringHooks

### ⚡ Performance

- Use only relevant tests

### 🧪 Testing

- Make test independent of config settings
- Extend config_loader tests
- Add tests for FormatStringSolver
- Update heap_overflow tests
- Add scnaf to tests
- All tests are now independent of config.toml

### ⚙️ Miscellaneous Tasks

- Edit default log_level
- Add comment in dwarf_analyzer
- Update prompt (clarify files might be in cwd)
- Remove duplicate code
- Add missing docstrings, add more comments and cleanup code
- Add example binaries with global variabels
- Put log at correct position
- Add binaries for format_string
- Remove hardcoded vuln_type in mcp-client
- Edit docstring in HeapoverflowSolver
- Update comments and docstring
- Add all binaries for format_string
- Add docstrings to config_loader.py
- Add scanf test binary
- *(merge)* Merge pull request #7 from FHNW-Security-Lab-Student-Projects/dev
- Update changelog
## [0.5.0] - 2026-06-03

### 🚀 Features

- Add BaseFakeHeapAlloc and MyFakeCalloc
- Add MyFakeAlignedAlloc
- Set libc string limits from DWARF locals
- Make c++ compatible
- Hook for c++ new/new[]
- Start with config file
- Add symbolic_stdin and heap_start to config
- Add analyzer config
- Start with intra-struct analysis
- Update prompt so LLM states structs
- Working draft of struct pointer in args
- First draft of struct in heap
- Allow multiple structs stored in heap

### 🐛 Bug Fixes

- Explicit signature in heap_hooks so angr passes size correctly
- Advance past prologue for correct rsp
- Don't limit vulnerability type in mcp server
- Typo
- Add offset to get correct struct address

### 🚜 Refactor

- Remove duplicate code from MyFakeAlignedAlloc
- Slim down BasememorySolver
- Add DwarfAnalyzer
- Cfa not hardcoded but relative to rsp
- Rename arg types and describe arg_index in prompt

### 📚 Documentation

- Describe compilation
- Add Configuration to Readme
- Update Readme (binary compilation and local usage commands)

### ⚡ Performance

- Calculate offset without LLM hint

### 🧪 Testing

- Add test case with calloc
- Add test for aligned_alloc
- Add test for c++ heap overflow
- Add tests for config_loader
- Add struct test cases
- Rename arg types and add struct pointer as arg
- Add cases for struct stored in heap

### ⚙️ Miscellaneous Tasks

- Add example code with calloc
- Instruct llm to return line number where vulnerability is
- Add pyelftools
- Add example binaries for aligned_alloc
- Add c++ example code
- Consistent naming of AngrAnalyzer
- Update test to work with structs
- Add example binary with struct in stack
- Remove irrelevant claude config
- Remove unused dwarf files
- Add safe binary with struct
- Add safe binary with struct
- Add logsfor function address resolution
- Remove unused prompt (obsolete because of prompt injection prevention)
- Remove prompt check
- Add struct-pointer in arg binaries
- Add binaries with struct stored in heap
- Remove unused logs and variabels
- Add binaries with multiple structs stored in heap
- *(merge)* Merge pull request #6 from FHNW-Security-Lab-Student-Projects/dev
- Update changelog
## [0.4.0] - 2026-05-13

### 🚀 Features

- First working poc with heap overflow
- Underflow canary for heap overflow
- Refactor symbolic arg placement (new for heapsolver) and keep stack canaries separate

### 🐛 Bug Fixes

- Write canary as little endian
- Don't analyze errored state
- Check if malloc exists
- Raise libc string limits for symbolic pointers

### 🚜 Refactor

- Add BaseMemorySolver
- Put hooks in separate file
- Move canary collection to solve
- Use state.globals also for stack canaries
- Use only one canary_list
- Move general tesets to test_base_memory_solver
- Remove duplicate code

### 📚 Documentation

- Add first draft of Sequenzdiagramm

### ⚡ Performance

- Reduce solver requests and unnecessary loop

### 🧪 Testing

- Tests for understanding angr heap overflow
- Understanding heap overflow with symbolic input
- Add tests for HeapOverflowSolver

### ⚙️ Miscellaneous Tasks

- Add test binaries for heap overflow
- *(merge)* Merge pull request #5 from FHNW-Security-Lab-Student-Projects/dev
- Update changelog
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
- Update changelog
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

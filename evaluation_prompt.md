---
**EVALUATION PROTOCOL (APPEND TO ABOVE INSTRUCTIONS):**

1.  **Action:** Create (or append to) a file named `evaluation_report.csv` in the root directory.
2.  **Header:** If the file is new, write the CSV headers first (you see them in step 3)
3.  **Row Generation (IMMEDIATE WRITE):**
    -   **Trigger:** As soon as you receive a `status: "done"` or `status: "error"` from `get_validation_result` for a specific function, you must stop all other activities.
    -   **Action:** Generate the report (Step 4) and **IMMEDIATELY** append the corresponding CSV row to `evaluation_report.csv`.
    -   **Constraint:** Do NOT proceed to poll the next job_id or analyze the next file until the CSV row for the current result is successfully written.
    -   **Columns:**
        -   `job_id`
        -   `file_path`, `file_name`: From source.
        -   `hypothesis`: Your initial finding from Step 1 (e.g., "Suspected stack_overflow in main" or "none").
        -   `tool_call_json`: All paramters you passed when calling `start_validation`. Write as JSON-String.
        -   `vulnerability_type`: Type from result or `none`.
        -   `target_function`: Function name.
        -   `is_vulnerable`: `true`/`false` (from result).
        -   `evidence`: Concise technical evidence (escape commas).
        -   `input_hex`: Hex string from tool or `n/a`.
        -   `code_line`: Line number or `n/a`.
        -   `time`: The value of `analysis_time_seconds` from the result object.
        -   `validation_status` (final verdict):
            -   If `is_vulnerable` is **None** (Case D): Write `solver_error`.
            -   Hypothesis suspected + `is_vulnerable=true` → `confirmed`
            -   Hypothesis suspected + `is_vulnerable=false` → `Vulnerability not found by solver! Might be false positive`
            -   Hypothesis suspected + (timeout/error) → `solver timeout`
            -   No hypothesis → `safe`
        -   `remark`: Notes (e.g., "Binary missing", "Timeout").
4.  **Continuity:** Do not output CSV content in chat. Only confirm: "Row appended for [filename].". Then proceed to the next job_id in the ordered list.
5.  **Error Handling:** If a tool call fails, record `is_vulnerable=false`, `remark`="Tool Error", write to CSV, then continue.

Proceed with the analysis using Steps 1-4 and this Protocol.
---
**EVALUATION PROTOCOL (APPEND TO ABOVE INSTRUCTIONS):**

1.  **Action:** Create (or append to) a file named `evaluation_report.csv` in the root directory.
2.  **Header:** If new, write: `file_path,file_name,hypothesis,is_vulnerable,vulnerability_type,target_function,evidence,input_hex,code_line,time,validation_status,remark`
3.  **Row Generation (IMMEDIATE WRITE):**
    -   **Trigger:** As soon as you receive a `status: "done"` or `status: "error"` from `get_validation_result` for a specific function, you must stop all other activities.
    -   **Action:** Generate the report (Step 4) and **IMMEDIATELY** append the corresponding CSV row to `evaluation_report.csv`.
    -   **Constraint:** Do NOT proceed to poll the next job_id or analyze the next file until the CSV row for the current result is successfully written.
    -   **Columns:**
        -   `file_path`, `file_name`: From source.
        -   `hypothesis`: Your initial finding from Step 1 (e.g., "Suspected stack_overflow in main" or "none").
        -   `is_vulnerable`: `true`/`false` (from result).
        -   `vulnerability_type`: Type from result or `none`.
        -   `target_function`: Function name.
        -   `evidence`: Concise technical evidence (escape commas).
        -   `input_hex`: Hex string from tool or `n/a`.
        -   `code_line`: Line number or `n/a`.
        -   `time`: The value of `analysis_time_seconds` from the result object.
        -   `tool_call`: All paramters you passed when calling `start_validation`.
        -   `validation_status`:
            -   If `is_vulnerable` is **None** (Case D): Write `solver_error`.
            -   Hypothesis suspected + `is_vulnerable=true` → `confirmed`
            -   Hypothesis suspected + `is_vulnerable=false` → `false_positive_filtered`
            -   Hypothesis suspected + (timeout/error) → `solver_limit`
            -   No hypothesis → `safe`
        -   `remark`: Notes (e.g., "Binary missing", "Timeout").
4.  **Continuity:** Do not output CSV content in chat. Only confirm: "Row appended for [filename].". Then proceed to the next job_id in the ordered list.
5.  **Error Handling:** If a tool call fails, record `is_vulnerable=false`, `remark`="Tool Error", write to CSV, then continue.

Proceed with the analysis using Steps 1-4 and this Protocol.
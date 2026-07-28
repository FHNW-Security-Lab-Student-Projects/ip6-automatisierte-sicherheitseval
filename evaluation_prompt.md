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
        -   `hypothesis_vuln_type`: Your initial finding from Step 1 but only the vulnerability type (e.g., "stack_overflow", "heap_oveflow").
        -   `hypothesis_target_function`: Where you suspect the vulnerability (e.g., "main" or "none" if you think it's safe)
        -   `hypothesis_explanation`: Explain short why this is your hypothesis
        -   `tool_call_json`: All paramters you passed when calling `start_validation`. Write as JSON-String.
        -   `vulnerability_type`: The vulnerability type the framework confirmed from result or `none` if the Framework didn't find a vulnerability.
        -   `target_function`: Function name the framework analyzed (which you can find in the result).
        -   `is_vulnerable`: `true`/`false`/`none` (from result).
        -   `evidence`: Concise technical evidence (escape commas).
        -   `input_hex`: Hex string from tool or `n/a`.
        -   `code_line`: Line number or `n/a`.
        -   `time`: The value of `analysis_time_seconds` from the result object.
        -   `validation_status`:
            -   Check whole result if the validation succeded (also read the message). If there was timeout you write `timeout`, if there was an error you write `error`. If it found a vulnerability you write `vuln_found` and if it din't find anything you write `no_vuln_found`.
        -   `remark`: Notes (e.g., "Binary missing" or whatever there ist in the message).
4.  **Continuity:** Do not output CSV content in chat. Only confirm: "Row appended for [filename].". Then proceed to the next job_id in the ordered list.
5.  **Error Handling:** If a tool call fails, record `is_vulnerable=false`, `remark`="Tool Error", write to CSV, then continue.

Proceed with the analysis using Steps 1-4 and this Protocol.
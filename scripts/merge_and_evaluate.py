import pandas as pd
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
print(f"Script directory: {SCRIPT_DIR}")
PROJECT_ROOT = SCRIPT_DIR.parent

SUFFIX = "2907_1_opus_48_high"

# CONFIGURATION
GT_FILE = PROJECT_ROOT / "docs/ground_truth.csv"
EVAL_FILE = PROJECT_ROOT / f"docs/evaluation_report_{SUFFIX}.csv"
OUTPUT_FILE = PROJECT_ROOT / f"docs/analysis_ready_{SUFFIX}.csv"


def parse_args(json_str):
    """Helper to extract args from JSON string for comparison"""
    if pd.isna(json_str) or json_str == "":
        return []
    try:
        data = json.loads(json_str)
        return data.get("function_args", [])
    except (json.JSONDecodeError, TypeError):
        print(f"Warning: Failed to parse JSON string: {json_str}")
        return []


def main():
    print("Loading data...")
    try:
        df_gt = pd.read_csv(GT_FILE)
        df_eval = pd.read_csv(EVAL_FILE)
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        return

    print(f"Ground Truth: {len(df_gt)} files | Evaluation Report: {len(df_eval)} files")

    # MERGE: Left Join (Keep ALL Ground Truth files, attach Eval data if available)
    merged = pd.merge(
        df_gt, df_eval, on="file_name", how="left", suffixes=("_gt", "_eval")
    )

    print("Creating analysis table...")

    analysis_data = []

    for idx, row in merged.iterrows():
        # 1. Ground Truth Values
        gt_vuln_type = str(row.get("Vulnerability", ""))
        gt_is_vuln = row.get("is_vulnerable_gt", "false")

        gt_target = str(row.get("exp_target_function", ""))

        # 2. LLM Hypothesis and Solver Result
        # Check if solver was called
        solver_called = pd.notna(row.get("validation_status"))

        llm_hypo_vuln = "none"
        llm_hypo_target = "none"
        fw_status = "no_solver_call"
        fw_is_vuln = False
        fw_vuln_type = "none"
        eval_args_count = 0

        if solver_called:
            llm_hypo_vuln = str(row.get("hypothesis_vuln_type", "none"))
            llm_hypo_target = str(row.get("hypothesis_target_function", "none"))
            fw_status = str(row.get("validation_status", "error"))
            fw_is_vuln = fw_status == "vuln_found"
            fw_vuln_type = str(row.get("vulnerability_type", "none"))

            tool_json = row.get("tool_call_json", "{}")
            eval_args = parse_args(tool_json)
            eval_args_count = len(eval_args)
        else:
            # If solver was NOT called, the LLM implicitly classified it as "safe"
            llm_hypo_vuln = "none"
            llm_hypo_target = "none"

        # 3. Categorization Logic
        category = "UNKNOWN"

        if gt_is_vuln:
            # Ground Truth says: VULNERABLE
            if solver_called:
                if fw_is_vuln:
                    category = "TRUE_POSITIVE"
                elif fw_status == "timeout":
                    category = "FALSE_NEGATIVE_TIMEOUT"
                else:  # no_vuln_found or error
                    category = "FALSE_NEGATIVE_SOLVER"
            else:
                # Solver NOT called -> LLM missed the vulnerability completely
                category = "FALSE_NEGATIVE_LLM"

        else:
            # Ground Truth says: SAFE
            if solver_called:
                if fw_is_vuln:
                    category = "FALSE_POSITIVE_SOLVER"  # LLM thought vuln, Solver agreed (wrongly)
                else:
                    category = "TRUE_NEGATIVE_SOLVER_FILTER"  # LLM thought vuln, Solver corrected it
            else:
                # Solver NOT called -> LLM correctly identified it as safe
                category = "TRUE_NEGATIVE_LLM"

        # Did the LLM hypothesis match the Ground Truth type? (Only if LLM suspected something)
        llm_hypo_correct = False
        if not gt_is_vuln and not solver_called:
            llm_hypo_correct = True  # Correctly ignored
        elif gt_is_vuln and solver_called:
            # Check if types match
            llm_hypo_correct = llm_hypo_vuln == gt_vuln_type
        elif not gt_is_vuln and solver_called:
            # LLM suspected vuln, but it was safe -> Hypothesis technically wrong on existence
            llm_hypo_correct = False
        else:
            # gt_is_vuln but no solver call -> LLM missed it
            llm_hypo_correct = False

        analysis_data.append(
            {
                "file_name": row["file_name"],
                "GT_Is_Vulnerable": gt_is_vuln,
                "GT_Vuln_Type": gt_vuln_type,
                "GT_Target_Func": gt_target,
                "LLM_Hypo_Vuln": llm_hypo_vuln,
                "LLM_Hypo_Target": llm_hypo_target,
                "LLM_Hypo_Correct": llm_hypo_correct,
                "Solver_Called": solver_called,
                "FW_Status": fw_status,
                "FW_Is_Vulnerable": fw_is_vuln,
                "FW_Vuln_Type": fw_vuln_type,
                "Eval_Args_Count": eval_args_count,
                "Result_Category": category,
            }
        )

    df_analysis = pd.DataFrame(analysis_data)

    # Save detailed results
    df_analysis.to_csv(OUTPUT_FILE, index=False)
    print(f"Analysis table saved to: {OUTPUT_FILE}")

    print("\n--- EVALUATION RESULTS ---")

    tp = len(df_analysis[df_analysis["Result_Category"] == "TRUE_POSITIVE"])
    fp_solver = len(
        df_analysis[df_analysis["Result_Category"] == "FALSE_POSITIVE_SOLVER"]
    )

    # True Negatives (Two types: LLM ignored safe file, or Solver corrected LLM)
    tn_llm = len(df_analysis[df_analysis["Result_Category"] == "TRUE_NEGATIVE_LLM"])
    tn_solver = len(
        df_analysis[df_analysis["Result_Category"] == "TRUE_NEGATIVE_SOLVER_FILTER"]
    )
    total_tn = tn_llm + tn_solver

    # False Negatives (Two types: LLM missed vuln, or Solver missed vuln)
    fn_llm = len(df_analysis[df_analysis["Result_Category"] == "FALSE_NEGATIVE_LLM"])
    fn_solver = len(
        df_analysis[df_analysis["Result_Category"] == "FALSE_NEGATIVE_SOLVER"]
    )
    fn_timeout = len(
        df_analysis[df_analysis["Result_Category"] == "FALSE_NEGATIVE_TIMEOUT"]
    )
    total_fn = fn_llm + fn_solver + fn_timeout

    # False Positives (Only possible if Solver was called and agreed with wrong LLM)
    total_fp = fp_solver

    print(f"True Positives (TP):              {tp}")
    print(
        f"False Positives (FP):             {total_fp} (Solver failed to filter LLM error)"
    )
    print(
        f"True Negatives (TN):              {total_tn} ({tn_llm} ignored by LLM, {tn_solver} filtered by Solver)"
    )
    print(
        f"False Negatives (FN):             {total_fn} ({fn_llm} missed by LLM, {fn_solver} missed by Solver, {fn_timeout} timeouts)"
    )

    total_actual_vulns = tp + total_fn

    recall = tp / total_actual_vulns if total_actual_vulns > 0 else 0
    precision = tp / (tp + total_fp) if (tp + total_fp) > 0 else 0

    # Specific metric: FP Reduction Rate
    # How many potential FPs (cases where LLM said vuln but GT was safe) did the solver catch?
    total_llm_false_alarms = fp_solver + tn_solver
    fp_reduction_rate = (
        tn_solver / total_llm_false_alarms if total_llm_false_alarms > 0 else 0
    )

    print(f"\nRecall (Detection Rate):          {recall:.2%}")
    print(f"Precision (Accuracy of Alarm):    {precision:.2%}")
    print(
        f"FP Reduction Rate (Solver Value): {fp_reduction_rate:.2%} (Filtered {tn_solver} of {total_llm_false_alarms} LLM false alarms)"
    )


if __name__ == "__main__":
    main()

import logging
from itertools import chain
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def _format_input_bytes(
    data: bytes, max_preview: int = 1024, as_value: bool = False
) -> str:
    if not data:
        return ""

    if all(b == 0 for b in data):
        return f"<all-zero len={len(data)}>"

    if as_value:
        return f"{int.from_bytes(data, byteorder='little'):0{len(data) * 2}x}"

    preview = data[:max_preview].hex()
    if len(data) > max_preview:
        return f"{preview}... <len={len(data)}>"
    return preview


def _get_cause(state, bv_args: List[Any], symbolic_stdin: Any) -> Dict[str, Any]:
    details = {
        "input_hex": {},
        "stdin_used": False,
    }

    for idx, item in enumerate(bv_args):
        name, bv_arg = item if isinstance(item, tuple) else (f"arg_{idx}", item)
        try:
            val = state.solver.eval(bv_arg, cast_to=bytes)
            details["input_hex"][name] = _format_input_bytes(val)
        except Exception as e:
            logger.warning("Failed to extract arg %d from %s state: %s", idx, state, e)
            details["input_hex"][name] = "Extraction failed"

    try:
        poc = state.solver.eval(symbolic_stdin, cast_to=bytes)
        details["stdin_used"] = any(b != 0 for b in poc)
        details["input_hex"]["stdin"] = _format_input_bytes(poc)
    except Exception as e:
        logger.warning("Failed to extract stdin from %s state: %s", state, e)
        details["input_hex"]["stdin"] = "Extraction failed"

    if state.globals.get("scanf_inputs"):
        details["input_hex"]["scanf_inputs"] = {}
        for scanf_input in state.globals["scanf_inputs"]:
            try:
                val = state.solver.eval(scanf_input["symbol"], cast_to=bytes)
                var_name = scanf_input["var_name"]
                details["input_hex"]["scanf_inputs"][var_name] = _format_input_bytes(
                    val, as_value=True
                )
            except Exception as e:
                logger.warning(
                    "Failed to extract scanf input at 0x%x from %s state: %s",
                    scanf_input["addr"],
                    state,
                    e,
                )
                details["input_hex"]["scanf_inputs"] = "Extraction failed"

    return details


def evaluate_results(
    simgr,
    canaries,
    bv_args,
    symbolic_stdin,
    target_function: str,
    structs: List[Dict[str, Any]],
    struct_addresses: List[int],
    message: str,
    vulnerability_type: str,
    build_result,
):
    """
    Evaluates the final states in the simulation manager to determine if a vulnerability was found.
    Checks for:
    1. Symbolic RIP in unconstrained states (indicates control flow hijack)
    2. Canary integrity (indicates overflow)
    3. Intra-struct corruption (if struct definitions are provided)
    4. Format String vulnerability (via state.globals flags set by FormatStringHook)
    """
    found_vuln = False
    evidence_list = []
    canary_hit = False

    # Check 1: Symbolic RIP (Control Flow Hijack)
    for state in simgr.unconstrained:
        if state.solver.symbolic(state.regs.rip):
            vuln_data = _get_cause(state, bv_args, symbolic_stdin)
            vuln_data["state_type"] = "unconstrained"
            vuln_data["description"] = "Unconstrained state with symbolic RIP detected."
            evidence_list.append(vuln_data)
            found_vuln = True

    # Check 2: Canaries (Data Corruption)
    for state in chain(simgr.active, simgr.deadended, simgr.unconstrained):
        if found_vuln:
            break
        for c in canaries:
            try:
                current_value = state.memory.load(
                    c["addr"],
                    c["padding_size"],
                    endness=state.project.arch.memory_endness,
                )
                is_hit = False
                reason = ""

                if state.solver.symbolic(current_value):
                    is_hit = True
                    reason = "symbolic"
                else:
                    concrete_value = state.solver.eval(current_value)
                    if concrete_value != c["expected"]:
                        is_hit = True
                        reason = f"modified to {hex(concrete_value)}"

                if is_hit:
                    canary_hit = True
                    vuln_data = _get_cause(state, bv_args, symbolic_stdin)
                    vuln_data["state_type"] = "canary_hit"
                    vuln_data["description"] = (
                        f"Canary at 0x{c['addr']:x} {reason}. Indicates overflow."
                    )
                    evidence_list.append(vuln_data)
                    break
            except Exception as e:
                logger.warning(
                    "Failed to check canary at address 0x%x: %s", c["addr"], e
                )
                continue
        if canary_hit:
            found_vuln = True
            break

    # Check 3: Intra-struct Corruption
    for state in chain(simgr.active, simgr.deadended):
        if found_vuln:
            break
        if len(struct_addresses) != len(structs):
            logger.warning(
                "Mismatch between resolved struct addresses and local struct definitions. Skipping intra-struct corruption check."
            )
            break
        for struct in structs:
            name = struct.get("name")
            addr = struct_addresses.get(name)
            logger.debug(
                f"Checking struct '{struct['name']}' at resolved address 0x{addr:x} for critical field corruption..."
            )
            size = 0
            offset = 0
            for field in struct.get("fields", []):
                offset += size
                size = field["size"]
                if field.get("is_critical"):
                    field_addr = addr + offset
                    try:
                        current_val = state.memory.load(
                            field_addr, size, endness=state.project.arch.memory_endness
                        )
                        if state.solver.symbolic(current_val):
                            vuln_data = _get_cause(state, bv_args, symbolic_stdin)
                            vuln_data["state_type"] = "intra_struct_corruption"
                            vuln_data["description"] = (
                                f"Critical field at offset {offset} in struct '{struct['name']}' became symbolic."
                            )
                            evidence_list.append(vuln_data)
                            found_vuln = True
                    except Exception as e:
                        logger.warning(
                            "Failed to check struct field at address 0x%x: %s",
                            field_addr,
                            e,
                        )
                        continue

    # Check 4: Format String Vulnerability Detection via Hooks
    for state in chain(simgr.active, simgr.deadended, simgr.unconstrained):
        if state.globals.get("fmt_vulnerable", False):
            vuln_data = _get_cause(state, bv_args, symbolic_stdin)
            vuln_data["state_type"] = state.globals.get(
                "fmt_vuln_type", "format_string_write"
            )
            vuln_data["description"] = state.globals.get(
                "fmt_vuln_desc", "Format String vulnerability verified by hook."
            )
            evidence_list.append(vuln_data)
            found_vuln = True
            break

    # Check 5: Double Free Detection via Hooks
    warning = None
    for state in chain(simgr.active, simgr.deadended, simgr.unconstrained):
        if state.globals.get("double_free_detected", False):
            warning = "Double Free detected in execution path (Potential DoS). Note: Modern glibc prevents exploitation via abort(). Old glibc versions may allow exploitation. Further analysis recommended."
            break

    if found_vuln:
        msg = f"{vulnerability_type.replace('_', ' ').title()} confirmed in '{target_function}'."
    else:
        msg = f"No {vulnerability_type.replace('_', ' ').title()} found in '{target_function}'."
        if message:
            msg += f" Additional info: {message}"
        if warning:
            msg += f" Warning: {warning}"

    return build_result(found_vuln, target_function, evidence_list, msg)

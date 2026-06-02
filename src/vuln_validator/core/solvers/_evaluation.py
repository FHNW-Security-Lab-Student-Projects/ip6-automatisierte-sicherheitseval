import logging
from itertools import chain
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def _get_cause(
    state,
    symbolic_args: List[Any],
    symbolic_stdin: Any,
) -> Dict[str, Any]:  # state_type is either "errored" or "unconstrained"
    details = {
        "input_hex": {},
    }
    if symbolic_args:
        for idx, sym_arg in enumerate(symbolic_args):
            try:
                val = state.solver.eval(sym_arg, cast_to=bytes)
                details["input_hex"][f"arg_{idx}"] = val.hex()
            except Exception as e:
                logger.warning(
                    "Failed to extract arg %d from %s state: %s",
                    idx,
                    e,
                )
                details["input_hex"][f"arg_{idx}"] = "Extraction failed"
    else:
        try:
            poc = state.solver.eval(symbolic_stdin, cast_to=bytes)
            details["input_hex"]["stdin"] = poc.hex()
        except Exception as e:
            logger.warning(
                "Failed to extract stdin from %s state: %s",
                e,
            )
            details["input_hex"]["stdin"] = "Extraction failed"

    logger.debug("Extracted details for %s state: %s", state, details)
    return details


def evaluate_results(
    simgr,
    canaries,
    symbolic_args,
    symbolic_stdin,
    target_function: str,
    structs: List[Dict[str, Any]],
    struct_addresses: List[int],
    vulnerability_type: str,
    build_result,
):
    found_vuln = False
    evidence_list = []
    canary_hit = False

    # Check 1: Symbolic RIP (Control Flow Hijack)
    for state in simgr.unconstrained:
        if state.solver.symbolic(state.regs.rip):
            vuln_data = _get_cause(state, symbolic_args, symbolic_stdin)
            vuln_data["state_type"] = "unconstrained"
            vuln_data["description"] = "Unconstrained state with symbolic RIP detected."
            evidence_list.append(vuln_data)
            found_vuln = True

    # Check 2: Canaries (Data Corruption)
    for state in chain(simgr.active, simgr.deadended, simgr.unconstrained):
        if canary_hit:
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
                    vuln_data = _get_cause(state, symbolic_args, symbolic_stdin)
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
        if len(struct_addresses) != len(structs):
            logger.warning(
                "Mismatch between resolved struct addresses and local struct definitions. Skipping intra-struct corruption check."
            )
            break
        for struct_addr, struct in zip(struct_addresses, structs):
            logger.info(
                f"Checking struct '{struct['name']}' at resolved address 0x{struct_addr:x} for critical field corruption..."
            )
            size = 0
            offset = 0
            for field in struct.get("fields", []):
                offset += size
                size = field["size"]
                if field.get("is_critical"):
                    field_addr = struct_addr + offset
                    try:
                        current_val = state.memory.load(
                            field_addr, size, endness=state.project.arch.memory_endness
                        )
                        if state.solver.symbolic(current_val):
                            vuln_data = _get_cause(state, symbolic_args, symbolic_stdin)
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

    if found_vuln:
        msg = f"{vulnerability_type.replace('_', ' ').title()} confirmed in '{target_function}'."
    else:
        msg = f"No {vulnerability_type.replace('_', ' ').title()} found in '{target_function}'."

    return build_result(found_vuln, target_function, evidence_list, msg)

from elftools.elf.elffile import ELFFile
import logging

logger = logging.getLogger(__name__)


def _decode_sleb128(data):
    """Decodes Signed Little Endian Base 128 from bytes. Returns int."""
    result = 0
    shift = 0
    for byte in data:
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
    # Sign extension
    if shift > 0 and (result & (1 << (shift - 1))):
        result -= 1 << shift
    return result


def get_struct_addr_from_dwarf(project, func_addr, struct_name, state):
    """
    Resolves runtime stack address of a local variable via DWARF.
    Returns int address or None. Requires -g flag.
    """
    binary_path = project.loader.main_object.binary

    try:
        with open(binary_path, "rb") as f:
            elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                return None

            dwarf = elffile.get_dwarf_info()

            for cu in dwarf.iter_CUs():
                for die in cu.get_top_DIE().iter_children():
                    if die.tag != "DW_TAG_subprogram":
                        continue

                    # Check function address range
                    low_pc = die.attributes.get("DW_AT_low_pc")
                    high_pc = die.attributes.get("DW_AT_high_pc")
                    if not low_pc:
                        continue

                    low_val = low_pc.value
                    high_val = (
                        high_pc.value
                        if high_pc.form.startswith("DW_FORM_addr")
                        else low_val + high_pc.value
                    )

                    if not (low_val <= func_addr < high_val):
                        continue

                    # Find variable by name
                    for child in die.iter_children():
                        if child.tag != "DW_TAG_variable":
                            continue

                        name_attr = child.attributes.get("DW_AT_name")
                        if not name_attr:
                            continue

                        var_name = (
                            name_attr.value.decode("utf-8")
                            if isinstance(name_attr.value, bytes)
                            else str(name_attr.value)
                        )
                        if var_name != struct_name:
                            continue

                        # Parse location (expect DW_OP_fb_offset)
                        loc_attr = child.attributes.get("DW_AT_location")
                        if not loc_attr:
                            return None

                        loc_expr = loc_attr.value
                        if (
                            not loc_expr or loc_expr[0] != 0x91
                        ):  # 0x91 = DW_OP_fb_offset
                            return None

                        # Decode offset
                        offset = _decode_sleb128(loc_expr[1:])

                        # Calculate absolute address
                        try:
                            rbp_val = state.solver.eval(state.regs.rbp)
                            return rbp_val + offset
                        except Exception as e:
                            logger.warning(
                                f"Failed to evaluate RBP for struct address calculation: {e}"
                            )
                            return None

            return None

    except Exception as e:
        logger.warning(f"Error while parsing DWARF for struct address: {e}")
        return None

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class


def _dwarf_type_size(die):
    if die is None:
        return None
    # get size directly if available
    if "DW_AT_byte_size" in die.attributes:
        return die.attributes["DW_AT_byte_size"].value
    # handle arrays by multiplying element size with count
    if die.tag == "DW_TAG_array_type":
        elem = die.get_DIE_from_attribute("DW_AT_type")
        elem_size = _dwarf_type_size(elem) or 0
        count = 1
        for sr in die.iter_children():
            if sr.tag == "DW_TAG_subrange_type":
                if "DW_AT_count" in sr.attributes:
                    count *= sr.attributes["DW_AT_count"].value
                elif "DW_AT_upper_bound" in sr.attributes:
                    count *= sr.attributes["DW_AT_upper_bound"].value + 1
        return elem_size * count
    if "DW_AT_type" in die.attributes:
        return _dwarf_type_size(die.get_DIE_from_attribute("DW_AT_type"))
    return None


def _max_local_size_from_dwarf(project, addr):
    path = project.loader.main_object.binary
    with open(path, "rb") as f:
        dwarf = ELFFile(f).get_dwarf_info()
        if dwarf is None:
            return None

        best = 0
        for cu in dwarf.iter_CUs():  # all compilation units
            for (
                die
            ) in (
                cu.get_top_DIE().iter_children()
            ):  # all top-level DIEs (functions, globals, etc.)
                if die.tag != "DW_TAG_subprogram":  # Standard tag for functions
                    continue
                low = die.attributes.get("DW_AT_low_pc")  # function start address
                high = die.attributes.get(
                    "DW_AT_high_pc"
                )  # function size or end address
                if not low or not high:
                    continue
                low = low.value
                high = (
                    high.value
                    if describe_form_class(high.form) == "address"
                    else low + high.value
                )
                if not (low <= addr < high):
                    continue

                for child in die.iter_children():
                    if child.tag not in (
                        "DW_TAG_variable",
                        "DW_TAG_formal_parameter",
                    ):  # only variables and parameters can have sizes
                        continue
                    size = _dwarf_type_size(child.get_DIE_from_attribute("DW_AT_type"))
                    if size:
                        best = max(best, size)

        return best or None


def adjust_libc_limits_from_locals(state, project, addr):
    if not hasattr(state, "libc"):
        return

    bound = _max_local_size_from_dwarf(project, addr)
    if bound:
        bound += 1  # +1 for null terminator
        state.libc.max_str_len = max(state.libc.max_str_len, bound)
        state.libc.buf_symbolic_bytes = max(state.libc.buf_symbolic_bytes, bound)

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class
import logging

logger = logging.getLogger(__name__)


class DwarfAnalyzer:
    """
    Analyzer for DWARF debug information.

    Usage:
        analyzer = DwarfAnalyzer(project)
        size = analyzer.get_max_local_size(addr)
        addr = analyzer.get_struct_stack_addr(func_addr, "my_struct", state)
    """

    def __init__(self, project):
        self.project = project
        self._binary_path = project.loader.main_object.binary
        self._dwarf_info = None
        self._load_error = False

    def _get_dwarf_info(self):
        """
        Lazy loading of DWARF info.
        Parses the file only once and caches the result.
        """
        if self._load_error:
            return None

        if self._dwarf_info is None:
            try:
                with open(self._binary_path, "rb") as f:
                    elffile = ELFFile(f)
                    if not elffile.has_dwarf_info():
                        logger.debug(f"No DWARF info found in {self._binary_path}")
                        self._load_error = True
                        return None

                    # Parsing happens here. This can be slow, so caching is key.
                    self._dwarf_info = elffile.get_dwarf_info()

            except Exception as e:
                logger.warning(f"Error loading ELF/DWARF file {self._binary_path}: {e}")
                self._load_error = True
                return None

        return self._dwarf_info

    @staticmethod
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

    def _get_type_size(self, die):
        """Recursively resolves the byte size of a DWARF type DIE."""
        if die is None:
            return None
        # get size directly if available
        if "DW_AT_byte_size" in die.attributes:
            return die.attributes["DW_AT_byte_size"].value
        # handle arrays by multiplying element size with count
        if die.tag == "DW_TAG_array_type":
            elem = die.get_DIE_from_attribute("DW_AT_type")
            elem_size = self._get_type_size(elem) or 0
            count = 1
            for sr in die.iter_children():
                if sr.tag == "DW_TAG_subrange_type":
                    if "DW_AT_count" in sr.attributes:
                        count *= sr.attributes["DW_AT_count"].value
                    elif "DW_AT_upper_bound" in sr.attributes:
                        count *= sr.attributes["DW_AT_upper_bound"].value + 1
            return elem_size * count

        if "DW_AT_type" in die.attributes:
            return self._get_type_size(die.get_DIE_from_attribute("DW_AT_type"))

        return None

    def _find_subprogram_die(self, addr):
        """
        Internal helper to find the DW_TAG_subprogram DIE that contains 'addr'.
        Returns the DIE or None.
        """
        dwarf = self._get_dwarf_info()
        if dwarf is None:
            return None

        for cu in dwarf.iter_CUs():  # all compilation units
            # all top-level DIEs (functions, globals, etc.)
            for die in cu.get_top_DIE().iter_children():
                if die.tag != "DW_TAG_subprogram":  # Standard tag for functions
                    continue

                low = die.attributes.get("DW_AT_low_pc")  # function start address
                # function size or end address
                high = die.attributes.get("DW_AT_high_pc")

                if not low or not high:
                    continue

                low_val = low.value
                high_val = (
                    high.value
                    if describe_form_class(high.form) == "address"
                    else low_val + high.value
                )

                if low_val <= addr < high_val:
                    return die

        return None

    def get_max_local_size(self, addr):
        """
        Calculates the maximum size of local variables/parameters
        for the function containing 'addr'.
        """
        func_die = self._find_subprogram_die(addr)
        if not func_die:
            return None

        best = 0
        for child in func_die.iter_children():
            if child.tag not in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                continue

            type_die = child.get_DIE_from_attribute("DW_AT_type")
            size = self._get_type_size(type_die)
            if size:
                best = max(best, size)

        return best if best > 0 else None

    def get_struct_stack_addr(self, func_addr, struct_name, state):
        """
        Resolves runtime stack address of a local variable via DWARF.
        Returns int address or None. Requires -g flag.
        """
        func_die = self._find_subprogram_die(func_addr)
        if not func_die:
            return None

        for child in func_die.iter_children():
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

            # location attribute should contain the DWARF expression for the variable's address
            loc_attr = child.attributes.get("DW_AT_location")
            if not loc_attr:
                return None

            # loc_expr is a list of bytes representing the DWARF expression.
            loc_expr = loc_attr.value
            # Expect DW_OP_fb_offset (0x91)
            if not loc_expr or loc_expr[0] != 0x91:
                return None

            # the offset from the frame base, which is typically the stack pointer at function entry.
            return self._decode_sleb128(loc_expr[1:])

        return None

    def adjust_libc_limits(self, state, addr):
        """
        Convenience method: Adjusts libc limits based on max local size found at addr.
        Equivalent to the old adjust_libc_limits_from_locals function.
        """
        if not hasattr(state, "libc"):
            return

        bound = self.get_max_local_size(addr)
        if bound:
            bound += 1  # +1 for null terminator
            state.libc.max_str_len = max(state.libc.max_str_len, bound)
            state.libc.buf_symbolic_bytes = max(state.libc.buf_symbolic_bytes, bound)

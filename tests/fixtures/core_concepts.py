import angr
import claripy

proj = angr.Project("tests/protostar_stack0")

print(proj.arch)  # should print the architecture of the binary, e.g., "i386"
print(proj.entry)  # should print the entry point of the binary, e.g., 0x8048080
print(
    proj.filename
)  # should print the filename of the binary, e.g., "tests/protostar_stack0"
print(proj.loader)  # should print the loader information, e.g., "ELF"
print(
    proj.loader.shared_objects
)  # should print the shared objects loaded by the binary
print(proj.loader.min_addr)  # should print the minimum address of the loaded binary
print(proj.loader.max_addr)  # should print the maximum address of the loaded binary

print(proj.loader.main_object)  # should print the main object of the binary
print(
    proj.loader.main_object.execstack
)  # should print whether the binary has an executable stack
print(
    proj.loader.main_object.pic
)  # should print whether the binary is position-independent

block = proj.factory.block(proj.entry)
print(block)  # should print the block information, e.g., "Block(0x8048080)"
block.pp()  # should print the disassembly of the block at the entry point
print(block.instructions)
print(
    block.instruction_addrs
)  # should print the addresses of the instructions in the block
# for addr in block.instruction_addrs:
#     print(hex(addr))

# States
state = proj.factory.entry_state()
print(state)  # should print the state information, e.g., "SimState(0x8048080)"
print(
    state.regs.rip
)  # should print the value of the instruction pointer register, e.g., 0x8048080
print(state.regs.rax)  # should print the value of the rax register, e.g., 0x0
print(
    state.mem[proj.entry].int.resolved
)  # should print the value at the entry point address, e.g., 0x55

bv = claripy.BVV(0x1234, 32)
print(bv)  # should print the bitvector information, e.g., "0x1234"
print(
    state.solver.eval(bv)
)  # should print the evaluated value of the bitvector, e.g., 0x1234

state.regs.rsi = claripy.BVV(3, 64)  # should set the value of the rsi register to 3
print(state.regs.rsi)  # should print the value of the rsi register, e.g., 0x3

state.mem[0x1000].long = 4  # should set the value at memory address 0x1000 to 4
print(state.mem[0x1000].long.resolved)  # should print the value at memory address

# Simulation Manager
simgr = proj.factory.simulation_manager(state)
print(simgr.active)  # should print the disassembly of the active state
simgr.step()
print(simgr.active)  # should print the disassembly of the active state after stepping
print(
    simgr.active[0].regs.rip
)  # should print the value of the instruction pointer register of the active state
print(
    state.regs.rip
)  # should print the value of the instruction pointer register of the original state


# proj.analyses.? # should print the available analyses for the project

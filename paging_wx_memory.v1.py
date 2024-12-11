# OS Paging Theorem with Z3 in Python
# Demonstrating the W^X (Write XOR Execute) property
#
# mmu1 maps virtual addresses (va) to physical addresses (pa)
# ro_bits and nx_bits in the page table specify access permissions for va
# The functions is_writable and is_executable set/unset ro_bits and nx_bits exclusively.

from z3 import *

def is_writable(va_val):
    # Create a Z3 solver instance
    s = Solver()
    s.push()

    # Define symbolic variables and functions

    # MMU mapping function from virtual to physical addresses
    mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))

    # Virtual and physical addresses
    va = BitVec('va', 32)
    pa = BitVec('pa', 32)

    # Access types
    write = Bool('write')

    # Access permissions in the page table
    ro_bits = Function('ro_bits', BitVecSort(32), BoolSort())  # Read-only bit
    nx_bits = Function('nx_bits', BitVecSort(32), BoolSort())  # Non-executable bit

    # Access permissions in physical memory
    phy_ro = Function('phy_ro', BitVecSort(32), BoolSort())    # Physical read-only
    phy_nx = Function('phy_nx', BitVecSort(32), BoolSort())    # Physical non-executable

    # Add constraints to the solver

    # Constraint 0: MMU maps va to pa
    s.add(mmu1(va) == pa)

    # Constraints 1 and 2: va and pa are page-aligned (lower 12 bits are zero)
    s.add((va & 0xFFF) == 0)
    s.add((pa & 0xFFF) == 0)

    # W^X property: A page cannot be both writable and executable
    s.add(phy_ro(pa) != phy_nx(pa))

    # Constraints for write access
    # If writing, the page must not be read-only
    s.add(Implies(write, ro_bits(va) == False))
    # Physical page must also not be read-only when writing
    s.add(Implies(write, phy_ro(pa) == False))

    # Set the specific virtual address and indicate write access
    s.add(va == BitVecVal(va_val, 32))
    s.add(write == True)

    # Check if the constraints are satisfiable
    CheckSatResult = s.check()

    if CheckSatResult == sat:
        m = s.model()
        print("=== Write Access ===")
        print("write:", m.evaluate(write))
        print("ro_bits(va):", m.evaluate(ro_bits(va)))
        print("phy_ro(pa):", m.evaluate(phy_ro(pa)))
        print("nx_bits(va):", m.evaluate(nx_bits(va)))
        print("phy_nx(pa):", m.evaluate(phy_nx(pa)))
    else:
        print("Constraints are unsatisfiable for write access.")

    s.pop()
    return CheckSatResult

def is_executable(va_val):
    # Create a Z3 solver instance
    s = Solver()
    s.push()

    # Define symbolic variables and functions

    # MMU mapping function from virtual to physical addresses
    mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))

    # Virtual and physical addresses
    va = BitVec('va', 32)
    pa = BitVec('pa', 32)

    # Access types
    execute = Bool('execute')

    # Access permissions in the page table
    ro_bits = Function('ro_bits', BitVecSort(32), BoolSort())  # Read-only bit
    nx_bits = Function('nx_bits', BitVecSort(32), BoolSort())  # Non-executable bit

    # Access permissions in physical memory
    phy_ro = Function('phy_ro', BitVecSort(32), BoolSort())    # Physical read-only
    phy_nx = Function('phy_nx', BitVecSort(32), BoolSort())    # Physical non-executable

    # Add constraints to the solver

    # Constraint 0: MMU maps va to pa
    s.add(mmu1(va) == pa)

    # Constraints 1 and 2: va and pa are page-aligned (lower 12 bits are zero)
    s.add((va & 0xFFF) == 0)
    s.add((pa & 0xFFF) == 0)

    # W^X property: A page cannot be both writable and executable
    s.add(phy_ro(pa) != phy_nx(pa))

    # Constraints for execute access
    # If executing, the page must be executable (nx_bits unset)
    s.add(Implies(execute, nx_bits(va) == False))
    # Physical page must also be executable
    s.add(Implies(execute, phy_nx(pa) == False))

    # Set the specific virtual address and indicate execute access
    s.add(va == BitVecVal(va_val, 32))
    s.add(execute == True)

    # Check if the constraints are satisfiable
    CheckSatResult = s.check()

    if CheckSatResult == sat:
        m = s.model()
        print("=== Execute Access ===")
        print("execute:", m.evaluate(execute))
        print("ro_bits(va):", m.evaluate(ro_bits(va)))
        print("phy_ro(pa):", m.evaluate(phy_ro(pa)))
        print("nx_bits(va):", m.evaluate(nx_bits(va)))
        print("phy_nx(pa):", m.evaluate(phy_nx(pa)))
    else:
        print("Constraints are unsatisfiable for execute access.")

    s.pop()
    return CheckSatResult

def is_writable_and_executable(va_val):
    # Create a Z3 solver instance
    s = Solver()
    s.push()

    # Define symbolic variables and functions

    # MMU mapping function from virtual to physical addresses
    mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))

    # Virtual and physical addresses
    va = BitVec('va', 32)
    pa = BitVec('pa', 32)

    # Access types
    write = Bool('write')
    execute = Bool('execute')

    # Access permissions in the page table
    ro_bits = Function('ro_bits', BitVecSort(32), BoolSort())  # Read-only bit
    nx_bits = Function('nx_bits', BitVecSort(32), BoolSort())  # Non-executable bit

    # Access permissions in physical memory
    phy_ro = Function('phy_ro', BitVecSort(32), BoolSort())    # Physical read-only
    phy_nx = Function('phy_nx', BitVecSort(32), BoolSort())    # Physical non-executable

    # Add constraints to the solver

    # Constraint 0: MMU maps va to pa
    s.add(mmu1(va) == pa)

    # Constraints 1 and 2: va and pa are page-aligned (lower 12 bits are zero)
    s.add((va & 0xFFF) == 0)
    s.add((pa & 0xFFF) == 0)

    # W^X property: A page cannot be both writable and executable
    s.add(phy_ro(pa) != phy_nx(pa))

    # Constraints for write access
    s.add(Implies(write, ro_bits(va) == False))
    s.add(Implies(write, phy_ro(pa) == False))

    # Constraints for execute access
    s.add(Implies(execute, nx_bits(va) == False))
    s.add(Implies(execute, phy_nx(pa) == False))

    # Set the specific virtual address and indicate both write and execute access
    s.add(va == BitVecVal(va_val, 32))
    s.add(write == True)
    s.add(execute == True)

    # Check if the constraints are satisfiable
    CheckSatResult = s.check()

    if CheckSatResult == sat:
        m = s.model()
        print("=== Write and Execute Access ===")
        print("write:", m.evaluate(write))
        print("execute:", m.evaluate(execute))
        print("ro_bits(va):", m.evaluate(ro_bits(va)))
        print("phy_ro(pa):", m.evaluate(phy_ro(pa)))
        print("nx_bits(va):", m.evaluate(nx_bits(va)))
        print("phy_nx(pa):", m.evaluate(phy_nx(pa)))
    else:
        print("Constraints are unsatisfiable for write and execute access.")

    s.pop()
    return CheckSatResult

# Example virtual address
va_val = 0x12345000

# Check if the virtual address is writable
if is_writable(va_val) == sat:
    print("==== Writable at {} ====".format(hex(va_val)))
else:
    print("Not writable at {}".format(hex(va_val)))

# Check if the virtual address is executable
if is_executable(va_val) == sat:
    print("==== Executable at {} ====".format(hex(va_val)))
else:
    print("Not executable at {}".format(hex(va_val)))

# Check if the virtual address can be both writable and executable
if is_writable_and_executable(va_val) == sat:
    print("==== Writable and Executable at {} ====".format(hex(va_val)))
else:
    print("Cannot be both writable and executable at {}".format(hex(va_val)))

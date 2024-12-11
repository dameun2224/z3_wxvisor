# OS paging theorem Z3 Python with W^X property
#
# Check the Write XOR Execute (W^X) guarantee with aliasing

from z3 import *

def is_alias_writable(va_val):
    # Create a Z3 solver instance
    s = Solver()
    
    # Define symbolic variables

    # MMU mapping from virtual addresses to physical addresses
    mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))

    # Virtual addresses
    va = BitVec('va', 32)       # Original virtual address
    va1 = BitVec('va1', 32)     # Alias virtual address 1
    va2 = BitVec('va2', 32)     # Alias virtual address 2

    # Physical address
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

    # Constraint 1: MMU maps va to pa
    s.add(mmu1(va) == pa)

    # Constraint 2: va and pa are page-aligned (lower 12 bits are zero)
    s.add((va & 0xFFF) == 0)
    s.add((pa & 0xFFF) == 0)

    # W^X property: A page cannot be both writable and executable
    s.add(ro_bits(va) != nx_bits(va))

    # Constraint 3: If writing, ro_bits should reflect phy_ro, and the page should not be read-only
    s.add(Implies(write, And(ro_bits(va) == phy_ro(pa), ro_bits(va) == False)))

    # Constraint 4: If executing, nx_bits should reflect phy_nx, and the page should be executable
    s.add(Implies(execute, And(nx_bits(va) == phy_nx(pa), nx_bits(va) == False)))

    # Alias mapping constraints
    s.add(Distinct(va, va1, va2))      # va, va1, va2 are distinct virtual addresses
    s.add(mmu1(va1) == pa)             # va1 maps to the same pa
    s.add(mmu1(va2) == pa)             # va2 maps to the same pa
    s.add((va1 & 0xFFF) == 0)          # va1 is page-aligned
    s.add((va2 & 0xFFF) == 0)          # va2 is page-aligned

    # Access permissions for aliases
    s.add(ro_bits(va) != ro_bits(va1))     # va and va1 have different ro_bits
    s.add(ro_bits(va1) == phy_ro(pa))      # ro_bits of va1 matches physical ro
    s.add(nx_bits(va) != nx_bits(va2))     # va and va2 have different nx_bits
    s.add(nx_bits(va2) == phy_nx(pa))      # nx_bits of va2 matches physical nx

    # Check if the constraints are satisfiable for the given va and write access
    s.push()
    s.add(va == BitVecVal(va_val, 32))
    s.add(write == True)
    s.add(ro_bits(va1) != ro_bits(va))
    CheckSatResult = s.check()

    if CheckSatResult == sat:
        m = s.model()
        print("=== Write Access Model ===")
        print("write: ", m.evaluate(write))
        print("ro_bits(va): ", m.evaluate(ro_bits(va)))
        print("phy_ro(pa): ", m.evaluate(phy_ro(pa)))
        print("nx_bits(va): ", m.evaluate(nx_bits(va)))
        print("phy_nx(pa): ", m.evaluate(phy_nx(pa)))
    else:
        print("Constraints are unsatisfiable for writable alias.")

    s.pop()
    # Return True if the constraints are satisfiable for writable va, False otherwise
    return CheckSatResult == sat

def is_alias_executable(va_val):
    # Similar to is_alias_writable, but for execute access
    s = Solver()
    
    # Define symbolic variables

    # MMU mapping from virtual addresses to physical addresses
    mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))

    # Virtual addresses
    va = BitVec('va', 32)       # Original virtual address
    va1 = BitVec('va1', 32)     # Alias virtual address 1
    va2 = BitVec('va2', 32)     # Alias virtual address 2

    # Physical address
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

    # Constraint 1: MMU maps va to pa
    s.add(mmu1(va) == pa)

    # Constraint 2: va and pa are page-aligned (lower 12 bits are zero)
    s.add((va & 0xFFF) == 0)
    s.add((pa & 0xFFF) == 0)

    # W^X property: A page cannot be both writable and executable
    s.add(ro_bits(va) != nx_bits(va))

    # Constraint 3: If writing, ro_bits should reflect phy_ro, and the page should not be read-only
    s.add(Implies(write, And(ro_bits(va) == phy_ro(pa), ro_bits(va) == False)))

    # Constraint 4: If executing, nx_bits should reflect phy_nx, and the page should be executable
    s.add(Implies(execute, And(nx_bits(va) == phy_nx(pa), nx_bits(va) == False)))

    # Alias mapping constraints
    s.add(Distinct(va, va1, va2))      # va, va1, va2 are distinct virtual addresses
    s.add(mmu1(va1) == pa)             # va1 maps to the same pa
    s.add(mmu1(va2) == pa)             # va2 maps to the same pa
    s.add((va1 & 0xFFF) == 0)          # va1 is page-aligned
    s.add((va2 & 0xFFF) == 0)          # va2 is page-aligned

    # Access permissions for aliases
    s.add(nx_bits(va) != nx_bits(va2))     # va and va2 have different nx_bits
    s.add(nx_bits(va2) == phy_nx(pa))      # nx_bits of va2 matches physical nx

    # Check if the constraints are satisfiable for the given va and execute access
    s.push()
    s.add(va == BitVecVal(va_val, 32))
    s.add(execute == True)
    s.add(nx_bits(va2) != nx_bits(va))
    CheckSatResult = s.check()

    if CheckSatResult == sat:
        m = s.model()
        print("=== Execute Access Model ===")
        print("execute: ", m.evaluate(execute))
        print("ro_bits(va): ", m.evaluate(ro_bits(va)))
        print("phy_ro(pa): ", m.evaluate(phy_ro(pa)))
        print("nx_bits(va): ", m.evaluate(nx_bits(va)))
        print("phy_nx(pa): ", m.evaluate(phy_nx(pa)))
    else:
        print("Constraints are unsatisfiable for executable alias.")

    s.pop()
    # Return True if the constraints are satisfiable for executable va, False otherwise
    return CheckSatResult == sat

va_val = 0x12345000  # Example virtual address

if is_alias_writable(va_val):
    print("==== Alias write({}) satisfied ====".format(hex(va_val)))
else:
    print("Alias write({}) unsatisfied".format(hex(va_val)))

if is_alias_executable(va_val):
    print("==== Alias execute({}) satisfied ====".format(hex(va_val)))
else:
    print("Alias execute({}) unsatisfied".format(hex(va_val)))

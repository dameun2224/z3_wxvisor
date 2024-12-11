from z3 import *

# This script models an OS paging system with aliasing using the Z3 theorem prover.
# It checks whether multiple virtual addresses can map to the same physical address
# with different access permissions, which should be unsatisfiable.

def alias_mapping():
    # Create a Z3 solver instance
    solver = Solver()

    # Define symbolic variables

    # MMU mapping from virtual addresses to physical addresses
    mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))

    # Virtual addresses
    va = BitVec('va', 32)     # Original virtual address
    va1 = BitVec('va1', 32)   # Alias virtual address 1
    va2 = BitVec('va2', 32)   # Alias virtual address 2

    # Physical address
    pa = BitVec('pa', 32)

    # Access permissions in the page table
    ro_bits = Function('ro_bits', BitVecSort(32), BoolSort())
    nx_bits = Function('nx_bits', BitVecSort(32), BoolSort())

    # Access permissions in physical memory
    phy_ro = Function('phy_ro', BitVecSort(32), BoolSort())
    phy_nx = Function('phy_nx', BitVecSort(32), BoolSort())

    # Add constraints to the solver

    # Basic constraints: MMU mappings and page alignment
    solver.add(mmu1(va) == pa)
    solver.add((va & 0xFFF) == 0)  # va is page-aligned
    solver.add((pa & 0xFFF) == 0)  # pa is page-aligned

    # Access permissions match between page table and physical memory
    solver.add(ro_bits(va) == phy_ro(pa))
    solver.add(nx_bits(va) == phy_nx(pa))

    # Aliasing constraints
    # va, va1, and va2 are distinct virtual addresses
    solver.add(Distinct(va, va1, va2))

    # va1 and va2 also map to the same physical address pa
    solver.add(mmu1(va1) == pa)
    solver.add(mmu1(va2) == pa)

    # va1 and va2 are page-aligned
    solver.add((va1 & 0xFFF) == 0)
    solver.add((va2 & 0xFFF) == 0)

    # va and va1 have different read-only permissions
    solver.add(ro_bits(va) != ro_bits(va1))
    solver.add(ro_bits(va1) == phy_ro(pa))

    # va and va2 have different non-executable permissions
    solver.add(nx_bits(va) != nx_bits(va2))
    solver.add(nx_bits(va2) == phy_nx(pa))

    # Check for satisfiability
    retVal = solver.check()
    if retVal == sat:
        print("Alias mapping is satisfiable.")
    else:
        print("Alias mapping with different permissions is unsatisfiable.")
        
    return retVal

def basic_mapping():
    # Create a Z3 solver instance
    solver = Solver()

    # Define symbolic variables

    # MMU mapping from virtual addresses to physical addresses
    mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))

    # Virtual and physical addresses
    va = BitVec('va', 32)
    pa = BitVec('pa', 32)

    # Access permissions in the page table
    ro_bits = Function('ro_bits', BitVecSort(32), BoolSort())
    nx_bits = Function('nx_bits', BitVecSort(32), BoolSort())

    # Access permissions in physical memory
    phy_ro = Function('phy_ro', BitVecSort(32), BoolSort())
    phy_nx = Function('phy_nx', BitVecSort(32), BoolSort())

    # Add constraints to the solver

    # MMU mapping and page alignment
    solver.add(mmu1(va) == pa)
    solver.add((va & 0xFFF) == 0)  # va is page-aligned
    solver.add((pa & 0xFFF) == 0)  # pa is page-aligned

    # Access permissions match between page table and physical memory
    solver.add(ro_bits(va) == phy_ro(pa))
    solver.add(nx_bits(va) == phy_nx(pa))

    # Check for satisfiability
    retVal = solver.check()
    if retVal == sat:
        print("Basic mapping is satisfiable.")
    else:
        print("Basic mapping is unsatisfiable.")
        
    return retVal

# Run the basic mapping and alias mapping checks
basic_mapping()
alias_mapping()

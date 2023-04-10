from z3 import *

# OS paging theorem z3 python
# mmu1 maps va to pa
# ro_bits in page table
# nx_bits in page table
# --> specifies access permission for va
# check physical access permission is same with page table's ro_bits, nx_bits
# satisfied.

# Define symbolic variables
mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))
va = BitVec('va', 32)
pa = BitVec('pa', 32)

# Access permission on page table
ro_bits = Function('ro_bits', BitVecSort(32), BoolSort())  # ro_bits(va) = 1 when set
nx_bits = Function('nx_bits', BitVecSort(32), BoolSort())  # nx_bits(va) = 1 when set

# Access permission on physical memory
phy_ro = Function('phy_ro', BitVecSort(32), BoolSort())  # phy_ro(pa) = 1 when pa is read-only
phy_nx = Function('phy_nx', BitVecSort(32), BoolSort())  # phy_nx(pa) = 1 when pa is non-executable


# Define constraints
# Constraint 0,1,2: Virtual address maps to the same physical address in the page table
constraint0 = mmu1(va) == pa
constraint1 = (va & 0xFFF) == 0
constraint2 = (pa & 0xFFF) == 0

# Constant 3,4: access permission (ro, nx)
constraint3 = ro_bits(va) == phy_ro(mmu1(va))
constraint4 = nx_bits(va) == phy_nx(mmu1(va))


# Create solver
solver = Solver()

# Add constraints to the solver
solver.add(constraint0)
solver.add(constraint1)
solver.add(constraint2)
solver.add(constraint3)
solver.add(constraint4)

# Check for satisfiability
if solver.check() == sat:
    print("satisfiable")
else:
    print("unsatisfiable")

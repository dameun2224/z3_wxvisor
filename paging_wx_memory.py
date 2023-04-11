
# OS paging theorem z3 python
# with W^X property
#
# mmu1 maps va to pa
# ro_bits in page table
# nx_bits in page table
# --> specifies access permission for va
# check physical access permission is same with page table's ro_bits, nx_bits
# unsatisfiable

from z3 import *

# Define symbolic variables
mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))
va = BitVec('va', 32)
va1 = BitVec('va1', 32)  # va1 is an alias of va
va2 = BitVec('va2', 32)
pa = BitVec('pa', 32)
write = Bool('write')
execute = Bool('execute')

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

# W^X property
constraint_wx = Distinct(ro_bits(va), nx_bits(va))

# Constraint 3: Virtual access permission (ro_bits) is set to physical access permission (phy_ro) when page is writable,
# and unset when writing to virtual page
constraint3 = Implies(write, And (ro_bits(va) == phy_ro(mmu1(va))), (ro_bits(va) == False))


# Constraint 4: Virtual access permission (nx_bits) is set to physical access permission (phy_nx) when executing from virtual page,
# and unset when executing
constraint4 = Implies(execute, And (nx_bits(va) == phy_nx(mmu1(va))), (nx_bits(va) == False))

def is_writable(va):
    s = Solver()
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint_wx)
    s.add(constraint3)
    s.add(constraint4)

    # Check if the constraints are satisfiable for the given va and write access
    s.push()
    s.add(va == BitVecVal(va, 32))
    s.add(write == True)
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== write: ", m.evaluate(write), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu1(va))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu1(va))))

    s.pop()
    # Return True if the constraints are satisfiable for writable va, False otherwise
    return CheckSatResult == sat


def is_executable(va):
    s = Solver()
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint_wx)
    s.add(constraint3)
    s.add(constraint4)

    # Check if the constraints are satisfiable for the given va and execute access
    s.push()
    s.add(va == BitVecVal(va, 32))
    s.add(execute == True)
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu1(va))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu1(va))))

    s.pop()
    # Return True if the constraints are satisfiable for executable va, False otherwise
    return CheckSatResult == sat

va_val = BitVecVal(0x12345000, 32).as_long()

if is_writable(va_val):
    print("==== write({}) satisfied ====".format(hex(va_val)))
else:
    print("write({}) unsatisfied".format(hex(va_val)))

if is_executable(va_val):
    print("==== execute({}) satisfied ====".format(hex(va_val)))
else:
    print("execute({}) unsatisfied".format(hex(va_val)))
    
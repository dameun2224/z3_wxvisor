
# WXvisor nested paging theorem z3 python
#
# mmu1 maps va to ipa
# ro_bits in page table
# nx_bits in page table
# phy_ro, phy_nx specifies physically read-only, physically non-executable pages
#
# mmu2 maps ipa to pa
# mmu2 disallow alias mapping
# mmu2 mandates W^X memory according to WXvisor's state transition model

from z3 import *

# Define symbolic variables
mmu1 = Function('mmu1', BitVecSort(32), BitVecSort(32))
va = BitVec('va', 32)
va1 = BitVec('va1', 32)  # va1 is an alias of va
va2 = BitVec('va2', 32)
pa = BitVec('pa', 32)
write = Bool('write')
execute = Bool('execute')

# Wxvisor introduces ipa-to-pa mapping
ipa = BitVec('ipa', 32) # va ----> ipa ----> pa
#                           mmu1      mmu2
mmu2 = Function('mmu2', BitVecSort(32), BitVecSort(32))
ipa1 = BitVec('ipa1', 32)
ipa2 = BitVec('ipa2', 32)
# ipa1,2 are alias to ipa (not allowed)

# Access permission on mmu1 page table
ro_bits = Function('ro_bits', BitVecSort(32), BoolSort())  # ro_bits(va) = 1 when set
nx_bits = Function('nx_bits', BitVecSort(32), BoolSort())  # nx_bits(va) = 1 when set

# Access permission by WXvisor
ro_bits2 = Function('ro_bits2', BitVecSort(32), BoolSort())  # ro_bits(va) = 1 when set
nx_bits2 = Function('nx_bits2', BitVecSort(32), BoolSort())  # nx_bits(va) = 1 when set

# Access permission on physical memory
phy_ro = Function('phy_ro', BitVecSort(32), BoolSort())  # phy_ro(pa) = 1 when pa is read-only
phy_nx = Function('phy_nx', BitVecSort(32), BoolSort())  # phy_nx(pa) = 1 when pa is non-executable

# Define constraints
# Constraint 0,1,2: Virtual address maps to the same physical address in the page table
constraint0 = mmu1(va) == ipa
constraint1 = (va & 0xFFF) == 0
constraint2 = (ipa & 0xFFF) == 0
constraint3 = mmu2(ipa) == pa
constraint4 = (pa & 0xFFF) == 0

# Constraint 3: mmu1 allows alias mapping, but mmu2 does not allow aliases
constraint5 = Distinct(va, va1, va2)
constraint6 = mmu1(va1) == ipa1
constraint7 = mmu1(va2) == ipa2
constraint8 = Implies( Distinct(ipa, ipa1), Distinct(mmu2(ipa), mmu2(ipa1)) )

# Constant 9: least privilege principle
# either va has RO bit in the mmu1 page table or RO bit in the mmu2 page table
constraint9  = phy_ro(mmu2((mmu1(va)))) == Or (ro_bits(va), ro_bits2(mmu1(va)), ro_bits(va1), ro_bits2(mmu1(va)) )
constraint10 = phy_nx(mmu2((mmu1(va)))) == Or (nx_bits(va), nx_bits2(mmu1(va)), nx_bits(va1), nx_bits2(mmu1(va1)) )

# physical W^X property
constraint_wx = Distinct(phy_ro(mmu2(mmu1(va))), phy_nx(mmu2(mmu1(va))))

# Constraint 3: Virtual access permission (ro_bits) is set to physical access permission (phy_ro) when page is writable,
# and unset when writing to virtual page
constraint11 = Implies(write, (ro_bits2(mmu1(va)) == False))
constraint12 = Implies(write, (phy_ro(mmu2(mmu1((va)))) == False))

# Constraint 4: Virtual access permission (nx_bits) is set to physical access permission (phy_nx) when executing from virtual page,
# and unset when executing
constraint13 = Implies(execute, (nx_bits2(mmu1(va)) == False))
constraint14 = Implies(execute, (phy_nx((mmu2(mmu1(va)))) == False) )

def basic_mapping(va_val):
    s = Solver()
    s.push()
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint3)
    s.add(constraint4)
    
    s.add(va == BitVecVal(va_val, 32))
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu2(mmu1(va)))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu2(mmu1(va)))))

    s.pop()
    # Return True if the constraints are satisfiable for writable va, False otherwise
    return CheckSatResult

def alias_mapping(va1_val, va2_val):
    s = Solver()
    s.push()
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint3)
    s.add(constraint4)
    s.add(constraint5)
    s.add(constraint6)
    s.add(constraint7)
    s.add(constraint8)
    s.add(constraint9)
    s.add(constraint10)
    
    s.add(va == BitVecVal(va1_val, 32))
    s.add(va1 == BitVecVal(va2_val, 32))
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu2(mmu1(va)))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu2(mmu1(va)))))

    s.pop()
    # Return True if the constraints are satisfiable for writable va, False otherwise
    return CheckSatResult
    
    

def is_writable(va):
    s = Solver()
    s.push()
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint3)
    s.add(constraint4)
    s.add(constraint5)
    s.add(constraint6)
    s.add(constraint7)
    s.add(constraint8)
    s.add(constraint9)
    s.add(constraint10)
    s.add(constraint11)
    s.add(constraint12)
    s.add(constraint_wx)

    # Check if the constraints are satisfiable for the given va and write access
    s.add(va == BitVecVal(va, 32))
    s.add(write == True)
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu2(mmu1(va)))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu2(mmu1(va)))))

    s.pop()
    # Return True if the constraints are satisfiable for writable va, False otherwise
    return CheckSatResult


def is_executable(va_val):
    s = Solver()
    s.push()
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint3)
    s.add(constraint4)
    s.add(constraint5)
    s.add(constraint6)
    s.add(constraint7)
    s.add(constraint8)
    s.add(constraint9)
    s.add(constraint10)
    s.add(constraint13)
    s.add(constraint14)
    s.add(constraint_wx)

    # Check if the constraints are satisfiable for the given va and execute access
    s.add(va == BitVecVal(va_val, 32))
    s.add(execute == True)
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu2(mmu1(va)))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu2(mmu1(va)))))

    s.pop()
    # Return True if the constraints are satisfiable for executable va, False otherwise
    return CheckSatResult


def is_writable_and_executable(va_val):
    s = Solver()
    s.push()
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint3)
    s.add(constraint4)
    s.add(constraint5)
    s.add(constraint6)
    s.add(constraint7)
    s.add(constraint8)
    s.add(constraint9)
    s.add(constraint10)
    s.add(constraint11)
    s.add(constraint12)
    s.add(constraint13)
    s.add(constraint14)
    s.add(constraint_wx)

    # Check if the constraints are satisfiable for the given va and write access
    s.add(va == BitVecVal(va_val, 32))
    s.add(And (write == True), (execute == True))
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu2(mmu1(va)))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu2(mmu1(va)))))

    s.pop()
    # Return True if the constraints are satisfiable for writable va, False otherwise
    return CheckSatResult

def is_va_writable_but_alias_read_only(va_val, va1_val):
    s = Solver()
    s.push()
    s.add(va == BitVecVal(va_val, 32))
    s.add(va1 == BitVecVal(va1_val, 32))
    s.add(Distinct(ro_bits(va1), ro_bits(va)))
    
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint3)
    s.add(constraint4)
    s.add(constraint5)
    s.add(constraint6)
    s.add(constraint7)
    s.add(constraint8)
    s.add(constraint9)
    s.add(constraint10)
    s.add(constraint11)
    s.add(constraint12)
    s.add(constraint13)
    s.add(constraint14)
    s.add(constraint_wx)

    # Check if the constraints are satisfiable for the given va and write access
    s.add(write == True)
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("ro_bits2: ", m.evaluate(ro_bits2(mmu1(va))))
        print("phy_ro: ", m.evaluate(phy_ro(mmu2(mmu1(va)))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu2(mmu1(va)))))

    s.pop()
    # Return True if the constraints are satisfiable for writable va, False otherwise
    return CheckSatResult


def is_va_executable_but_alias_nx(va_val, va1_val):
    s = Solver()
    s.push()
    
    s.add(va == BitVecVal(va_val, 32))
    s.add(va1 == BitVecVal(va1_val, 32))
    s.add(Distinct(nx_bits(va1), nx_bits(va)))
    
    # Add constraints to the solver
    s.add(constraint0)
    s.add(constraint1)
    s.add(constraint2)
    s.add(constraint3)
    s.add(constraint4)
    s.add(constraint5)
    s.add(constraint6)
    s.add(constraint7)
    s.add(constraint8)
    s.add(constraint9)
    s.add(constraint10)
    s.add(constraint11)
    s.add(constraint12)
    s.add(constraint13)
    s.add(constraint14)
    s.add(constraint_wx)

    # Check if the constraints are satisfiable for the given va and execute access
    s.add(execute == True)
    CheckSatResult = s.check()
        
    if CheckSatResult == sat:
        m = s.model()
        print("=== execute: ", m.evaluate(execute), " ===")
        print("ro_bits: ", m.evaluate(ro_bits(va)))
        print("phy_ro: ", m.evaluate(phy_ro(mmu2(mmu1(va)))))
        print("nx_bits: ", m.evaluate(nx_bits(va)))
        print("phy_nx: ", m.evaluate(phy_nx(mmu2(mmu1(va)))))

    s.pop()
    # Return True if the constraints are satisfiable for executable va, False otherwise
    return CheckSatResult

va_val = BitVecVal(0x12345000, 32).as_long()
va1_val = BitVecVal(0x23456000, 32).as_long()

if is_writable(va_val) == sat:
    print("==== write({}) satisfied ====".format(hex(va_val)))
else:
    print("write({}) unsatisfied".format(hex(va_val)))

if is_executable(va_val) == sat:
    print("==== execute({}) satisfied ====".format(hex(va_val)))
else:
    print("execute({}) unsatisfied".format(hex(va_val)))
    
    
if is_va_writable_but_alias_read_only(va_val, va1_val) == sat:
    print("==== va writable & alias read-only({}) satisfied ====".format(hex(va_val)))
else:
    print("alias write({}) unsatisfied".format(hex(va_val)))

if is_va_executable_but_alias_nx(va_val, va1_val) == sat:
    print("==== va executable & alias nx({}) satisfied ====".format(hex(va_val)))
else:
    print("alias execute({}) unsatisfied".format(hex(va_val)))
    
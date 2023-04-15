#test_theorems

#Testing Z3 theorems

from z3 import *
import pytest


def test_basic_mapping():
    import paging
    assert paging.basic_mapping() == z3.sat, "basic mapping unsatisfiable"

def test_alias_mapping():
    import paging_alias
    assert paging_alias.basic_mapping() == z3.sat , "basic mapping unsatisfiable"
    assert paging_alias.alias_mapping() == z3.unsat , "aliases can have physically different access permission; thus unsatisfiable"

def test_paging_wx_memory():
    import paging_wx_memory
    
    va_val = BitVecVal(0x12345000, 32).as_long()
    assert paging_wx_memory.basic_mapping(va_val) == z3.sat , "basic mapping unsatisfiable"
    assert paging_wx_memory.is_writable(va_val) == z3.sat , "is_writable unsatisfiable"
    assert paging_wx_memory.is_executable(va_val) == z3.sat , "is_executable unsatisfiable"
    assert paging_wx_memory.is_writable_and_executable(va_val) == z3.unsat , "w+x at the same time unsatisfiable"
    
def test_wxvisor():
    import wxvisor
    
    va_val = BitVecVal(0x12345000, 32).as_long()
    va1_val = BitVecVal(0x23456000, 32).as_long()
    assert wxvisor.basic_mapping(va_val) == z3.sat , "basic mapping unsatisfiable"
    assert wxvisor.alias_mapping(va_val, va1_val) == z3.sat , "aliases can have physically different access permission; thus unsatisfiable"
    
    assert wxvisor.is_writable(va_val) == z3.sat , "is_writable unsatisfiable"
    assert wxvisor.is_executable(va_val) == z3.sat , "is_executable unsatisfiable"
    assert wxvisor.is_writable_and_executable(va_val) == z3.unsat , "w^x failure"
    
    assert wxvisor.is_va_writable_but_alias_read_only(va_val, va1_val) == z3.unsat , "w+x at the same time unsatisfiable"
    assert wxvisor.is_va_executable_but_alias_nx(va_val, va1_val) == z3.unsat , "w+x at the same time unsatisfiable"
    
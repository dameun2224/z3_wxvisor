# z3_wxvisor
z3 theorem for wxvisor


Assume you have Z3 python
https://github.com/Z3Prover/z3

## 1. basic OS paging with address mapping and access permission
- To run, 
> shell> python paging.py
- Checks the satisfiablity of the constraints in the theorem.
theorem has 
  1. basic address mapping va-to-pa in paging unit,
  2. each va has access permission bit in the page table
  3. matches physical access permission with the permission in the page table

## 2. OS paging with alias
- To run, 
> shell> python paging.py
- Checks the satisfiability of the constraints in the theorem
theorem defines alias to va
  1. different virtual addresses (va1 != va2)
  2. could have the same mapping to the same physical address (mmu1(va1) == mmu1(pa))
  3. matches physical access permission with the permission in the page table

## 3. OS paging with WX memory
- To run, 
> shell> python paging.py
- Checks the satisfiability of the constraints in the theorem
theorem defines WX property
  1. defines ro_bits, nx_bits in the page table
  2. physical read only, non-execute region
  3. checks when write, ro is unset in the page table, and physically same access permission is granted
  4. checks when execute, nx is unset in the page table, and physically same access permission is granted

## 4. WXvisor
- To run, 
> shell> python paging.py
- Checks the satisfiability of the constraints in the theorem
theorem defines WXvisor WX property with aliases
  1. nested paging structure (mmu1: va->ipa, mmu2: ipa->pa)
  2. with access permission in WXvisor (ro_bits2, nx_bits2)
  3. matches physical access permission is the least permission granted
  4. w^x access permission is preserved
  5. matches physical access permission for alias, that has the least permission granted
  6. checks when write, ro is unset in the page table, and physically same access permission is granted
  7. checks when execute, nx is unset in the page table, and physically same access permission is granted

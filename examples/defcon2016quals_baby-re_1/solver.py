#!/usr/bin/python2

import angr
import simuvex
import logging

# DEFCON - BABY-RE
# @author: P1kachu
# @contact: p1kachu@lse.epita.fr
# execution time: 14s  - Intel i7 - 16Gb RAM

p = angr.Project('baby-re')


win            = 0x4028e9  # good
fail           = 0x402941  # fail
main           = 0x4025e7  # Address of main
PASS_LEN       = 13
call_check     = 0x4028e0
flag_addr      = 0x7fffffffffeff98 # First rsi from scanf
find           = (win,)
avoid          = (fail,)


def patch_scanf(state):
    print(state.regs.rsi)
    state.mem[state.regs.rsi:] = state.se.BVS('c', 8)

scanf_offsets = (0x4d, 0x85, 0xbd, 0xf5, 0x12d, 0x165, 0x19d, 0x1d5, 0x20d, 0x245, 0x27d, 0x2b5, 0x2ed)


init = p.factory.blank_state(addr=main)

# Patch scanfs
for offst in scanf_offsets:
    p.hook(main + offst, func=patch_scanf, length=5)


pgp = p.factory.path_group(init, threads=8)

# Now stuff becomes interesting
ex = pgp.explore(find=find, avoid=avoid)

print(ex)
s = ex.found[0].state
flag = s.se.any_str(s.memory.load(flag_addr, 50))

# The flag is 'Math is hard!'
print("The flag is '{0}'".format(flag))


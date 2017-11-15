#!/usr/bin/python2

import string

import angr
from angr.procedures.stubs.UserHook import UserHook

# DEFCON - BABY-RE
# @author: P1kachu
# @contact: p1kachu@lse.epita.fr
# execution time: 14s  - Intel i7 - 16Gb RAM

def main():
    p = angr.Project('baby-re')


    win            = 0x4028e9  # good
    fail           = 0x402941  # fail
    main           = 0x4025e7  # Address of main
    PASS_LEN       = 13
    flag_addr      = 0x7fffffffffeff98 # First rsi from scanf
    find           = (win,)
    avoid          = (fail,)


    def patch_scanf(state):
        print(state.regs.rsi)
        state.mem[state.regs.rsi:].char = state.solver.BVS('c', 8)

    # IDA xrefs
    scanf_offsets = (0x4d, 0x85, 0xbd, 0xf5, 0x12d, 0x165, 0x19d, 0x1d5, 0x20d, 0x245, 0x27d, 0x2b5, 0x2ed)


    init = p.factory.blank_state(addr=main)

    # Patch scanfs (don't know how angr handles it)
    for offst in scanf_offsets:
        p.hook(main + offst, UserHook(user_func=patch_scanf, length=5))


    sm = p.factory.simulation_manager(init)

    # Now stuff becomes interesting
    ex = sm.explore(find=find, avoid=avoid)

    print(ex)
    s = ex.found[0]
    flag = s.solver.eval(s.memory.load(flag_addr, 50), cast_to=str)

    # The flag is 'Math is hard!'
    print("The flag is '{0}'".format(flag))
    return flag

def test():
    res = main()
    printable = set(string.printable)
    res = filter(lambda x: x in printable, res)
    assert res == "Math is hard!"

if __name__ in '__main__':
    print(main())

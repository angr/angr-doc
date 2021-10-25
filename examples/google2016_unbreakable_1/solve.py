#!/usr/bin/env python2

"""
In this challenge we are given a binary that checks an input given as a
command line argument. If it is correct, 'Thank you - product activated!' is
printed. If it is incorrect, 'Product activation failure %d' is printed with a
specific error code.

Reversing shows that the program verifies that various operations on specific 
characters of input are equal to zero. Because of the program's linear nature
and reliance on verbose constraints, angr is perfect for solving this challenge
quickly. On a virtual machine, it took ~7 seconds to solve.

Author: scienceman (@docileninja)
Team: bitsforeveryone (USMA)
"""

import angr


START_ADDR = 0x4005bd # first part of program that does computation
AVOID_ADDR = 0x400850 # address of function that prints wrong
FIND_ADDR = 0x400830 # address of function that prints correct
INPUT_ADDR = 0x6042c0 # location in memory of user input
INPUT_LENGTH = 0xf2 - 0xc0 + 1 # derived from the first and last character
                               # reference in data

def extract_memory(state):
    """Convience method that returns the flag input memory."""
    return state.solver.eval(state.memory.load(INPUT_ADDR, INPUT_LENGTH), cast_to=bytes)

def char(state, n):
    """Returns a symbolic BitVector and contrains it to printable chars for a given state."""
    vec = state.solver.BVS('c{}'.format(n), 8, explicit_name=True)
    return vec, state.solver.And(vec >= ord(' '), vec <= ord('~'))

def main():
    p = angr.Project('unbreakable', auto_load_libs=False)

    print('adding BitVectors and constraints')
    state = p.factory.blank_state(addr=START_ADDR, add_options={angr.options.LAZY_SOLVES})
    for i in range(INPUT_LENGTH):
        c, cond = char(state, i)
        # the first command line argument is copied to INPUT_ADDR in memory
        # so we store the BitVectors for angr to manipulate
        state.memory.store(INPUT_ADDR + i, c)
        state.add_constraints(cond)

    print('creating simgr')
    ex = p.factory.simulation_manager(state)

    print('running explorer')
    ex.explore(find=(FIND_ADDR,), avoid=(AVOID_ADDR,))

    flag = extract_memory(ex.one_found) # ex.one_found is equiv. to ex.found[0]
    print('found flag: {}'.format(flag))

    return flag

def test():
    assert main() == b'CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}'

if __name__ == '__main__':
    main()

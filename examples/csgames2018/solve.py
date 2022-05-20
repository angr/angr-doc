#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# CS Games 2018

'''
Reverse #6: KeygenMe

The task is simple. Reverse the key generation algorithm to make a working key generator.

Provide 100 valid keys in a file named Keys.txt.
'''

import angr, claripy
import logging
logging.getLogger('angr.manager').setLevel(logging.DEBUG)

# Used for troubleshooting
# import IPython
# logging.getLogger('angr').setLevel(logging.DEBUG)

def main():
    project = angr.Project('./KeygenMe', load_options={"auto_load_libs": False})

    def correct(state):
        try:
            return b'correct!' in state.posix.dumps(1)
        except Exception as e:
            return False

    def wrong(state):
        try:
            return b'incorrect' in state.posix.dumps(1)
        except Exception as e:
            return False

    input_key = claripy.BVS("input_key", 16*8) # As seen in 0x699, keys are 0x10 (16) characters long.

    state = project.factory.entry_state(args=["./KeygenMe", input_key], add_options=angr.options.unicorn) # Unicorn Engine is not needed, but will speed up the process

    simulation_manager = project.factory.simulation_manager(state)

    # (•_•) ( •_•)>⌐■-■ (⌐■_■)
    simulation_manager.explore(find=correct, avoid=wrong) # We could alternatively use addresses here, like find=0x400000 + 0x8f3.

    # For troubleshooting/development, drop into IPython
    # IPython.embed()

    found = simulation_manager.found[-1]

    # At this point, we've actually found "correct" flags, but they contain symbols that probably aren't on all keyboards. Ideally we only want to find alphanumeric keys.

    def is_alphanumeric(state, byte):
        is_num = state.solver.And(byte >= b"0", byte <= b"9")
        is_alpha_lower = state.solver.And(byte >= b"a", byte <= b"z")
        is_alpha_upper = state.solver.And(byte >= b"A", byte <= b"Z")
        return state.solver.Or(is_num, is_alpha_lower, is_alpha_upper)

    # XXXX-XX-XXX-XXXX
    for i in list(range(0, 4)) + list(range(5, 7)) + list(range(8, 11)) + list(range(12, 16)):
        found.add_constraints(is_alphanumeric(found, input_key.chop(8)[i]))

    min_solutions = found.solver.min(input_key)

    keys = found.solver.eval_atleast(input_key, 100, cast_to=bytes)

    print("We found at least " + str(min_solutions) + " keys! The Recording Industry Association of Space Penguins says their entire galaxy is now bankrupt, so we might as well have 100 of their keys:")

    for key in keys:
        print(key)

    return min_solutions

def test():
    assert main() >= 100

if __name__ == '__main__':
    main()

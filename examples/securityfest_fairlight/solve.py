#!/usr/bin/python

"""
Author: chuckleberryfinn
Security Fest 2016
Challenge: fairlight (250)

Runtime: ~1 minute

Simple solution, requires 0 knowledge of the check functions.
"""

import angr
import claripy

def main():
    proj = angr.Project('./fairlight', load_options={"auto_load_libs": False})
    argv1 = claripy.BVS("argv1", 0xE * 8)
    initial_state = proj.factory.entry_state(args=["./fairlight", argv1]) 

    sm = proj.factory.simulation_manager(initial_state)
    sm.explore(find=0x4018f7, avoid=0x4018f9)
    found = sm.found[0]
    return found.solver.eval(argv1, cast_to=str)


def test():
    res = main()
    print repr(res)
    assert res == '4ngrman4gem3nt'


if __name__ == '__main__':
    main()

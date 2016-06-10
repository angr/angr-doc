#!/usr/bin/python

"""
Author: chuckleberryfinn
Security Fest 2016
Challenge: fairlight (250)

Runtime: ~1 minute

Simple solution, requires 0 knowledge of the check functions.
"""

import angr

def main():
    proj = angr.Project('./fairlight', load_options={"auto_load_libs": False})
    argv1 = angr.claripy.BVS("argv1", 0xE * 8)
    initial_state = proj.factory.entry_state(args=["./fairlight", argv1]) 

    initial_path = proj.factory.path(initial_state)
    path_group = proj.factory.path_group(initial_state)
    path_group.explore(find=0x4018f7, avoid=0x4018f9)
    found = path_group.found[0]
    return found.state.se.any_str(argv1)


def test():
    assert '4ngrman4gem3nt' == main()


if __name__ == '__main__':
    main()
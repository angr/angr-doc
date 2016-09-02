#!/usr/bin/python

import angr

import os
import psutil
import ipdb
import logging

def main():
    process = psutil.Process(os.getpid())

    p = angr.Project('./issue', load_options={"auto_load_libs": False})

    state = p.factory.entry_state(add_options={"SYMBOLIC_WRITE_ADDRESSES"})

    u = angr.claripy.BVS("u", 8)
    state.memory.store(0x804a021, u)

    initial_path = p.factory.path(state)

    pg = p.factory.path_group(state)
    pg.explore(find=0x80484e3, avoid=0x80484f5)

    if pg.found:
        print "found!"
        print "%d" % pg.found[0].state.se.any_int(u)
    else:
        print "no paths found"

    return

if __name__ == '__main__':
    main()

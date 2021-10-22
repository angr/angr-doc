#!/usr/bin/env python2

"""
In this challenge we're given a text file with trace of a program execution. The file has
two columns, address and instruction executed. So we know all the instructions being executed,
and which branches were taken. But the initial data is not known.

Reversing reveals that a buffer on the stack is initialized with known constant string first,
then an unknown string is appended to it (the flag), and finally it's sorted with some
variant of quicksort. And we need to find the flag somehow.

angr easily solves this problem. We only have to direct it to the right direction
at every branch, and solver finds the flag at a glance.
"""

from __future__ import print_function

import struct

import angr

MAIN_START = 0x4009d4
MAIN_END = 0x00400c18

FLAG_LOCATION = 0x400D80
FLAG_PTR_LOCATION = 0x410EA0

def load_trace():
    res = []
    delay_slots = set()
    with open("./trace_8339a701aae26588966ad9efa0815a0a.log") as f:
        for line in f:
            if line.startswith('[INFO]'):
                addr = int(line[6:6+8], 16)

                res.append(addr)

                # every command like this is in delay slot
                # (in this particular binary)
                if ("move r1, r1" in line):
                    delay_slots.add(addr)

    return res, delay_slots

def main():
    trace_log, delay_slots = load_trace()

    # data.bin is simply the binary assembled from trace,
    # starting on 0x400770
    project = angr.Project("./data.bin", load_options={
        'main_opts': {
            'backend': 'blob',
            'base_addr': 0x400770,
            'arch': 'mipsel',
        },
        }, auto_load_libs=False)

    state = project.factory.blank_state(addr=MAIN_START)
    state.memory.store(FLAG_LOCATION, state.solver.BVS("flag", 8*32))
    state.memory.store(FLAG_PTR_LOCATION, struct.pack("<I", FLAG_LOCATION))

    sm = project.factory.simulation_manager(state)
    choices = [state]

    print("Tracing...")
    for i, addr in enumerate(trace_log):
        if addr in delay_slots:
            continue

        for s in choices:
            if s.addr == addr:
                break

        else:
            raise ValueError("couldn't advance to %08x, line %d" % (addr, i+1))

        if s.addr == MAIN_END:
            break

        # if command is a jump, it's followed by a delay slot
        # we need to advance by two instructions
        # https://github.com/angr/angr/issues/71
        if s.addr + 4 in delay_slots:
            choices = project.factory.successors(s, num_inst=2).successors
        else:
            choices = project.factory.successors(s, num_inst=1).successors

    state = s

    print("Running solver...")

    solution = state.solver.eval(state.memory.load(FLAG_LOCATION, 32), cast_to=bytes).rstrip(b'\0').decode('ascii')
    print("The flag is", solution)

    return solution

def test():
    assert main() == "0ctf{tr135m1k5l96551s9l5r}"

if __name__ == "__main__":
    main()

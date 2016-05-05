#!/usr/bin/env python

# Author: David Manouchehri <manouchehri@protonmail.com>
# Google 2016 CTF
# Challenge: Unbreakable Enterprise Product Activation

import angr

def main():
    proj = angr.Project('./unbreakable-enterprise-product-activation', load_options={"auto_load_libs": False}) # Disabling the automatic library loading saves a few milliseconds.

    input_size = 0x43; # Max length from strncpy, see 0x4005ae.

    argv1 = angr.claripy.BVS("argv1", input_size * 8) # 

    initial_state = proj.factory.entry_state(args=["./unbreakable-enterprise-product-activation", argv1]) 
    initial_state.libc.buf_symbolic_bytes=input_size + 1 # Thanks to @salls for pointing this out.

    # For some reason if you constrain less bytes, the solution isn't found. To be safe, I'm constraining them all.
    for byte in argv1.chop(8):
        initial_state.add_constraints(byte != '\x00')

    # We're told that every flag starts with "CTF", so we might as well use that information to save processing time. 
    initial_state.add_constraints(argv1.chop(8)[0] == '\x43') # C
    initial_state.add_constraints(argv1.chop(8)[1] == '\x54') # T
    initial_state.add_constraints(argv1.chop(8)[2] == '\x46') # F

    initial_path = proj.factory.path(initial_state)
    path_group = proj.factory.path_group(initial_state)

    # 0x4005AA = starting of 'good' function
    # 0x400830 = thank you message
    # 0x400850 = activation failure

    path_group.explore(find=0x400830, avoid=0x400850)

    found = path_group.found[0]

    solution = found.state.se.any_str(argv1)
    solution = solution[:solution.find("}")+1]
    return solution

def test():
    assert main() == 'CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}'

if __name__ == '__main__':
    print(repr(main()))


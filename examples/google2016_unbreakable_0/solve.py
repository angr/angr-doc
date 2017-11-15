#!/usr/bin/env python2

# Author: David Manouchehri <manouchehri@protonmail.com>
# Google 2016 CTF
# Challenge: Unbreakable Enterprise Product Activation
# Team: hack.carleton (http://hack.carleton.team/)
# Runtime: ~4.5 seconds (single threaded E5-2666 v3 @ 2.90GHz on AWS/EC2)

import angr

import claripy

def main():
    proj = angr.Project('./unbreakable-enterprise-product-activation', load_options={"auto_load_libs": False}) # Disabling the automatic library loading saves a few milliseconds.

    input_size = 0x43; # Max length from strncpy, see 0x4005ae.

    argv1 = claripy.BVS("argv1", input_size * 8)

    initial_state = proj.factory.entry_state(args=["./unbreakable-enterprise-product-activation", argv1], add_options={angr.options.LAZY_SOLVES})
    initial_state.libc.buf_symbolic_bytes=input_size + 1 # Thanks to Christopher Salls (@salls) for pointing this out. By default there's only 60 symbolic bytes, which is too small.

    # For some reason if you constrain too few bytes, the solution isn't found. To be safe, I'm constraining them all.
    for byte in argv1.chop(8):
        initial_state.add_constraints(byte != '\x00') # null
        initial_state.add_constraints(byte >= ' ') # '\x20'
        initial_state.add_constraints(byte <= '~') # '\x7e'
        # Source: https://www.juniper.net/documentation/en_US/idp5.1/topics/reference/general/intrusion-detection-prevention-custom-attack-object-extended-ascii.html
        # Thanks to Tom Ravenscroft (@tomravenscroft) for showing me how to restrict to printable characters.

    # We're told that every flag is formatted as "CTF{...}", so we might as well use that information to save processing time. 
    initial_state.add_constraints(argv1.chop(8)[0] == 'C')
    initial_state.add_constraints(argv1.chop(8)[1] == 'T')
    initial_state.add_constraints(argv1.chop(8)[2] == 'F')
    initial_state.add_constraints(argv1.chop(8)[3] == '{')
    # angr will still find the solution without setting these, but it'll take a few seconds more.

    sm = proj.factory.simulation_manager(initial_state)

                          # 0x400830 = thank you message
    sm.explore(find=0x400830, avoid=0x400850)
                                          # 0x400850 = activation failure

    found = sm.found[0] # In our case, there's only one printable solution.

    solution = found.solver.eval(argv1, cast_to=str)
    solution = solution[:solution.find("}")+1] # Trim off the null bytes at the end of the flag (if any).
    return solution

def test():
    assert main() == 'CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}'

if __name__ == '__main__':
    print(repr(main()))


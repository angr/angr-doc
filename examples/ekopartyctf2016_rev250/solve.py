#!/usr/bin/env python2

"""
In this challenge we are given a binary that checks an input given from stdin.
If it is correct, it will call get_flag in a separate library and print it.
However, we don't have the library so need to find the correct input and input
it over netcat. If it is incorrect, only 'Goodbye' is printed.

Reversing shows that the program verifies the input character by character.]
Because of the program's linear nature and reliance on verbose constraints, 
angr is perfect for solving this challenge quickly. On a virtual machine
with one core and 4 GB of RAM, it took ~26 seconds to solve.

Author: scienceman (@docileninja)
Team: PPP (CMU)
"""

import angr

START = 0x400B30 # start of main
FIND = 0x403A40 # part of program that prints the flag
AVOID = [0x403A7E + i * 60 for i in range(100)] # all addresses after a failed check occur on a fixed interval

BUF_LEN = 100

def char(state, c):
    '''returns constraints s.t. c is printable'''
    return state.solver.And(c <= '~', c >= ' ')

def main():
    p = angr.Project('FUck_binary')

    print('creating state')
    state = p.factory.blank_state(addr=START)

    print('adding constaints to stdin')
    for i in range(BUF_LEN):
        c = state.posix.files[0].read_from(1)
        state.solver.add(char(state, c))

    # even though we mark stdin as 100 long angr can still chose to cut it off 
    state.posix.files[0].seek(0)
    state.posix.files[0].length = 100

    print('creating path and explorer')
    ex = p.surveyors.Explorer(start=state, find=FIND, avoid=AVOID)

    print('running explorer')
    ex.run()

    print('found solution')
    correct_input = ex._f.posix.dumps(0) # ex._f is equiv. to ex.found[0]

    # we didn't know how long the input had to be except < 100 bytes
    team_name = correct_input[:correct_input.index('\x00')]

    print('found correct input/team name: {}'.format(repr(team_name)))

    return team_name

def test():
    team = '@@@(h@@@@f@v@ @@/@vCo@&D@ACHP@@@@@@@@D@@ @X@@@@@B@h@]@@@W@UB@"(@Lq@@@@@,FBtH@?6@@" * k[Q@@@@@@@@@I@@'
    import subprocess
    p = subprocess.Popen(["./FUck_binary"], env={"LD_LIBRARY_PATH": "."}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(input=team + "\n")
    assert "BOOM" in out

if __name__ == '__main__':
    main()

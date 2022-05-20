#!/usr/bin/env python3
from __future__ import print_function

# Authors: David Manouchehri <manouchehri@protonmail.com>
#          P1kachu <p1kachu@lse.epita.fr>
#          Audrey Dutcher <audrey@rhelmot.io>
# DEFCON CTF Qualifier 2016
# Challenge: baby-re
# Write-up: http://hack.carleton.team/2016/05/21/defcon-ctf-qualifier-2016-baby-re/
# Runtime: ~15 seconds (thanks lazy solves!)

import angr
import claripy

def main():
    proj = angr.Project('./baby-re', auto_load_libs=False)

    # let's provide the exact variables received through the scanf so we don't have to worry about parsing stdin into a bunch of ints.
    flag_chars = [claripy.BVS('flag_%d' % i, 32) for i in range(13)]
    class my_scanf(angr.SimProcedure):
        def run(self, fmt, ptr): # pylint: disable=arguments-differ,unused-argument
            self.state.mem[ptr].dword = flag_chars[self.state.globals['scanf_count']]
            self.state.globals['scanf_count'] += 1

    proj.hook_symbol('__isoc99_scanf', my_scanf(), replace=True)

    sm = proj.factory.simulation_manager()
    sm.one_active.options.add(angr.options.LAZY_SOLVES)
    sm.one_active.globals['scanf_count'] = 0

    # search for just before the printf("%c%c...")
    # If we get to 0x402941, "Wrong" is going to be printed out, so definitely avoid that.
    sm.explore(find=0x4028E9, avoid=0x402941)

    # evaluate each of the flag chars against the constraints on the found state to construct the flag
    flag = ''.join(chr(sm.one_found.solver.eval(c)) for c in flag_chars)
    return flag

def test():
    assert main() == 'Math is hard!'

if __name__ == '__main__':
    print(main())

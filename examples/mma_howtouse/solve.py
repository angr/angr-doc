#!/usr/bin/env python

#
# This binary, from the MMA CTF, was a simple reversing challenge. THe biggest
# challenge was actually *running* this library in Windows. Luckily, with angr,
# we can avoid having to do this!
#
# The approach here is to use angr as a concrete execution engine to call the
# `howtouse` function 45 times, as the array of function pointers in that
# function has 45 entries. The result turned out to be the flag.
#

import angr
import claripy

def main():
    # Load the binary. Base addresses are weird when loading binaries directly, so
    # we specify it explicitly.
    p = angr.Project('howtouse.dll', load_options={'main_opts': {'base_addr': 0x10000000}}, auto_load_libs=False)

    # A "Callable" is angr's FFI-equivalent. It allows you to call binary functions
    # from Python. Here, we use it to call the `howtouse` function.
    howtouse = p.factory.callable(0x10001130)

    # In this binary, the result is a concrete char, so we don't need a symbolic
    # state or a solver to get its value.
    getch = lambda i: chr(claripy.backends.concrete.convert(howtouse(i)).value)

    # Let's call this 45 times, and that's the result!
    return ''.join(getch(i) for i in range(45))

def test():
    assert main() == 'MMA{fc7d90ca001fc8712497d88d9ee7efa9e9b32ed8}'

if __name__ == '__main__':
    print(main())

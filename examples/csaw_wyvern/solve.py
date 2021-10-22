#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time

def main():
    # Load the binary. This is a 64-bit C++ binary, pretty heavily obfuscated.
    # its correct emulation by angr depends heavily on the libraries it is loaded with,
    # so if this script fails, try copying to this dir the .so files from our binaries repo:
    # https://github.com/angr/binaries/tree/master/tests/x86_64
    p = angr.Project('wyvern', auto_load_libs=True)

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline. Let's construct a value of several
    # symbols that we can add constraints on once we have a state.

    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(28)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The full_init_state
    # will do that. In order to do this peformantly, we will use the unicorn engine!
    st = p.factory.full_init_state(
            args=['./wyvern'],
            add_options=angr.options.unicorn,
            stdin=flag,
    )

    # Constrain the first 28 bytes to be non-null and non-newline:
    for k in flag_chars:
        st.solver.add(k != 0)
        st.solver.add(k != 10)

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)
    sm.run()

    # Get the stdout of every path that reached an exit syscall. The flag should be in one of these!
    out = b''
    for pp in sm.deadended:
        out = pp.posix.dumps(1)
        if b'flag{' in out:
            return next(filter(lambda s: b'flag{' in s, out.split()))

    # Runs in about 15 minutes!

def test():
    assert main() == b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))

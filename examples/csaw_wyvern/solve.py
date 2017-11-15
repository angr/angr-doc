#!/usr/bin/env python
# coding: utf-8
import angr
import time

def main():
    # Load the binary. This is a 64-bit C++ binary, pretty heavily obfuscated.
    p = angr.Project('wyvern')

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The full_init_state
    # will do that. In order to do this peformantly, we will use the unicorn engine!
    st = p.factory.full_init_state(args=['./wyvern'], add_options=angr.options.unicorn)

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline.

    # Constrain the first 28 bytes to be non-null and non-newline:
    for _ in xrange(28):
        k = st.posix.files[0].read_from(1)
        st.solver.add(k != 0)
        st.solver.add(k != 10)

    # Constrain the last byte to be a newline
    k = st.posix.files[0].read_from(1)
    st.solver.add(k == 10)

    # Reset the symbolic stdin's properties and set its length.
    st.posix.files[0].seek(0)
    st.posix.files[0].length = 29

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)
    sm.run()

    # Get the stdout of every path that reached an exit syscall. The flag should be in one of these!
    out = ''
    for pp in sm.deadended:
        out = pp.posix.dumps(1)
        if 'flag{' in out:
            return filter(lambda s: 'flag{' in s, out.split())[0]

    # Runs in about 15 minutes!

def test():
    assert main() == 'flag{dr4g0n_or_p4tric1an_it5_LLVM}'

if __name__ == "__main__":
    before = time.time()
    print main()
    after = time.time()
    print "Time elapsed: {}".format(after - before)

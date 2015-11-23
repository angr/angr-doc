#!/usr/bin/env python
# coding: utf-8
import angr

def main():
    # Load the binary. This is a 64-bit C++ binary, pretty heavily obfuscated.
    p = angr.Project('wyvern')

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The full_init_state
    # will do that.
    st = p.factory.full_init_state(args=['./wyvern'])

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline.

    # Constrain the first 28 bytes to be non-null and non-newline:
    for _ in xrange(28):
        k = st.posix.files[0].read_from(1)
        st.se.add(k != 0)
        st.se.add(k != 10)

    # Constrain the last byte to be a newline
    k = st.posix.files[0].read_from(1)
    st.se.add(k == 10)

    # Reset the symbolic stdin's properties and set its length.
    st.posix.files[0].seek(0)
    st.posix.files[0].length = 29

    # Construct a path group to perform symbolic execution.
    # Step the program though 100000 basic blocks (it will not actually get to run
    # that many blocks, all the paths will deadend before that).
    # The step_func argument is run after each step, and instructs the program to
    # check that each state is satisfiable and prune the ones that aren't if there's more
    # than one state active.
    pg = p.factory.path_group(st, immutable=False)
    pg.step(step_func=lambda lpg: lpg if len(lpg.active) == 1 else lpg.prune(), n=100000)

    # Get the stdout of every path that reached an exit syscall. The flag should be in one of these!
    out = ''
    for pp in pg.deadended:
        out = pp.state.posix.dumps(1)
        if 'flag{' in out:
            return filter(lambda s: 'flag{' in s, out.split())[0]

    # Runs in about 15 minutes!

def test():
    assert main() == 'flag{dr4g0n_or_p4tric1an_it5_LLVM}'

if __name__ == "__main__":
    print main()

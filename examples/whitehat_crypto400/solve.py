#!/usr/bin/env python

'''
This is an example that uses angr to assist in solving a crackme, given as
a 400-level crypto challenge in WhitehatCTF in 2015. In this example, angr is
used to reduce the keyspace, allowing for a reasonable brute-force.
'''

# lots of imports
import logging
import itertools
import subprocess
import progressbar

import angr
import claripy

def get_possible_flags():
    # load the binary
    print('[*] loading the binary')
    p = angr.Project("whitehat_crypto400", auto_load_libs=False)

    # this is a statically-linked binary, and it's easer for angr if we use Python
    # summaries for the libc functions
    p.hook(0x4018B0, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())
    p.hook(0x422690, angr.SIM_PROCEDURES['libc']['memcpy']())
    p.hook(0x408F10, angr.SIM_PROCEDURES['libc']['puts']())

    # this is some anti-debugging initialization. It doesn't do much against angr,
    # but wastes time
    p.hook(0x401438, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    # from playing with the binary, we can easily see that it requires strings of
    # length 8, so we'll hook the strlen calls and make sure we pass an 8-byte
    # string
    def hook_length(state):
        state.regs.rax = 8
    p.hook(0x40168e, hook_length, length=5)
    p.hook(0x4016BE, hook_length, length=5)

    # here, we create the initial state to start execution. argv[1] is our 8-byte
    # string, and we add an angr option to gracefully handle unsupported syscalls
    arg1 = claripy.BVS('arg1', 8*8)
    initial_state = p.factory.entry_state(args=["crypto400", arg1], add_options={"BYPASS_UNSUPPORTED_SYSCALL"})

    # and let's add a constraint that none of the string's bytes can be null
    for b in arg1.chop(8):
        initial_state.add_constraints(b != 0)

    # Simulation managers are a basic building block of the symbolic execution engine.
    # They track a group of states as the binary is executed, and allows for easier
    # management, pruning, and so forth of those states
    sm = p.factory.simulation_manager(initial_state)

    # here, we get to stage 2 using the simulation manager's explore() functionality.
    # This executes until at least one path reaches the specified address, and can
    # discard paths that hit certain other addresses.
    print('[*] executing')
    sm.explore(find=0x4016A3).unstash(from_stash='found', to_stash='active')
    sm.explore(find=0x4016B7, avoid=[0x4017D6, 0x401699, 0x40167D]).unstash(from_stash='found', to_stash='active')
    sm.explore(find=0x4017CF, avoid=[0x4017D6, 0x401699, 0x40167D]).unstash(from_stash='found', to_stash='active')
    sm.explore(find=0x401825, avoid=[0x401811])

    # now, we're at stage 2. stage 2 is too complex for a SAT solver to solve, but
    # stage1 has narrowed down the keyspace enough to brute-force the rest, so
    # let's get the possible values for the passphrase and brute-force the rest.
    s = sm.found[0]

    # to reduce the keyspace further, let's assume the bytes are printable
    for i in range(8):
        b = s.memory.load(0x6C4B20 + i, 1)
        s.add_constraints(b >= 0x21, b <= 0x7e)

    # now get the possible values. One caveat is that getting all possible values
    # for all 8 bytes pushes a lot of complexity to the SAT solver, and it chokes.
    # To avoid this, we're going to get the solutions to 2 bytes at a time, and
    # brute force the combinations.
    possible_values = [ s.solver.eval_upto(s.memory.load(0x6C4B20 + i, 2), 65536, cast_to=bytes) for i in range(0, 8, 2) ]
    possibilities = tuple(itertools.product(*possible_values))
    return possibilities

def bruteforce_possibilities(possibilities):
    # let's try those values!
    print('[*] example guess: %r' % b''.join(possibilities[0]))
    print('[*] brute-forcing %d possibilities' % len(possibilities))
    for guess in progressbar.ProgressBar(widgets=[progressbar.Counter(), ' ', progressbar.Percentage(), ' ', progressbar.Bar(), ' ', progressbar.ETA()])(possibilities):
        guess_str = b''.join(guess)
        stdout,_ = subprocess.Popen(["./whitehat_crypto400", guess_str.decode("ascii")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
        if b'FLAG IS' in stdout:
            return next(filter(lambda s: guess_str in s, stdout.split()))

def main():
    return bruteforce_possibilities(get_possible_flags())

def test():
    assert b'nytEaTBU' in [ b''.join(p) for p in get_possible_flags() ]

if __name__ == '__main__':
    # set some debug messages so that we know what's going on
    logging.getLogger('angr.sim_manager').setLevel('DEBUG')
    print(main())

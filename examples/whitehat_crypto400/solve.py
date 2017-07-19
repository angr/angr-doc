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

from angr.procedures.stubs.UserHook import UserHook

def get_possible_flags():
    # load the binary
    print '[*] loading the binary'
    p = angr.Project("whitehat_crypto400")

    # this is a statically-linked binary, and it's easer for angr if we use Python
    # summaries for the libc functions
    p.hook(0x4018B0, angr.SIM_PROCEDURES['glibc']['__libc_start_main'])
    p.hook(0x422690, angr.SIM_PROCEDURES['libc']['memcpy'])
    p.hook(0x408F10, angr.SIM_PROCEDURES['libc']['puts'])

    # this is some anti-debugging initialization. It doesn't do much against angr,
    # but wastes time
    p.hook(0x401438, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](resolves='nothing'))
    # from playing with the binary, we can easily see that it requires strings of
    # length 8, so we'll hook the strlen calls and make sure we pass an 8-byte
    # string
    def hook_length(state):
        state.regs.rax = 8
    p.hook(0x40168e, UserHook(user_func=hook_length, length=5))
    p.hook(0x4016BE, UserHook(user_func=hook_length, length=5))

    # here, we create the initial state to start execution. argv[1] is our 8-byte
    # string, and we add an angr option to gracefully handle unsupported syscalls
    arg1 = claripy.BVS('arg1', 8*8)
    initial_state = p.factory.entry_state(args=["crypto400", arg1], add_options={"BYPASS_UNSUPPORTED_SYSCALL"})

    # and let's add a constraint that none of the string's bytes can be null
    for b in arg1.chop(8):
        initial_state.add_constraints(b != 0)

    # PathGroups are a basic building block of the symbolic execution engine. They
    # track a group of paths as the binary is executed, and allows for easier
    # management, pruning, and so forth of those paths
    sm = p.factory.simgr(initial_state, immutable=False)

    # here, we get to stage 2 using the PathGroup's find() functionality. This
    # executes until at least one path reaches the specified address, and can
    # discard paths that hit certain other addresses.
    print '[*] executing'
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
    possible_values = [ s.se.any_n_str(s.memory.load(0x6C4B20 + i, 2), 65536) for i in range(0, 8, 2) ]
    possibilities = tuple(itertools.product(*possible_values))
    return possibilities

def bruteforce_possibilities(possibilities):
    # let's try those values!
    print '[*] example guess: %r' % ''.join(possibilities[0])
    print '[*] brute-forcing %d possibilities' % len(possibilities)
    for guess in progressbar.ProgressBar(widgets=[progressbar.Counter(), ' ', progressbar.Percentage(), ' ', progressbar.Bar(), ' ', progressbar.ETA()])(possibilities):
        stdout,_ = subprocess.Popen(["./whitehat_crypto400", ''.join(guess)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
        if 'FLAG IS' in stdout:
            return filter(lambda s: ''.join(guess) in s, stdout.split())[0]

def main():
    return bruteforce_possibilities(get_possible_flags())

def test():
    assert 'nytEaTBU' in [ ''.join(p) for p in get_possible_flags() ]

if __name__ == '__main__':
    # set some debug messages so that we know what's going on
    logging.basicConfig()
    angr.manager.l.setLevel('DEBUG')

    print main()

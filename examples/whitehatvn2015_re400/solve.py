#import logging
#logging.getLogger('angr.surveyor').setLevel(logging.DEBUG)

import angr
import simuvex

def patch_0(state):
    pass

def get_byte(s, i):
    pos = s.size() / 8 - 1 - i
    return s[pos * 8 + 7 : pos * 8]

def main():
    p = angr.Project("re400.exe")

    # Patch out the part that is difficult for angr to solve
    p.hook(0x401f7e, patch_0, length=0x4028dd-0x401f7e)
    p.hook(0x402b5d, patch_0, length=0x402b91-0x402b5d)

    state = p.factory.blank_state(addr=0x401f30, remove_options={simuvex.s_options.LAZY_SOLVES})
    argv=['re400.exe', state.se.BVS('arg1', 37 * 8)]


    # Add previous conditions got from debugging the part of code that is patched out
    state.add_constraints(get_byte(argv[1], 0) >= get_byte(argv[1], 1))
    state.add_constraints(get_byte(argv[1], 0) ^ get_byte(argv[1], 1) == 0x1f)
    state.add_constraints(get_byte(argv[1], 4) <= get_byte(argv[1], 5))
    state.add_constraints(get_byte(argv[1], 4) ^ get_byte(argv[1], 5) == 0x67)
    state.add_constraints(get_byte(argv[1], 8) >= get_byte(argv[1], 9))
    state.add_constraints(get_byte(argv[1], 8) ^ get_byte(argv[1], 9) == 0x5a)
    state.add_constraints(get_byte(argv[1], 34) <= get_byte(argv[1], 35))
    state.add_constraints(get_byte(argv[1], 34) ^ get_byte(argv[1], 35) == 0x8)
    state.add_constraints(get_byte(argv[1], 10) <= get_byte(argv[1], 11))
    state.add_constraints(get_byte(argv[1], 10) ^ get_byte(argv[1], 11) == 0x6b)
    state.add_constraints(get_byte(argv[1], 6) >= get_byte(argv[1], 7))
    state.add_constraints(get_byte(argv[1], 6) ^ get_byte(argv[1], 7) == 0xd)
    state.add_constraints(get_byte(argv[1], 2) <= get_byte(argv[1], 3))
    state.add_constraints(get_byte(argv[1], 2) ^ get_byte(argv[1], 3) == 0x34)
    state.add_constraints(get_byte(argv[1], 32) >= get_byte(argv[1], 33))
    state.add_constraints(get_byte(argv[1], 32) ^ get_byte(argv[1], 33) == 0x1e)

    for i in xrange(36):
        # We want those flags to be printable characters
        state.add_constraints(get_byte(argv[1], i) >= 0x20)
        state.add_constraints(get_byte(argv[1], i) <= ord('}'))
    state.add_constraints(get_byte(argv[1], 36) == 0)

    # Prepare the argc and argv
    state.memory.store(0xd0000000, argv[0]) # content of argv[0], which is the executable name
    state.memory.store(0xd0000010, argv[1]) # content of argv[1], which is our flag
    state.stack_push(0xd0000010) # pointer to argv[1]
    state.stack_push(0xd0000000) # pointer to argv[0]
    state.stack_push(state.regs.esp) # argv
    state.stack_push(2) # argc
    state.stack_push(0x401f30) # address of main

    state.memory.store(0x413ad4, 36, endness=state.arch.memory_endness)

    path = p.factory.path(state=state)

    ex = p.surveyors.Explorer(
        start=path,
        find=(0x402f29,),
        avoid=(0x402f3f,),
    )
    ex.run()

    possible_flags = ex.found[0].state.se.any_n_int(argv[1], 20)
    for i, f in enumerate(possible_flags):
        print "Flag %d:" % i, hex(f)[2:-1].decode("hex")

    return [hex(f)[2:-1].decode("hex") for f in possible_flags]


def test():
    # Since there are multiple solutions, we just do some basic checks
    # on the format of the solutions
    res = main()
    assert len(res) == 20
    for f in res:
        f = f[:f.find("\x00")]
        assert len(f) == 36
        assert all([ord(c) >= 0x20 and ord(c) <= ord("}") for c in f])

if __name__ == "__main__":
    main()


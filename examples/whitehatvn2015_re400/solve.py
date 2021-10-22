#import logging

import angr

def patch_0(state):
    pass


def main():
    p = angr.Project("re400.exe", auto_load_libs=False)

    # Patch out the part that is difficult for angr to solve
    p.hook(0x401f7e, patch_0, length=0x4028dd-0x401f7e)
    p.hook(0x402b5d, patch_0, length=0x402b91-0x402b5d)

    state = p.factory.blank_state(addr=0x401f30)
    argv=[b're400.exe', state.solver.BVS('arg1', 37 * 8)]


    # Add previous conditions got from debugging the part of code that is patched out
    state.add_constraints(argv[1].get_byte(0) >= argv[1].get_byte(1))
    state.add_constraints(argv[1].get_byte(0) ^ argv[1].get_byte(1) == 0x1f)
    state.add_constraints(argv[1].get_byte(4) <= argv[1].get_byte(5))
    state.add_constraints(argv[1].get_byte(4) ^ argv[1].get_byte(5) == 0x67)
    state.add_constraints(argv[1].get_byte(8) >= argv[1].get_byte(9))
    state.add_constraints(argv[1].get_byte(8) ^ argv[1].get_byte(9) == 0x5a)
    state.add_constraints(argv[1].get_byte(34) <= argv[1].get_byte(35))
    state.add_constraints(argv[1].get_byte(34) ^ argv[1].get_byte(35) == 0x8)
    state.add_constraints(argv[1].get_byte(10) <= argv[1].get_byte(11))
    state.add_constraints(argv[1].get_byte(10) ^ argv[1].get_byte(11) == 0x6b)
    state.add_constraints(argv[1].get_byte(6) >= argv[1].get_byte(7))
    state.add_constraints(argv[1].get_byte(6) ^ argv[1].get_byte(7) == 0xd)
    state.add_constraints(argv[1].get_byte(2) <= argv[1].get_byte(3))
    state.add_constraints(argv[1].get_byte(2) ^ argv[1].get_byte(3) == 0x34)
    state.add_constraints(argv[1].get_byte(32) >= argv[1].get_byte(33))
    state.add_constraints(argv[1].get_byte(32) ^ argv[1].get_byte(33) == 0x1e)

    for i in range(36):
        # We want those flags to be printable characters
        state.add_constraints(argv[1].get_byte(i) >= 0x20)
        state.add_constraints(argv[1].get_byte(i) <= 0x7e)
    state.add_constraints(argv[1].get_byte(36) == 0)

    # Prepare the argc and argv
    state.memory.store(0xd0000000, argv[0]) # content of argv[0], which is the executable name
    state.memory.store(0xd0000010, argv[1]) # content of argv[1], which is our flag
    state.stack_push(0xd0000010) # pointer to argv[1]
    state.stack_push(0xd0000000) # pointer to argv[0]
    state.stack_push(state.regs.esp) # argv
    state.stack_push(2) # argc
    state.stack_push(0x401f30) # address of main

    state.memory.store(0x413ad4, 36, size=state.arch.bytes, endness=state.arch.memory_endness)

    ex = p.factory.simulation_manager(state)
    ex.explore(find=0x402f29, avoid=0x402f3f)

    possible_flags = ex.found[0].solver.eval_upto(argv[1], 20, cast_to=bytes)
    for i, f in enumerate(possible_flags):
        print("Flag %d:" % i, f)

    return possible_flags


def test():
    # Since there are multiple solutions, we just do some basic checks
    # on the format of the solutions
    res = main()
    assert len(res) == 20
    for f in res:
        f = f[:f.find(b"\x00")]
        assert len(f) == 36
        assert all(20 <= c <= 0x7e for c in f)

if __name__ == "__main__":
    main()

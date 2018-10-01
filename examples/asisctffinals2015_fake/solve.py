import angr
import binascii

def main():
    p = angr.Project("fake", auto_load_libs=False)

    state = p.factory.blank_state(addr=0x4004AC)
    inp = state.solver.BVS('inp', 8*8)
    state.regs.rax = inp

    simgr= p.factory.simulation_manager(state)
    simgr.explore(find=0x400684)
    found = simgr.found[0]

    # We know the flag starts with "ASIS{"
    flag_addr = found.regs.rdi
    found.add_constraints(found.memory.load(flag_addr, 5) == int(binascii.hexlify(b"ASIS{"), 16))

    # More constraints: the whole flag should be printable
    flag = found.memory.load(flag_addr, 40)
    for i in range(5, 5+32):
        cond_0 = flag.get_byte(i) >= ord('0')
        cond_1 = flag.get_byte(i) <= ord('9')
        cond_2 = flag.get_byte(i) >= ord('a')
        cond_3 = flag.get_byte(i) <= ord('f')
        cond_4 = found.solver.And(cond_0, cond_1)
        cond_5 = found.solver.And(cond_2, cond_3)
        found.add_constraints(found.solver.Or(cond_4, cond_5))

    # And it ends with a '}'
    found.add_constraints(flag.get_byte(32+5) == ord('}'))

    # In fact, putting less constraints (for example, only constraining the first 
    # several characters) is enough to get the final flag, and Z3 runs much faster 
    # if there are less constraints. I added all constraints just to stay on the 
    # safe side.

    flag_str = found.solver.eval(flag, cast_to=bytes)
    return flag_str.rstrip(b'\0')

    #print("The number to input: ", found.solver.eval(inp))
    #print("Flag:", flag)

    # The number to input:  25313971399
    # Flag: ASIS{f5f7af556bd6973bd6f2687280a243d9}

def test():
    a = main()
    assert a == b'ASIS{f5f7af556bd6973bd6f2687280a243d9}'

if __name__ == '__main__':
    import logging
    logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
    print(main())

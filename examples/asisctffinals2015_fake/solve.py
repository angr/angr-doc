import angr

unconstrained_number = None

def strtol(state):
    # We return an unconstrained number here
    global unconstrained_number
    unconstrained_number = state.se.BVS('strtol', 64)
    # Store it to rax
    state.regs.rax = unconstrained_number

def main():
    p = angr.Project("fake", load_options={'auto_load_libs': False})
    p.hook(0x4004a7, strtol, length=5)

    path = p.factory.path(
        args=['fake', '123'], # Specify an arbitrary number so that we can bypass 
                              # the check of argc in program
        env={"HOME": "/home/angr"}
    )
    ex = p.surveyors.Explorer(find=(0x400450, ), 
                              start=path
                              )
    ex.run()

    found = ex.found[0]
    # We know the flag starts with "ASIS{"
    flag_addr = found.state.regs.rsp + 0x8 + 0x38 - 0x38
    found.state.add_constraints(found.state.memory.load(flag_addr, 5) == int("ASIS{".encode("hex"), 16))

    # More constraints: the whole flag should be printable
    for i in xrange(0, 32):
        cond_0 = found.state.memory.load(flag_addr + 5 + i, 1) >= ord('0')
        cond_1 = found.state.memory.load(flag_addr + 5 + i, 1) <= ord('9')
        cond_2 = found.state.memory.load(flag_addr + 5 + i, 1) >= ord('a')
        cond_3 = found.state.memory.load(flag_addr + 5 + i, 1) <= ord('f')
        found.state.add_constraints(
            found.state.se.Or(
                found.state.se.And(cond_0, cond_1),
                found.state.se.And(cond_2, cond_3)
            )
        )

    # And it ends with a '}'
    found.state.add_constraints(found.state.memory.load(flag_addr + 5 + 32, 1) == 
                                ord('}'))

    # In fact, putting less constraints (for example, only constraining the first 
    # several characters) is enough to get the final flag, and Z3 runs much faster 
    # if there are less constraints. I added all constraints just to stay on the 
    # safe side.

    flag = found.state.se.any_int(found.state.memory.load(flag_addr, 8 * 5))
    return hex(flag)[2:-1].decode("hex").strip('\0')

    #print "The number to input: ", found.state.se.any_int(unconstrained_number)
    #print "Flag:", flag

    # The number to input:  25313971399
    # Flag: ASIS{f5f7af556bd6973bd6f2687280a243d9}

def test():
    a = main()
    assert main() == 'ASIS{f5f7af556bd6973bd6f2687280a243d9}'

if __name__ == '__main__':
    print main()

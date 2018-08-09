import angr
import claripy

def main():
    p = angr.Project("license", load_options={'auto_load_libs': False})

    # Create a blank state
    state = p.factory.blank_state()

    # Build the file whose name is weird
    license_name = "_a\nb\tc_"

    # This is the license file
    # From analyzing the binary, we know that the license file should have five 
    # lines in total, and each line has 6 characters. Not setting file content 
    # may also work, but in that case, angr will produce many more paths, and we 
    # will spent much more time in path trimming.

    bytestring = None
    for i in range(5):
        line = [ ]
        for j in range(6):
            line.append(state.solver.BVS('license_file_byte_%d_%d' % (i, j), 8))
            state.add_constraints(line[-1] != b'\n')
        if bytestring is None:
            bytestring = claripy.Concat(*line)
        else:
            bytestring = bytestring.concat(state.solver.BVV(b'\n'), *line)

    license_file = angr.storage.file.SimFile(license_name, bytestring)
    state.fs.insert(license_name, license_file)

    simgr = p.factory.simulation_manager(state)

    simgr.explore(
                find=(0x400e93, ),
                avoid=(0x400bb1, 0x400b8f, 0x400b6d, 0x400a85,
                       0x400ebf, 0x400a59)
            )

    # One path will be found
    found = simgr.found[0]
    rsp = found.regs.rsp
    flag_addr = rsp + 0x278 - 0xd8 # Ripped from IDA
    # Perform an inline call to strlen() in order to determine the length of the 
    # flag
    FAKE_ADDR = 0x100000
    strlen = lambda state, arguments: \
        angr.SIM_PROCEDURES['libc']['strlen'](p, FAKE_ADDR, p.arch).execute(
            state, arguments=arguments
        )
    flag_length = strlen(found, arguments=[flag_addr]).ret_expr
    # In case it's not null-terminated, we get the least number as the length
    flag_length_int = min(found.solver.eval_upto(flag_length, 3))
    # Read out the flag!
    flag_int = found.solver.eval(found.memory.load(flag_addr, flag_length_int))
    flag = bytes.fromhex(hex(flag_int)[2:])
    return flag

def test():
    assert main() == b'ASIS{8d2cc30143831881f94cb05dcf0b83e0}'

if __name__ == '__main__':
    print(main())


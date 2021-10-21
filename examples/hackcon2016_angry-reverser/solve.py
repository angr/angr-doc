import angr
import claripy

# HackCon 2016 - angry-reverser
# @author: P1kachu, Kyle ZENG
# @contact: p1kachu@lse.epita.fr, jkjh1jkjh1@gmail.com
# Execution time: ~1 minute

def main():
    flag    = claripy.BVS('flag', 20*8, explicit_name=True)# symbolized flag, we know the length by looking at the assembly code
    buf     = 0x606000# buffer to store flag
    crazy   = 0x400646# entry point of crazy function
    find    = 0x405a6e# end of crazy function

    # Offset of 'FAIL' blocks in Crazy(from pwntools--e.search(asm('mov ecx, 0')))
    avoids = [0x402c3c, 0x402eaf, 0x40311c, 0x40338b, 0x4035f8, 0x403868,
              0x403ad5, 0x403d47, 0x403fb9, 0x404227, 0x404496, 0x40470a,
              0x404978, 0x404bec, 0x404e59, 0x4050c7, 0x405338, 0x4055a9,
              0x4057f4, 0x405a2b]


    proj = angr.Project('./yolomolo', auto_load_libs=False)
    # Create blank state starting from crazy function
    # LAZY_SOLVES is very important here because we are actually collecting constraints for an equation Ax=b, where A is 20 by 20, x and b are 20 by 1
    state = proj.factory.blank_state(addr=crazy, add_options={angr.options.LAZY_SOLVES})
    # insert flag into memory by hand
    state.memory.store(buf, flag, endness='Iend_BE')
    state.regs.rdi = buf

    # each character of flag should be between 0x30 and 0x7f
    for i in range(19):
        state.solver.add(flag.get_byte(i) >= 0x30)
        state.solver.add(flag.get_byte(i) <= 0x7f)

    simgr = proj.factory.simulation_manager(state)

    simgr.explore(find=find, avoid=avoids)
    found = simgr.found[0]
    return found.solver.eval(flag, cast_to=bytes)

def test():
    assert main() == b"HACKCON{VVhYS04ngrY}"

if __name__ in '__main__':
    import logging
    logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
    print(main())

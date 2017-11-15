"""
Full writeup of the walkthrough:
http://0x0atang.github.io/reversing/2015/09/18/flareon5-concolic.html
"""
import angr


# Globals
LEN_PW = 0x22
ADDR_PW_ORI = ADDR_PW_ENC = ADDR_HASH = 0
GOAL_HASH = 'UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW=='


def hook_duplicate_pw_buf(state):
    for i in xrange(LEN_PW):
        char_ori = state.memory.load(ADDR_PW_ORI + i, 1)
        state.memory.store(ADDR_PW_ENC + i, char_ori)
    state.regs.ebx = ADDR_PW_ENC

def hook_use_dup_pw_buf(state):
    state.regs.ecx = ADDR_PW_ENC

def hook_heapalloc(state):
    state.regs.eax = ADDR_HASH


def main():
    global ADDR_PW_ORI, ADDR_PW_ENC, ADDR_HASH

    # Load binary
    p = angr.Project('sender')

    # Start with a blank state at the EIP after "key.txt" is read
    state = p.factory.blank_state(addr=0x401198)

    # Initialize global variables
    ADDR_PW_ORI = state.regs.ebp - 0x80004
    ADDR_PW_ENC = ADDR_PW_ORI + 0x10000
    ADDR_HASH = state.regs.ebp - 0x40000

    # Setup stack to simulate the state after which the "key.txt" is read
    state.regs.esi = LEN_PW
    for i in xrange(LEN_PW):
        state.mem[ADDR_PW_ORI+i:].byte = state.solver.BVS('pw', 8)

    # Hook instructions to use a separate buffer for the XOR-ing function
    p.hook(0x401259, hook_duplicate_pw_buf, length=0)
    p.hook(0x4011E7, hook_use_dup_pw_buf, length=0)

    # To avoid calling imports (HeapAlloc), retrofit part of the stack as 
    # temporary buffer to hold symbolic copy of the password
    p.hook(0x4011D6, hook_heapalloc, length=5)

    # Explore the states until after the hash is computed
    sm = p.factory.simulation_manager(state, immutable=False)
    sm.explore(find=0x4011EC)

    # Add constraints to make final hash equal to the one we want
    # Also restrict the hash to only printable bytes
    found_s = sm.found[0]
    for i in xrange(len(GOAL_HASH)):
        char = found_s.memory.load(ADDR_HASH + i, 1)
        found_s.add_constraints(char >= 0x21,
                                char <= 0x7e,
                                char == ord(GOAL_HASH[i]))

    # Solve for password that will result in the required hash
    print found_s.solver.eval(found_s.memory.load(ADDR_PW_ORI+0, 1), cast_to=str) + \
          found_s.solver.eval(found_s.memory.load(ADDR_PW_ORI+1, LEN_PW-1), cast_to=str)

def test():
    main()

if __name__ == '__main__':
    main()

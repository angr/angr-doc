# coding: utf-8

#
# This file solves the problem `nobranch` from 9447 CTF 2015. It got the first blood solution!
# It takes a VERY long time to run! I took a well-deserved nap while it was solving :)
#

import angr, claripy
p = angr.Project('nobranch')
all_blocks = []
mainaddr = 0x400400
outaddr = 0x616050

shouldbe = 'HMQhQLi6VqgeOj78AbiaqquK3noeJt'

def main():
    state = p.factory.blank_state(addr=mainaddr)                                                    # set up the initial state at the start of main
    state.memory.store(state.regs.rsp, claripy.BVV(0x4141414141414141, 64), endness='Iend_LE')      # set fake return address
    state.memory.store(state.regs.rsp + 8, state.regs.rsp + 64, endness='Iend_LE')                  # I can't remember if I even need this... better safe than sorry
    state.memory.store(state.regs.rsp + 16, claripy.BVV(0, 64), endness='Iend_LE')                  # see above

    state.memory.store(state.regs.rsp + 64, state.regs.rsp + 128, endness='Iend_LE')                # set first argv string pointer
    state.memory.store(state.regs.rsp + 72, state.regs.rsp + 129, endness='Iend_LE')                # set second argv string pointer
    state.memory.store(state.regs.rsp + 80, claripy.BVV(0, 64), endness='Iend_LE')

    state.memory.store(state.regs.rsp + 128, claripy.BVV(0, 8))                                     # set first argv string to the empty string
    flag = claripy.BVS('flag', 18*8)
    state.memory.store(state.regs.rsp + 129, flag)                                                  # set second argv string to symbolic flag!

    state.regs.rdi = 2                                                                              # set argc = 2
    state.regs.rsi = state.regs.rsp + 64                                                            # set argv = args
    state.regs.rdx = state.regs.rsp + 80                                                            # set envp = empty list

    i = 0
    while state.history.jumpkind == 'Ijk_Boring':                                                   # symbolically execute until we hit the syscall at the end
        i += 1
        print i
        ss = p.factory.successors(state, num_inst=1)                                                # only step one instruction at a time
        state = ss.successors[0]
        reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

        assert not state.regs.rsp.symbolic

        for reg_name in reg_names:                                                                  # for each register and memory location that matters in the program,
            val = state.registers.load(reg_name)                                               # after each step, if the symbolic AST for that value has become larger than
            if val.symbolic and val.depth > 3:                                                      # three nodes deep, stub it out by replacing it with a single symbolic value
                newval = claripy.BVS('replacement', len(val))                                       # constrained to be equal to the original value. This makes the constraints much
                state.solver.add(newval == val)                                                    # easier for z3 to bite into in smaller chunks. It might also indicate that there
                state.registers.store(reg_name, newval)                                        # some issues with angr's current usage of z3 :-)

        for mem_addr in range(outaddr, outaddr + 0x1f) + [state.regs.rsp - x for x in xrange(0x40)]:
            val = state.memory.load(mem_addr, 1)
            if val.symbolic and val.depth > 3:
                newval = claripy.BVS('replacement', len(val))
                state.solver.add(newval == val)
                state.memory.store(mem_addr, newval)

    fstate = state.copy()
    fstate.solver._solver.timeout = 0xfffffff                                                           # turn off z3's timeout for solving :^)
    for i, c in enumerate(shouldbe):
        fstate.solver.add(fstate.memory.load(0x616050 + i, 1) == ord(c))                                # constrain the output to what we were told it should be

    cflag = hex(fstate.solver.eval(flag))[2:-1].decode('hex')                                        # solve for the flag!
    return cflag

def test():
    f = main()
    assert f.startswith('9447{') and f.endswith('}')
    # lol I don't have the flag onhand and I don't want to wait hours for it to re-solve :P
    # you can verify it by running ./nobranch `cat flag`
    # and verifying that it prints out the shouldbe value at the top

if __name__ == '__main__':
    print main()


import logging
import sys

import angr
import capstone
import r2pipe

l = logging.getLogger('angr.manager').setLevel(logging.WARNING)
l = logging.getLogger('angr.engines.vex.engine').setLevel(logging.ERROR)

pos = 0xd000000

def recvuntil(sock, s):
    data = ""
    while True:
        char = sock.recv(1)
        if not char:
            break
        data += char
        if data.endswith(s):
            break
    return data

def get_symbol_addr(s, symbol_name):
    r2 = r2pipe.open("occult_dist/%s" % s)
    symbols = r2.cmdj("isj")
    symbol = next(iter(symbol for symbol in symbols if symbol['name'] == symbol_name))
    return symbol['vaddr'] + 0x400000

def count_calls(func, to_func):
    graph = func.transition_graph
    # the node
    to_func_node = [ n for n in graph.nodes() if isinstance(n, angr.knowledge.Function) and n.addr == to_func ]
    if not to_func_node:
        return
    assert len(to_func_node) == 1
    to_func_node = to_func_node[0]

    # count in_edges
    return len(graph.in_edges(to_func_node))

def solve(s):

    c_mutate_slot = get_symbol_addr(s, "imp.C_mutate_slot")
    assert c_mutate_slot != 0

    p = angr.Project("occult_dist/%s" % s,
            auto_load_libs=False
            )
    cfg = p.analyses.CFG(show_progressbar=True)

    # determine the function address
    callers = cfg.functions.callgraph.predecessors(c_mutate_slot)
    caller_addr = max(callers)  # remove the one in PLT

    all_checkers = [  ]

    for caller_caller in cfg.functions.callgraph.predecessors(caller_addr):
        func = cfg.functions[caller_caller]
        call_times = count_calls(func, caller_addr)
        if call_times != 32:
            continue

        # make sure it has sub rsp, r15
        has_alloca = False
        for block in func.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic == 'sub' and \
                        insn.operands[0].type == 1 and \
                        insn.operands[0].reg == capstone.x86_const.X86_REG_RSP and \
                        insn.operands[1].type == 1:
                    has_alloca = True
                    break
            if has_alloca:
                break

        if not has_alloca:
            continue

        all_checkers.append(func)

    chars = {}

    for o, check_func in enumerate(all_checkers):

        print o, len(all_checkers)

        # parse basic blocks in this function to figure out the char offset
        char_offset = None
        for block in check_func.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic == 'mov' and \
                        insn.operands[0].type == 3 and \
                        insn.operands[0].mem.base == capstone.x86_const.X86_REG_R12 and \
                        insn.operands[0].mem.disp == 0x10:
                    char_offset = insn.operands[1].imm
                    break
            if char_offset is not None:
                break

        state = p.factory.blank_state(addr=check_func.addr, add_options={angr.options.LAZY_SOLVES, angr.options.NO_SYMBOLIC_JUMP_RESOLUTION})

        char = state.solver.BVS("chr", 64)

        # rsi is a2
        state.regs.rsi = state.solver.BVV(0xd000000, 64)
        state.memory.store(0xd000000, state.solver.BVV(0xd000010, 64), endness='Iend_LE')
        state.memory.store(0xd000010 + 16, state.solver.BVV(0xd000040, 64), endness='Iend_LE')
        state.memory.store(0xd000040 + 8, char, endness='Iend_LE')

        sm = p.factory.simulation_manager(state)
        sm.explore(avoid=(c_mutate_slot,))

        the_char = None
        for state in sm.deadended:
            if not state.satisfiable():
                continue
            char_n = state.solver.eval_upto(char, 2)
            if len(char_n) == 2:
                continue
            the_char = char_n[0]
            break

        if the_char is None:
            continue

        chars[char_offset] = the_char

    return "".join([ chr(v/2) for k, v in sorted(chars.items()) ])

def main():
    import os
    for i, filename in enumerate(os.listdir("occult_dist")):
        if i % 8 != int(sys.argv[1]):
            continue
        solution_file = "%s.solution" % filename
        if os.path.exists(solution_file):
            continue
        print i, filename
        try:
            sol = solve(filename)
        except ValueError:
            print "oops failed on %s" % filename
            continue
        # data = sol.encode("base64")
        with open(solution_file, "wb") as f:
            f.write(sol)
        #print "Send this:" + data
        #sock.send(data + "\n")


if __name__ == "__main__":
    main()


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
    r2 = r2pipe.open("bc9cd8ff91a55ecee73caf85c3d55e45/%s" % s)
    symbols = r2.cmdj("isj")
    symbol = next(iter(symbol for symbol in symbols if symbol['name'] == symbol_name))
    return symbol['vaddr']

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

    p = angr.Project("bc9cd8ff91a55ecee73caf85c3d55e45/%s" % s,
            auto_load_libs=False
            )
    cfg = p.analyses.CFG(show_progressbar=True)

    # determine the function address
    all_checkers = [  ]

    for caller_caller in cfg.functions.callgraph.predecessors(c_mutate_slot):
        func = cfg.functions[caller_caller]
        call_times = count_calls(func, c_mutate_slot)

        if func.addr == 0x404650:
            import ipdb; ipdb.set_trace()

        if call_times != 32:
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
                        insn.operands[0].type == capstone.x86_const.X86_OP_REG and \
                        insn.operands[0].reg == capstone.x86_const.X86_REG_ECX and \
                        insn.operands[1].type == capstone.x86_const.X86_OP_IMM:
                    char_offset = insn.operands[1].imm
                    break
            if char_offset is not None:
                break

        if check_func.addr == 0x404650:
            import ipdb; ipdb.set_trace()

        if char_offset is None:
            continue

        state = p.factory.blank_state(addr=check_func.addr, add_options={angr.options.LAZY_SOLVES, angr.options.NO_SYMBOLIC_JUMP_RESOLUTION})

        char = state.solver.BVS("chr", 64)

        # rsi is a2
        state.regs.rsi = state.solver.BVV(0xd000000, 64)
        state.memory.store(0xd000000 + 16, state.solver.BVV(0xd000040, 64), endness='Iend_LE')
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

    print chars
    return "".join([ chr(v/2) for k, v in sorted(chars.items()) ])

def main():
    print solve("df8737d9d5aee3cee6320e7313414458fdfb10552a8e6c8ea45753102ba4509a")
    return
    import os
    for i, filename in enumerate(os.listdir("bc9cd8ff91a55ecee73caf85c3d55e45")):
        if i % 8 != int(sys.argv[1]):
            continue
        solution_file = "%s.solution" % filename
        if os.path.exists(solution_file):
            continue
        print i, filename
        try:
            sol = solve(filename)
            if not sol:
                continue
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


import os
import string
import sys

import angr
import capstone

import logging

logging.getLogger('cle.loader').setLevel(logging.ERROR)


def solve(filename):
    p = angr.Project("0ac60e121305416e9fea5e5f887675a3/%s" % filename, auto_load_libs=False)
    cfg = p.analyses.CFG(show_progressbar=False)

    # the main function calls pthread_mutex_lock three times
    callgraph = cfg.functions.callgraph
    pthread_mutex_lock = cfg.functions.function(name='pthread_mutex_lock', plt=True)
    callers = callgraph.predecessors(pthread_mutex_lock.addr)

    assert callers
    the_func = None
    for caller_addr in callers:
        func = cfg.functions[caller_addr]
        the_node = [ n for n in func.transition_graph.nodes() if isinstance(n, angr.knowledge.Function) and n.addr == pthread_mutex_lock.addr ]
        in_edges = func.transition_graph.in_edges(the_node[0])
        if len(in_edges) == 3:
            the_func = func
            break

    assert the_func is not None

    key = ""

    for block in sorted(the_func.blocks, key=lambda x: x.addr):
        insns = block.capstone.insns
        for insn in insns:
            if insn.mnemonic == 'cmp' and \
                    insn.operands[0].type == 1 and \
                    insn.operands[0].reg in (capstone.x86_const.X86_REG_CL, capstone.x86_const.X86_REG_AL) and \
                    insn.operands[1].type == 2:
                char = chr(insn.operands[1].imm)
                if char in string.printable:
                    key += char
                    break

    return key

def main():
    for i, filename in enumerate(os.listdir("0ac60e121305416e9fea5e5f887675a3")):
        if i % 8 != int(sys.argv[1]):
            continue
        if "." in filename:
            continue
        print i, filename, '"%s"' % solve(filename)

if __name__ == "__main__":
    main()

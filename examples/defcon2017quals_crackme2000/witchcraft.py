
import logging
import sys

l = logging.getLogger('angr.manager').setLevel(logging.DEBUG)

import angr

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

class Alloca(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVV(pos, 64)

def solve(s):
    p = angr.Project("witchcraft_dist/%s" % s,
            auto_load_libs=False
            )
    cfg = p.analyses.CFG(show_progressbar=True)

    # determine the function address
    callers = cfg.functions.callgraph.predecessors(cfg.functions.function(name='_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_', plt=True).addr)
    caller_funcs = [ cfg.functions[caller_addr] for caller_addr in callers ]
    caller_func = sorted(caller_funcs, key=lambda f: f.size)[-1]

    print hex(caller_func.addr)
    state = p.factory.blank_state(addr=caller_func.addr, add_options={angr.options.LAZY_SOLVES})
    state.regs.rbx = 0

    # get the function to hook
    ctr = 0
    alloca = None
    for block in sorted(caller_func.blocks, key=lambda b: b.addr):
        if block.vex.jumpkind == 'Ijk_Call':
            ctr += 1
            if ctr == 1:
                swift_retain = cfg.get_any_node(block.addr).successors[0].addr
            if ctr == 3:
                alloca = cfg.get_any_node(block.addr).successors[0].addr
                break

    if alloca is None:
        return ""

    print "swift_retain:", hex(swift_retain)
    print "Alloca:", hex(alloca)
    p.hook(swift_retain, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'])
    p.hook(alloca, Alloca)

    sm = p.factory.simulation_manager(state)
    sm.explore()

    state = sm.deadended[-1]
    mem = state.memory.load(pos + 0x20, 60)
    mem_str = state.solver.eval(mem, cast_to=str).replace("\x00", "")
    return mem_str

def main():
    import os
    for i, filename in enumerate(os.listdir("witchcraft_dist")):
        if i % 8 != int(sys.argv[1]):
            continue
        solution_file = "%s.solution" % filename
        if os.path.exists(solution_file):
            continue
        print i, filename
        sol = solve(filename)
        # data = sol.encode("base64")
        with open(solution_file, "wb") as f:
            f.write(sol)
        #print "Send this:" + data
        #sock.send(data + "\n")


if __name__ == "__main__":
    main()

import angr
import logging

def main():
    p = angr.Project("r200", auto_load_libs=False)
    sm = p.factory.simulation_manager()

    # avoid the antidebug traps, go to the merge point
    sm.explore(find=0x4007FD, avoid=(0x40085D, 0x400882), num_find=11)
    print sm

    var_addr = sm.one_found.solver.eval(sm.one_found.regs.rbp - 0x4c)
    for s in sm.found:
        print s, s.mem[var_addr].dword.resolved

    print 'merging...'
    import ipdb; ipdb.set_trace()
    sm.merge(stash='found')

    s = sm.one_found
    culprit = s.mem[var_addr].dword.resolved
    print s, culprit.__repr__(max_depth=3)
    for i in xrange(1, 0xb):
        print i, s.solver.satisfiable(extra_constraints=(culprit == i,))

if __name__ == '__main__':
    logging.getLogger('angr.state_plugins.callstack').setLevel('ERROR')
    #logging.getLogger('angr.manager').setLevel('DEBUG')
    #logging.getLogger('angr.exploration_techniques.manual_mergepoint').setLevel('DEBUG')
    main()

#!/usr/bin/env python

import angr
import logging

# This is the important logic that makes this problemt tractable
class CheckUniqueness(angr.ExplorationTechnique):
    def __init__(self):
        self.unique_states = set()

    def filter(self, simgr, state, filter_func=None):
        vals = []
        for reg in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'):
            val = state.registers.load(reg)
            if val.symbolic:
                vals.append('symbolic')
            else:
                vals.append(state.solver.eval(val))

        vals = tuple(vals)
        if vals in self.unique_states:
            return 'not_unique'

        self.unique_states.add(vals)
        return simgr.filter(state, filter_func=filter_func)


class SearchForNull(angr.ExplorationTechnique):
    def setup(self, simgr):
        if 'found' not in simgr.stashes:
            simgr.stashes['found'] = []

    def filter(self, simgr, state, filter_func=None):
        if state.addr == 0:
            return 'found'
        return simgr.filter(state, filter_func=filter_func)

    def complete(self, simgr):
        return len(simgr.found)

def setup_project():
    project = angr.Project('crypto.mod', auto_load_libs=False)

    # use libc functions as stand-ins for grub functions
    memset = angr.SIM_PROCEDURES['libc']['memset']
    getchar = angr.SIM_PROCEDURES['libc']['getchar']
    do_nothing = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']

    project.hook_symbol('grub_memset', memset())
    project.hook_symbol('grub_getkey', getchar())

    # I don't know why, but grub_xputs is apparently not the function but a pointer to it?
    xputs_pointer_addr = project.loader.find_symbol('grub_xputs').rebased_addr
    xputs_func_addr = project.loader.extern_object.allocate()
    project.hook(xputs_func_addr, do_nothing())
    project.loader.memory.pack_word(xputs_pointer_addr, xputs_func_addr)

    return project

def find_bug(project, function, args):
    # set up the most generic state that could enter this function
    func_addr = project.loader.find_symbol(function).rebased_addr
    start_state = project.factory.call_state(func_addr, *args)

    # create a new simulation manager to explore the state space of this function
    simgr = project.factory.simulation_manager(start_state)
    simgr.use_technique(SearchForNull())
    simgr.use_technique(CheckUniqueness())
    simgr.run()

    print('we found a crashing input!')
    print('crashing state:', simgr.found[0])
    print('input:', repr(simgr.found[0].posix.dumps(0)))
    return simgr.found[0].posix.dumps(0)

def test():
    assert find_bug(setup_project(), 'grub_password_get', (angr.PointerWrapper(b'\0'*64), 64)) == b'\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\r'

if __name__ == '__main__':
    logging.getLogger('angr.sim_manager').setLevel('DEBUG')
    p = setup_project()
    find_bug(p, 'grub_password_get', (angr.PointerWrapper('\0'*64), 64))

#!/usr/bin/env python

import angr, simuvex

def find_bug():
    p = angr.Project('crypto.mod', load_options={'main_opts': {'custom_base_addr': 0x8000000}})
    # custom base addr to match what IDA says

    # This might be a method that gets migrated into angr proper soon
    # the functionality in CLE that it uses is very new (I wrote it 24h before the presentation) :)
    def resolve_dependancy(name, func):
        pseudo_addr = p._extern_obj.get_pseudo_addr(name)
        pseudo_offset = pseudo_addr - p._extern_obj.rebase_addr
        p.loader.provide_symbol(p._extern_obj, name, pseudo_offset)
        p.hook(pseudo_addr, func)

    # use libc functions as stand-ins for grub functions
    grub_memset = simuvex.SimProcedures['libc.so.6']['memset']
    grub_getkey = simuvex.SimProcedures['libc.so.6']['getchar']
    grub_puts = simuvex.SimProcedures['stubs']['ReturnUnconstrained']
    grub_refresh = simuvex.SimProcedures['stubs']['ReturnUnconstrained']
    resolve_dependancy('grub_getkey', grub_getkey)
    resolve_dependancy('grub_memset', grub_memset)
    resolve_dependancy('grub_refresh', grub_refresh)

    # I don't know why, but the grub_xputs symbol is apparently a pointer to a pointer to the function. why.
    p.hook(p._extern_obj.get_pseudo_addr('grub_puts'), grub_puts)
    p.loader.provide_symbol(p._extern_obj, 'grub_xputs', p._extern_obj.get_pseudo_addr('grub_xputs') - p._extern_obj.rebase_addr)

    exec_sink = p._extern_obj.get_pseudo_addr('exec_sink')
    p.hook(exec_sink, simuvex.SimProcedures['stubs']['PathTerminator'])

    # set up the most generic state that could enter this function
    start_state = p.factory.blank_state(addr=0x80008A1)
    start_state.stack_push(256)              # buffer size: 256
    start_state.stack_push(start_state.regs.esp + 20)      # buffer: space on previous stack frame
    start_state.stack_push(exec_sink)   # return address: terminate execution

    # additional kludge to deal with the xputs call
    start_state.memory.store(p._extern_obj.get_pseudo_addr('grub_xputs'), p._extern_obj.get_pseudo_addr('grub_puts'), size=4, endness='Iend_LE')

    # create a new path group to explore the state space of this function
    pg = p.factory.path_group(start_state)

    unique_states = set()
    def check_uniqueness(path):
        vals = []
        for reg in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'):
            val = path.state.registers.load(reg)
            if val.symbolic:
                vals.append('symbolic')
            else:
                vals.append(path.state.se.any_int(val))

        vals = tuple(vals)
        if vals in unique_states:
            return True

        unique_states.add(vals)
        return False

    def step_func(lpg):
        print lpg
        lpg.stash(filter_func=check_uniqueness, from_stash='active', to_stash='not_unique')
        lpg.stash(filter_func=lambda path: path.addr == 0, from_stash='active', to_stash='found')
        return lpg

    pg.step(step_func=step_func, until=lambda lpg: len(lpg.found) > 0)

    print 'we found a crashing input!'
    print 'path:', pg.found[0]
    print 'input:', repr(pg.found[0].state.posix.dumps(0))

def test():
    pass        # this is not a CI test

if __name__ == '__main__':
    find_bug()

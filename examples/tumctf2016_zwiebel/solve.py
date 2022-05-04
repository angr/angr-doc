import angr

def main():

    # Uncomment the following two lines if you want to have logging output from
    # SimulationManager
    # import logging
    # logging.getLogger('angr.manager').setLevel(logging.DEBUG)

    p = angr.Project("zwiebel", support_selfmodifying_code=True) # this is important! this binary unpacks its code
    p.hook_symbol('ptrace', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](return_value=0))

    # unicorn support makes execution, especially code unpacking, way faster
    state = p.factory.full_init_state(add_options=angr.options.unicorn)
    sm = p.factory.simulation_manager(state)

    while sm.active:
        # in order to save memory, we only keep the recent 20 deadended or
        # errored states
        #print(len(sm.active))
        sm.run(n=20)
        if 'deadended' in sm.stashes and sm.deadended:
            sm.stashes['deadended'] = sm.deadended[-20:]
        if sm.errored:
            sm.errored = sm.errored[-20:]

    assert sm.deadended
    flag = sm.deadended[-1].posix.dumps(0).split(b"\n")[0]
    return flag

def test():
    flag = main()
    assert flag.startswith(b'hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}')

if __name__ == "__main__":
    print(main())

# Here is the output (after 2 hours and 31 minutes on my machine running Pypy):
# 
# ipdb> print(sm)
# <PathGroup with 20 errored, 21 deadended>
# ipdb> print(sm.deadended[-1])
# <Path with 160170 runs (at 0x20001e0)>
# ipdb> print(sm.deadended[-1].state.posix.dumps(0))
# hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}
# :)

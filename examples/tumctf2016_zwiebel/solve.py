
import angr
import simuvex

def main():

    # Uncomment the following two lines if you want to have logging output from path_group
    # import logging
    # logging.getLogger('angr.path_group').setLevel(logging.DEBUG)

    p = angr.Project("zwiebel",
                     support_selfmodifying_code=True, # this is important! this binary unpacks its code
                     load_options={'auto_load_libs': False}
                     )

    # unicorn support makes execution, especially code unpacking, way faster
    state = p.factory.entry_state(add_options=simuvex.o.unicorn)
    pg = p.factory.path_group(state)

    while pg.active:
        # in order to save memory, we only keep the recent 20 deadended or errored paths
        pg.run(n=20)
        print pg.active[0]
        if 'deadended' in pg.stashes and pg.deadended:
            pg.stashes['deadended'] = pg.deadended[-20:]
        if 'errored' in pg.stashes and pg.errored:
            pg.stashes['errored'] = pg.errored[-20:]

    assert pg.deadended
    flag = pg.deadended[-1].state.posix.dumps(0).split("\n")[0]
    print flag

    # import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    main()

"""
Here is the output (after 2 hours and 31 minutes on my machine running Pypy):

ipdb> print pg
<PathGroup with 20 errored, 21 deadended>
ipdb> print pg.deadended[-1]
<Path with 160170 runs (at 0x20001e0)>
ipdb> print pg.deadended[-1].state.posix.dumps(0)
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}
:)
"""


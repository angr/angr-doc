
import logging

#l = logging.getLogger('angr.manager').setLevel(logging.DEBUG)

import angr

def solve(s):
    p = angr.Project("challs/magic_dist/%s" % s,
            auto_load_libs=False
            )
    cfg = p.analyses.CFG()

    state = p.factory.blank_state(addr=0x400770)
    sm = p.factory.simulation_manager(state)
    sm.explore()
    sol = sm.deadended[-1].posix.dumps(0).replace("\x00", "").replace("\n", "")
    return sol

def main():
    #solve("65cb596908789372c2d6fbeb0ac3a0e3a1089039138711a016ec3994ad5c7f10")
    import pwn
    host, port = "cm2k-magic_b46299df0752c152a8e0c5f0a9e5b8f0.quals.shallweplayaga.me", 12001
    r = pwn.remote(host, port)
    print r.readuntil("newline\n")
    while True:
        filename = r.readuntil("\n").strip("\n")
        print filename
        sol = solve(filename)
        print repr(sol)
        data = sol.encode("base64")
        print "Send this:" + data
        r.send(data)


if __name__ == "__main__":
    main()

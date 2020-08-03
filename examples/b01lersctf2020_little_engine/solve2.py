#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time

# compiled on ubuntu 18.04 system:
# https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine


def main():
    # length of desired input is 75 as found from reversing the binary in ghidra
    # 1 extra byte for first input
    input_len = 1 + 75

    # seting up the angr project
    p = angr.Project('./engine')

    # looking at the code/binary, we can tell the input string is expected to fill 22 bytes,
    # thus the 8 byte symbolic size. Hopefully we can find the constraints the binary
    # expects during symbolic execution
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]

    #extra \n for first input, then find the flag!
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
    # enable unicorn engine for fast efficient solving
    st = p.factory.entry_state(stdin=angr.SimFile('/dev/stdin', content=flag))

    # constrain to non-newline bytes
    # constrain to ascii-only characters
    for k in flag_chars:
        st.solver.add(k < 0x7f)
        st.solver.add(k > 0x20)

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)

    # now we defind the callback to check is the right or woring path
    def isOk(x):
        return b'Chugga' in x.posix.dumps(1)

    def isBad(x):
        return b'TRAINing' in x.posix.dumps(1)

    # now we find it !
    sm.explore(find=isOk, avoid=isBad)

    # try to get the right path!
    if sm.found:
        valid = sm.found[0].posix.dumps(0)
        flag = valid[1:76]
        return flag.decode('utf-8')

    # otherwise ,must be something woring!
    raise Exception('something wrong!')


def test():
    assert main(
    ) == "pctf{th3_m0d3rn_st34m_3ng1n3_w45_1nv3nt3d_1n_1698_buT_th3_b3st_0n3_in_1940}"


if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))

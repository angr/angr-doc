#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time

#compiled on ubuntu 18.04 system:
#https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine

def main():
    #setup of addresses used in program
    #addresses assume base address of
    base_addr = 0x100000

    #length of desired input is 75 as found from reversing the binary in ghidra
    #need to add 4 times this size, since the actual array is 4 times the size
    #1 extra byte for first input
    input_len = 1+75*4

    #seting up the angr project
    p = angr.Project('./engine', main_opts={'base_addr': base_addr})

    #looking at the code/binary, we can tell the input string is expected to fill 22 bytes,
    # thus the 8 byte symbolic size. Hopefully we can find the constraints the binary
    # expects during symbolic execution
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]

    #extra \n for first input, then find the flag!
    flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

    # enable unicorn engine for fast efficient solving
    st = p.factory.full_init_state(
            args=['./engine'],
            add_options=angr.options.unicorn,
            stdin=flag
           )

    #constrain to non-newline bytes
    #constrain to ascii-only characters
    for k in flag_chars:
        st.solver.add(k < 0x7f)
        st.solver.add(k > 0x20)

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)
    sm.run()

    #grab all finished states, that have the win function output in stdout
    y = []
    for x in sm.deadended:
        if b"Chugga" in x.posix.dumps(1):
            y.append(x)

    #grab the first output
    valid = y[0].posix.dumps(0)

    #parse and turn into final flag
    bt = [ chr(valid[i]) for i in range(0,len(valid),2)]
    flag = ''.join(bt)[1:76]
    return flag

def test():
    assert main() == "pctf{th3_m0d3rn_st34m_3ng1n3_w45_1nv3nt3d_1n_1698_buT_th3_b3st_0n3_in_1940}"

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))

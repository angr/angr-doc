#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: Kyle ZENG
# Runtime: ~6 minutes

import hashlib
import angr

def main():
    e = open('./sakura', 'rb').read()

    # make sure return value is not 0, add corresponding addr to avoid list
    avoids = []
    index = 0
    while True:
        # avoid asm('mov byte ptr [rbp-0x1E49], 0')
        index = e.find(b'\xc6\x85\xb7\xe1\xff\xff\x00', index+1)
        if index == -1:
            break
        addr = 0x400000 + index
        avoids.append(addr)

    # find list
    finds = []
    index = 0
    while True:
        # find asm('mov rdi, rax')
        index = e.find(b'H\x89\xc7', index+1)
        if index == -1 or index > 0x10ff5:
            break
        addr = 0x400000 + index
        finds.append(addr)

        # skip a addr we don't want to find
        index = e.find(b'H\x89\xc7', index+1)

    # initialize project
    proj = angr.Project('./sakura', auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    # find ans stage by stage
    for find in finds:
        simgr.explore(find=find, avoid=avoids)
        found = simgr.found[0]
        simgr = proj.factory.simulation_manager(found)

    # evaluate text
    text = found.solver.eval(found.memory.load(0x612040, 400), cast_to=bytes)

    h = hashlib.sha256(text)
    flag = 'hitcon{'+h.hexdigest()+'}'
    return flag

def test():
    assert main() == 'hitcon{6c0d62189adfd27a12289890d5b89c0dc8098bc976ecc3f6d61ec0429cccae61}'

if __name__ == '__main__':
    import logging
    logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

    print(main())

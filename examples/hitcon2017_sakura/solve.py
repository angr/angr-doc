#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: Kyle ZENG
# Runtime: ~10 minutes

import hashlib

from pwn import *
context.arch = 'amd64'

import angr
import logging
logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)


def main():
    e = ELF('./sakura')
    
    # make sure return value is not 0, add corresponding addr to avoid list
    avoids = []
    gen = e.search(asm('mov byte ptr [rbp-0x1E49], 0'))
    try:
        while True:
            avoids.append(0x400000+gen.next())
    except:
        pass
    
    # find list
    finds = []
    gen = e.search(asm('mov rdi, rax'))
    while True:
        addr = 0x400000+gen.next()
        gen.next()
        if addr > 0x410FF5:
            break
        finds.append(addr)

    # initialize project
    proj = angr.Project('./sakura')
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    
    # find ans stage by stage
    for find in finds:
        print hex(find)
        simgr.explore(find=find, avoid=avoids)
        found = simgr.found[0]
        print [found.posix.dumps(0)]
        simgr = proj.factory.simgr(found)
    
    # evaluate text
    text = found.solver.eval(found.memory.load(0x612040, 400), cast_to=str)
    
    h = hashlib.sha256(text)
    flag = 'hitcon{'+h.digest().encode('hex')+'}'
    return flag

def test():
    assert main() == 'hitcon{6c0d62189adfd27a12289890d5b89c0dc8098bc976ecc3f6d61ec0429cccae61}'

if __name__ == '__main__':
    print main()



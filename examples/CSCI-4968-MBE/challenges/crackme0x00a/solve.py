#!/usr/bin/env python2

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

FIND_ADDR = 0x08048533 # mov dword [esp], str.Congrats_ ; [0x8048654:4]=0x676e6f43 LEA str.Congrats_ ; "Congrats!" @ 0x8048654
AVOID_ADDR = 0x08048554 # mov dword [esp], str.Wrong_ ; [0x804865e:4]=0x6e6f7257 LEA str.Wrong_ ; "Wrong!" @ 0x804865e


def main():
	proj = angr.Project('crackme0x00a', load_options={"auto_load_libs": False})
	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)
	return sm.found[0].posix.dumps(0).split('\0')[0] # stdin

def test():
	assert main() == 'g00dJ0B!'

if __name__ == '__main__':
	print(main())

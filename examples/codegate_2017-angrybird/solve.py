#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Runtime: ~3 minutes

import angr
import string

START_ADDR = 0x4007c2
FIND_ADDR = 0x404fc1  # This is shortly after the printf.

def main():
	proj = angr.Project('angrybird', load_options={"auto_load_libs": False})
	# There's a couple anti-run instructions in this binary.
	# Yes, anti-run. That's not a typo.

	# Because I'm not interested in fixing a weird binary, I'm going to skip all the beginning of the program.
	state = proj.factory.entry_state(addr=START_ADDR)

	sm = proj.factory.simgr(state)  # Create the SimulationManager.

	sm.explore(find=FIND_ADDR)  # This will take a couple minutes. Ignore the warning message(s), it's fine.
	found = sm.found[-1]
	stdin = found.posix.dumps(0)

	# This trims off anything that's not printable.
	flag = filter(lambda x: x in string.printable, stdin).split()[0]

	# (•_•) ( •_•)>⌐■-■ (⌐■_■)
	return flag

def test():
	assert main() == 'Im_so_cute&pretty_:)'

if __name__ == '__main__':
	print(main())

#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
Author: xoreaxeaxeax
Modified by David Manouchehri <manouchehri@protonmail.com>
Original at https://lists.cs.ucsb.edu/pipermail/angr/2016-August/000167.html

The purpose of this example is to show how to use symbolic write addresses.
"""

import angr
import claripy

def main():
	p = angr.Project('./issue', load_options={"auto_load_libs": False})

	# By default, all symbolic write indices are concretized.
	state = p.factory.entry_state(add_options={"SYMBOLIC_WRITE_ADDRESSES"})

	u = claripy.BVS("u", 8)
	state.memory.store(0x804a021, u)

	sm = p.factory.simulation_manager(state)

	def correct(state):
		try:
			return 'win' in state.posix.dumps(1)
		except:
			return False
	def wrong(state):
	 	try:
	 		return 'lose' in state.posix.dumps(1)
	 	except:
	 		return False

	sm.explore(find=correct, avoid=wrong)

	# Alternatively, you can hardcode the addresses.
	# sm.explore(find=0x80484e3, avoid=0x80484f5)

	return sm.found[0].solver.eval(u)


def test():
	assert '240' in str(main())


if __name__ == '__main__':
	print(repr(main()))

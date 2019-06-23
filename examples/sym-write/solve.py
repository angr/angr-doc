#!/usr/bin/env python3
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
	state = p.factory.entry_state(add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES})

	u = claripy.BVS("u", 8)
	state.memory.store(0x804a021, u)

	sm = p.factory.simulation_manager(state)

	def correct(state):
		try:
			return b'win' in state.posix.dumps(1)
		except:
			return False
	def wrong(state):
		try:
			return b'lose' in state.posix.dumps(1)
		except:
			return False

	sm.explore(find=correct, avoid=wrong)

	# Alternatively, you can hardcode the addresses.
	# sm.explore(find=0x80484e3, avoid=0x80484f5)

	return sm.found[0].solver.eval_upto(u, 256)


def test():
	good = set()
	for u in range(256):
		bits = [0, 0]
		for i in range(8):
			bits[u&(1<<i)!=0] += 1
		if bits[0] == bits[1]:
			good.add(u)

	res = main()
	assert set(res) == good

if __name__ == '__main__':
	print(repr(main()))

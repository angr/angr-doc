#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
Author: xoreaxeaxeax
Modified by David Manouchehri <manouchehri@protonmail.com>
Original at https://lists.cs.ucsb.edu/pipermail/angr/2016-August/000167.html

The purpose of this example is to show how to use symbolic write addresses.
"""

import angr

def main():
	p = angr.Project('./issue', load_options={"auto_load_libs": False})

	# By default, all symbolic write indices are concretized.
	state = p.factory.entry_state(add_options={"SYMBOLIC_WRITE_ADDRESSES"})

	u = angr.claripy.BVS("u", 8)
	state.memory.store(0x804a021, u)

	initial_path = p.factory.path(state)

	pg = p.factory.path_group(state)

	def correct(path):
		try:
			return 'win' in path.state.posix.dumps(1)
		except:
			return False
	def wrong(path):
	 	try:
	 		return 'lose' in path.state.posix.dumps(1)
	 	except:
	 		return False

	pg.explore(find=correct, avoid=wrong)

	# Alternatively, you can hardcode the addresses.
	# pg.explore(find=0x80484e3, avoid=0x80484f5)

	return pg.found[0].state.se.any_int(u)


def test():
	assert '240' in main()


if __name__ == '__main__':
	print(repr(main()))

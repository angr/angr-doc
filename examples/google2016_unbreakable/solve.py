#!/usr/bin/env python

# Author: David Manouchehri <manouchehri@protonmail.com>
# Google 2016 CTF
# Challenge: Unbreakable Enterprise Product Activation

import angr

def main():
	proj = angr.Project('./unbreakable-enterprise-product-activation') #, load_options={"auto_load_libs": False})

	argv1 = angr.claripy.BVS("argv1", 250*8)

	initial_state = proj.factory.entry_state(args=["./unbreakable-enterprise-product-activation", argv1]) 
	initial_state.libc.buf_symbolic_bytes=500 # Thanks to @salls for pointing this out.

	# Source: https://github.com/angr/angr-doc/blob/a3f2adac17e16b4633b741ed114692f3a069cc79/examples/whitehatvn2015_re400/solve.py#L10
	def get_byte(s, i):
		pos = s.size() / 8 - 1 - i
		return s[pos * 8 + 7 : pos * 8]

	# For some reason if you constrain less bytes, the solution isn't found.
	for num in range(0, 75):
		initial_state.add_constraints(get_byte(argv1, num) != initial_state.se.BVV('\x00'))

	# The .se.BVV('\xXX') is required, just '\xXX' doesn't seem to work.
	initial_state.add_constraints(get_byte(argv1, 0) == initial_state.se.BVV('\x43')) # C
	initial_state.add_constraints(get_byte(argv1, 1) == initial_state.se.BVV('\x54')) # T
	initial_state.add_constraints(get_byte(argv1, 2) == initial_state.se.BVV('\x46')) # F

	initial_path = proj.factory.path(initial_state)
	path_group = proj.factory.path_group(initial_state)

	# 0x4005AA = starting of 'good' function
	# 0x400830 = thank you message
	# 0x400850 = activation failure

	path_group.explore(find=0x400830, avoid=0x400850)

	found = path_group.found[0]

	solution = found.state.se.any_str(argv1)
	solution = found.state.se.any_n_str(argv1, 100)
	print repr(solution)
	solution = solution[:solution.find("\x00")]
	print solution
	return solution

def test():
	assert main() == 'CTF{The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}'

if __name__ == '__main__':
	print(repr(main()))

#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri

import angr, claripy
import logging
logging.getLogger('angr.manager').setLevel(logging.DEBUG)

# import subprocess

# import IPython
# logging.getLogger('angr').setLevel(logging.DEBUG)

def main():
	project = angr.Project('./lab2C', load_options={"auto_load_libs": False})

	def correct(state):
		try:
			return 'You did it.' in state.posix.dumps(1)
		except:
			return False
	def wrong(state):
		try:
			return 'Not authenticated' in state.posix.dumps(1)
		except:
			return False

	input = claripy.BVS("input", 32*8)

	state = project.factory.entry_state(args=["./lab2C", input], add_options=angr.options.unicorn)

	simulation_manager = project.factory.simgr(state)

	# (•_•) ( •_•)>⌐■-■ (⌐■_■)
	simulation_manager.explore(find=correct, avoid=wrong)

	found = simulation_manager.found[-1]
	solution = found.se.eval(input, cast_to=str)

	return solution

def test():
	pass
	# solution = main()
	# stdout,_ = subprocess.Popen(["./lab2C", solution], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
	# print(stdout)
	# assert stdout == "You did it."

if __name__ == '__main__':
	print(repr(main()))

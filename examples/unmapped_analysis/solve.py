#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Example of halting on unmapped memory
#
# Solution for Eric Miller (Endgame)
# https://lists.cs.ucsb.edu/pipermail/angr/2017-September/000386.html

import angr
import logging
logging.getLogger('angr.manager').setLevel(logging.DEBUG)

# import IPython
# logging.getLogger('angr').setLevel(logging.DEBUG)

def main():
	project = angr.Project('./unmap', load_options={"auto_load_libs": False})
	state = project.factory.entry_state(add_options={angr.options.STRICT_PAGE_ACCESS})

	simulation_manager = project.factory.simulation_manager(state)

	# (•_•) ( •_•)>⌐■-■ (⌐■_■)
	simulation_manager.explore()

	keys = []

	for deadended in simulation_manager.deadended:
		print("Valid memory access triggered by %s" % repr(deadended.posix.dumps(0)))

	for errored in simulation_manager.errored:
		stdin = errored.state.posix.dumps(0)
		keys.append(stdin)
		print("%s caused by %s" % (errored.error, repr(stdin)))

	keys.sort()
	return keys

def test():
	keys = sorted(['e6dba991c1745128787fbc7a9843306cb2bcc63e', '275edf0657388c3a1197cdadfad7b96da0f977a3'])
	assert main() == keys

if __name__ == '__main__':
	main()

#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri

import angr, angrop
import logging
import IPython

logging.getLogger('angr').setLevel(logging.DEBUG)
logging.getLogger('angrop').setLevel(logging.DEBUG)


from addresses_list import *  # Private addreses

proj = angr.Project("./ram.raw.dump.bin", load_options={
	'main_opts': {
		'backend': 'blob',
		'custom_arch': 'mips',
		#'custom_base_addr': TODO,
		'custom_entry_point': ENTRY_ADDR,
		'segments': {(0x0, RAM_START_ADDR, RAM_SIZE)},
	},
	'auto_load_libs': False,  # Probably not needed.
})

secondary_objection = proj.loader.load_object('./ram.raw.dump.bin',
	backend=angr.cle.backends.blob.Blob, custom_arch='mips')

proj.loader.add_object(secondary_objection)

def smashed(path):
	ra = path.state.se.any_int(path.state.regs.ra)
	print "ra is at " + hex(ra)
	try:
		return (ra < RAM_START_ADDR or ra > RAM_START_ADDR+RAM_SIZE) and ra > 0
	except:
		return False

state = proj.factory.blank_state(addr=HANDLE_IP_ADDR) # add_options={"SYMBOLIC_WRITE_ADDRESSES"}
path = proj.factory.path(state)  # Set up the first path.
path_group = proj.factory.path_group(path)  # Create the path group.
path_group.explore(n=20, find=smashed)  # Increase/remove n, this is just a demo to cut it off short.

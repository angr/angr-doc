#!/usr/bin/env python2

"""
Author: David Manouchehri <manouchehri@protonmail.com>
DEFCON CTF Qualifier 2016
Challenge: baby-re
Team: hack.carleton
Write-up: http://hack.carleton.team/2016/05/21/defcon-ctf-qualifier-2016-baby-re/
Runtime: ~8 minutes (single threaded E5-2650L v3 @ 1.80GHz on DigitalOcean)

DigitalOcean is horrible for single threaded applications, I would highly suggest using something else.
"""

import angr

def main():
	proj = angr.Project('./baby-re',  load_options={'auto_load_libs': False})

	path_group = proj.factory.path_group(threads=4) # Doesn't really help to have more threads, but whatever.

	# If we get to 0x402941, "Wrong" is going to be printed out, so definitely avoid that.
	path_group.explore(find=0x40294b, avoid=0x402941) 
	# If you use anywhere before 0x40292c, angr won't have the flag to print out yet. So don't do that.

	return path_group.found[0].state.posix.dumps(1) # The flag is at the end.

	"""
	Note: There will be a bunch of warnings on your terminal that look like this.

	WARNING | 2016-05-21 17:34:33,185 | simuvex.plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
	WARNING | 2016-05-21 17:34:49,353 | simuvex.plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
	WARNING | 2016-05-21 17:35:11,810 | simuvex.plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
	WARNING | 2016-05-21 17:35:44,170 | simuvex.plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.

	Don't worry about these, they're not an issue for this challenge.
	"""

def test():
	assert 'Math is hard!' in main()


if __name__ == '__main__':
	print(repr(main()))

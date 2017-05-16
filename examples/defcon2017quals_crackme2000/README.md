# Solutions to DEFCON 2017 crackme2000 category

The 2017 DEFCON CTF qualifying event had an entire category of automated reverse engineering challenges.
We (Shellphish) solved all of them with angr (with, embarrassingly, one instance of light use of r2 to work around a PLT resolution bug).
This directory contains the solutions.
One day, we might add an explanation about how they work :-)

We didn't just use blind symbolic exploration for these ones -- we leveraged angr's static analysis to target it to specific code regions or, in some cases, avoid having to use it altogether.

The scripts:

- [magic](./magic.py)
- [occult](./occult.py) - angr has a PLT resolution bug that we'll get to eventually. In the meantime, we called out to r2
- [sorcery](./sorcery.py)
- [witchcraft](./witchcraft.py)
- [enlightenment](./enlightenment) - This was a superset of all the others, with some extra complications.

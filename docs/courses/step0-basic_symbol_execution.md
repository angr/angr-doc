# angr courses - Step 0 - Basic symbolic execution

The first thing you are going to do with angr is executing symbolicaly your
program. As a reminder, you can check what symbolic execution is [here](symbolic.md).

The binary and source code for this course can be found [here](./src/).

```python
>>> import angr

# We load the binary in angr
>>> project = angr.Project('docs/courses/src/step0.bin')

# Let's make things more readable
>>> addr_main = 0x4004a6
>>> first_jmp = 0x4004b9
>>> endpoint = 0x4004d6
>>> first_branch_left = 0x4004bb
>>> first_branch_right = 0x4004c2
>>> second_branch_left = 0x4004ca
>>> second_branch_right = 0x4004d1


# We create a state so that angr starts at the beginning of the main function
>>> main_state = project.factory.blank_state(addr=addr_main)
>>> pg = project.factory.path_group(main_state)
>>> assert pg.active[0].addr == addr_main


# Our path group hasn't done anything yet, so it only has one active path
# which address is main
# Let's step
# The pathgroup.step functions accepts different arguments to regulate
# the stepping. Here, let's try to step until we reach the first comparison
>>> pg.step(until=lambda p: p.active[0].addr >= first_jmp)


# We know have two active paths. Each of them took a branch from the
# comparison and will progress independently from the other one
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 2
>>> assert pg.active[0].addr == first_branch_left
>>> assert pg.active[1].addr == first_branch_right


# If we make the first path step, it will continue until reaching the endpoint
# The other one, however, will reach another comparison and should
# split again
>>> pg.step()
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 3
>>> assert pg.active[0].addr == endpoint
>>> assert pg.active[1].addr == second_branch_left
>>> assert pg.active[2].addr == second_branch_right


# Good We know have three paths
# - The two first paths reached the endpoint, and thus became deadended
# - The other one will have the same history thus stop stepping at the endpoint
>>> pg.step()
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 1
>>> assert len(pg.deadended) == 2
>>> assert pg.active[0].addr == endpoint


# The same effect can be done by using pathgroup.explore()
# The explorer will step every path until no more paths are active
>>> pg = project.factory.path_group(main_state)
>>> pg.explore()
>>> assert len(pg.active) == 0
```

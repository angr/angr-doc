# angr courses - Step 0 - Basic symbolic execution

The first thing you are going to do with angr is symbolically execute your
program. As a reminder, you can check what symbolic execution is [here](/docs/symbolic.md).

The binary and source code for this course can be found [here](./).

For reference, here's what the asm dump of `main` looks like:
```asm
main:
     0x004004a6  push rbp
     0x004004a7  mov rbp, rsp
     0x004004aa  mov dword [rbp - 4], edi
     0x004004ad  mov qword [rbp - 0x10], rsi
     0x004004b1  sub dword [rbp - 4], 1
     0x004004b5  cmp dword [rbp - 4], 0
     0x004004b9  jne 0x4004c2
     0x004004bb  mov eax, 0
     0x004004c0  jmp 0x4004d6
     0x004004c2  mov eax, dword [rbp - 4]
     0x004004c5  cmp eax, 1
     0x004004c8  jne 0x4004d1
     0x004004ca  mov eax, 1
     0x004004cf  jmp 0x4004d6
     0x004004d1  mov eax, 2
     0x004004d6  pop rbp
     0x004004d7  ret
```

```python
>>> import angr

# We load the binary in angr
>>> project = angr.Project('docs/courses/step0-basic_symbol_execution/step0.bin')

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

# Our path group hasn't done anything yet, so it only has one active path:
>>> assert len(pg.active) == 1

# Every active path represents has its own "Program Counter", which points at
# the instruction to be executed next. Our single active path is now now
# resting at the first instruction of `main`:
>>> assert pg.active[0].addr == addr_main

# One way to actually perform execution, is to use the `pathgroup.step`
# function. As we'll soon see, something special happens when we reach
# conditional branches, and angr's `pathgroup.step()` function by default
# advances each active path to the next such "event" in its own execution. But
# first, let's just step our active path by a single instruction, like we
# would in a debugger.
>>> pg.step(num_inst=1)
>>> assert pg.active[0].addr == 0x004004a7 # the 2nd instruction in main

# The `pathgroup.step` function can take various arguments which control
# what it does. For example, we can use the super-useful `until` kwarg
# to step the active path up to, but not past, the first conditional branch.
#
# Remember that, by default, pathgroup.step() advances not by a single
# instruction but to the next *basic block*, so if we want instead to stop at
# a specific address, we have to step one instruction at a time, so we specify
# `num_instr=1` again:
>>> pg.step(num_inst=1, until=lambda p: p.active[0].addr == first_jmp)
>>> assert len(pg.active) == 1 # still just one active path
>>> assert pg.active[0].addr == first_jmp # located just at the conditional branch

# Now it gets interesting.
#
# A conditional branch represents a fork in the CFG
# (control flow graph) because, execution may take one of two possible code
# paths at  this point, depending on whether the branch is taken or not. Of
# course, angr does *symbolic* execution, which means **we take both** code
# paths. In practice, what happens is that stepping over a conditional branch
# causes our single active path to split and become *two* active paths, both
# of which reside in our pathgroup. One active path represents the execution
# path that takes the conditional branch, and the other represents the one
# that didn't take it.
#
# Let's step on it:
>>> pg.step(num_inst=1)   # execute the conditional branch
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 2  # ZOMG!!!
>>> assert pg.active[0].addr == first_branch_left
>>> assert pg.active[1].addr == first_branch_right

# ... so now we have two <del>problems</del> active paths. Each is pointing at
# a different location corresponding to the two possible execution paths after
# the conditional branch is executed.
#
# Recall that when we step the group, each active path executes its own
# current instruction. Basically, as we step the group, each path executes
# independently. We'll do that in a second, but to keep things simple,
# Let's just step one path in isolation, and see where it goes, because
# this is open-source and we can just simply do that:
>>> goes_its_own_way_path = pg.active[0].step(num_inst=1)
>>> assert len(goes_its_own_way_path) == 1 # why a list??
>>> assert goes_its_own_way_path[0].addr == first_branch_left+5 # The following instruction
>>> assert pg.active[0].addr == first_branch_left # hasn't moved?!?
>>> assert pg.active[1].addr == first_branch_right # hasn't moved

# Well, that requires some 'splaining.
#
# - Why didn't pg.active[0].addr change? Stepping doesn't mutate the Path
#   it operates on, it returns a new path object with new state.
#   This is a Feature! It means you can grab a specific path from a group
#   and play with it, without interfering with future stepping of
#   the pathgroup. This is also a detail that pathgroup.step() conveniently
#   hides from us, when we don't need it.
#
# - Why does the result of the step return a singleton list of Path
#   instead of just a straight-up Path object? ah, so you noticed. Good for you.
#   Well, if the instruction executed was a conditional branch, it would split
#   the active path into two, right?

# Ok,  let's get back to our (completely unaffected by that little experiment)
# path group. Where were we?
>>> assert len(pg.active) == 2  # ZOMG!!!

# Ah, yes. Let's step some more. In fact, let's step it up!
>>> pg.step() # step all active paths in the group
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 3
>>> assert pg.active[0].addr == endpoint
>>> assert pg.active[1].addr == second_branch_left
>>> assert pg.active[2].addr == second_branch_right

# ... what just happened there?
#
# We stepped the group, which by default means that every active path
# in the group jumps fast-forwards through its current basic block.
#
# The first path, the one which didn't take the conditional branch at first_jmp,
# took the unconditional jump at 0x004004c0 and is now at the start of the
# basic block at 0x004004d6.
#
# The 2nd active path zoomed past the 2nd conditional branch at 0x004004c8
# and split into two active paths (paths 2 and 3), as it is wont to do.
# Because in angr, unlike in Robert Frost, one never meets a "Road Not Taken".
# Unless one optimizes. This demonstrates, yet again, the dubious, and completely illusory,
# supremacy of code over poetry. Or something.

# Good. So now we have three paths. Careful, Not one more step! well... ok, just one.
>>> pg.step()
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 1
>>> assert len(pg.deadended) == 2
>>> assert pg.active[0].addr == endpoint

# We've got two "deadended" paths. What does that mean? It simply means that two of our paths
# have reached and executed an exit point from the program, in this case the `ret` instruction
# at 0x004004d7, and have now moved on to execute that great basic block in the sky. deadended
# paths are "retired", and further stepping will does not affect them.
#

# All the manual stepping we've done up to this point isn't strictly
# necessary, we could just have used `pathgroup.explore()` to reach this
# point. The explorer will step every path until no more paths are active
#
# Of course, we'd like to extract some information from our execution,
# such as what input corresponds to a specifc code path we're interested
# in, such as the "You Win!" code path for example. More on that and
# how we can use the `pathgroup.explore()` function to do that can
# be found in later lessos. It's all about "finding" what we want and
# "avoiding" what we don't.
>>> pg = project.factory.path_group(main_state)
>>> pg.explore()
>>> assert len(pg.active) == 0
```

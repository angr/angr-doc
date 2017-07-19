Bulk Execution and Exploration - Path Groups
============================================

Path groups are just a bunch of paths being executed at once. They are also the future.

Path groups let you wrangle multiple paths in a slick way.
Paths are organized into “stashes”, which you can step forward, filter, merge,
and move around as you wish. There are different kind of stashes, which are
specified in [Paths](./paths.md#path-types). This allows you to, for example,
step two different stashes of paths at different rates, then merge them together.


Here are some basic examples of SimulationManager capabilities:
```python
>>> import angr


>>> p = angr.Project('examples/fauxware/fauxware', load_options={'auto_load_libs': False})
>>> sm = p.factory.simgr()
```

Exploring a state:
```python
# While there are active path, we step
>>> while len(sm.active) > 0:
...    sm.step()

>>> print(sm)
<SimulationManager with 3 deadended>
```

We now have 3 deadended states, let's see what we can do with it
```python
>>> state = sm.deadended[0]
>>> print 'State length: %d steps' % len(state.history.descriptions)
State length: 51 steps
```

Get state trace:
```python
>>> print 'Trace:'
>>> for step in state.history.descriptions:
...    print step
Trace:
<IRSB from 0x400580: 1 sat>
<IRSB from 0x400540: 1 sat>
<SimProcedure __libc_start_main from 0x1000030: 1 sat>
<IRSB from 0x4007e0: 1 sat>
<IRSB from 0x4004e0: 1 sat>
<IRSB from 0x4005ac: 1 sat 1 unsat>
<IRSB from 0x4005be: 1 sat>
<IRSB from 0x4004e9: 1 sat>
<IRSB from 0x400640: 1 sat 1 unsat>
<IRSB from 0x400660: 1 sat>
<IRSB from 0x4004ee: 1 sat>
<IRSB from 0x400880: 1 sat 1 unsat>
<IRSB from 0x4008af: 1 sat>
<IRSB from 0x4004f3: 1 sat>
<IRSB from 0x400825: 1 sat 1 unsat>
<IRSB from 0x400846: 1 sat>
<SimProcedure __libc_start_main from 0x1000040: 1 sat>
<IRSB from 0x40071d: 1 sat>
<IRSB from 0x400510: 1 sat>
<SimProcedure puts from 0x1000000: 1 sat>
<IRSB from 0x40073e: 1 sat>
<IRSB from 0x400530: 1 sat>
<SimProcedure read from 0x1000020: 1 sat>
<IRSB from 0x400754: 1 sat>
<IRSB from 0x400530: 1 sat>
<SimProcedure read from 0x1000020: 1 sat>
<IRSB from 0x40076a: 1 sat>
<IRSB from 0x400510: 1 sat>
<SimProcedure puts from 0x1000000: 1 sat>
<IRSB from 0x400774: 1 sat>
<IRSB from 0x400530: 1 sat>
<SimProcedure read from 0x1000020: 1 sat>
<IRSB from 0x40078a: 1 sat>
<IRSB from 0x400530: 1 sat>
<SimProcedure read from 0x1000020: 1 sat>
<IRSB from 0x4007a0: 1 sat>
<IRSB from 0x400664: 1 sat>
<IRSB from 0x400550: 1 sat>
<SimProcedure strcmp from 0x1000050: 1 sat>
<IRSB from 0x40068e: 2 sat>
<IRSB from 0x400692: 1 sat>
<IRSB from 0x4006eb: 1 sat>
<IRSB from 0x4007b3: 1 sat 1 unsat>
<IRSB from 0x4007bd: 1 sat>
<IRSB from 0x4006ed: 1 sat>
<IRSB from 0x400510: 1 sat>
<SimProcedure puts from 0x1000000: 1 sat>
<IRSB from 0x4006fb: 1 sat>
<IRSB from 0x4007c7: 1 sat>
<IRSB from 0x4007d3: 1 sat>
<SimProcedure __libc_start_main from 0x1000040: 1 sat>
```

Get constraints applied to the state:
```python
>>> print 'There are %d constraints.' % len(state.se.constraints)
There are 2 constraints.
```

Get memory state at the end of the traversal:
```python
>>> print 'rax: %s' % state.regs.rax
rax: <BV64 0x37>
>>> assert state.se.any_int(state.regs.rip) == state.addr  # regs are BitVectors
```

### PathGroup.Explorer()
Pathgroups are supposed to replace `surveyors.Explorer`, being more clever and
efficient. When launching path_group.Explore with a `find` argument, multiple
paths will be launched and step until one of them finds one of the address we
are looking for. Paths reaching the `avoided` addresses, if any, will be put
into the `avoided` stash. If an active path reaches an interesting address, it
will be stashed into the `found` stash, and the other ones will remain active.
You can then explore the found path, or decide to discard it and continue with
the other ones.

Let's look at a simple crackme [example](./examples.md#reverseme-modern-binary-exploitation---csci-4968):

First, we load the binary.
```python
>>> p = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
```

Next, we create a SimulationManager.
```python
>>> sm = p.factory.simgr()
```

Now, we symbolically execute until we find a state that matches our condition (i.e., the "win" condition).
```python
>> sm.explore(find=lambda s: "Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
```

Now, we can get the flag out of that state!
```
>>> s = sm.found[0]
>>> print s.posix.dumps(1)
Enter password: Congrats!


>>> flag = s.posix.dumps(0)
>>> print(flag)
g00dJ0B!
```

Pretty simple, isn't it?

Other examples can be found by browsing the [examples](./examples.md).


## TODO: STASHES

## Stash types

Paths are put into different stashes during a PathGroup's execution.
These are:

| Stash | Description |
|-------|-------------|
| active     | This stash contains the paths that will be stepped by default (unless an alternate stash is specified for `path_group.step()`. |
| deadended     | A path goes to the deadended stash when it cannot continue the execution for some reason, including no more valid instructions, unsat state of all of its successors, or an invalid instruction pointer. |
| found         | A path goes to the found stash when the path group determines that it matches the condition passed to the `find` argument of `path_group.explore`. |
| avoided         | A path goes to the avoided stash when the path group determines that it matches the condition passed to the `avoid` argument of `path_group.explore`. |
| pruned        | When using `LAZY_SOLVES`, paths are not checked for satisfiability unless absolutely necessary. When a state is found to be unsat in the presence of `LAZY_SOLVES`, the path hierarchy is traversed to identify when, in its history, it initially became unsat. All paths that are descendent from that point (which will also be unsat, since a state cannot become un-unsat) are pruned and put in this stash. |
| errored       | Paths are put in this stash when they cause a Python exception to be raised during execution. This implies a bug in angr or in your custom code (if any). |
| unconstrained | If the `save_unconstrained` option is provided to the PathGroup constructor, paths that are determined to be unconstrained (i.e., with the instruction pointer controlled by user data or some other source of symbolic data) are placed here. |
| unsat | If the `save_unsat` option is provided to the PathGroup constructor, paths that are determined to be unsatisfiable (i.e., they have constraints that are contradictory, like the input having to be both "AAAA" and "BBBB" at the same time) are placed here. |

You can move paths between stashes by using the `path_group.move` function.
This function accepts many options to control which paths are moved between which stashes.

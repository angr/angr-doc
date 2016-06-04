Bulk Execution and Exploration - Path Groups
============================================

Path groups are just a bunch of paths being executed at once. They are also the future.

Path groups let you wrangle multiple paths in a slick way.
Paths are organized into “stashes”, which you can step forward, filter, merge,
and move around as you wish. There are different kind of stashes, which are
specified in [Paths](./paths.md#path-types). This allows you to, for example,
step two different stashes of paths at different rates, then merge them together.


Here are some basic examples of pathgroups capabilities:
```python
>>> import angr


>>> p = angr.Project('/bin/ls', load_options={'auto_load_libs': False})
>>> pg = p.factory.path_group()
```

Exploring a path:
```python
# While there are active path, we step
>>> while len(pg.active) > 0:
...    pg.step()

>>> print(pg)
<PathGroup with 1 deadended>
```

We now have a deadended path, let's see what we can do with it
```python
>>> path = pg.deadended[0]
>>> print('Path length: {0} steps'.format(path.length))
Path length: 23 steps
```

Get path trace:
```python
>>> print('Trace:')
>>> for step in path.trace:
...    print(step)
Trace:
<SimIRSB 0x4049a0>
<SimIRSB 0x402650>
<SimProcedure __libc_start_main>
<SimIRSB 0x413930>
<SimIRSB 0x4022d0>
<SimIRSB 0x4022e5>
<SimIRSB 0x413961>
<SimIRSB 0x413966>
<SimIRSB 0x404a70>
<SimIRSB 0x404a7b>
<SimIRSB 0x404a10>
<SimIRSB 0x404a48>
<SimIRSB 0x41397d>
<SimIRSB 0x413986>
<SimProcedure __libc_start_main>
<SimIRSB 0x402a00>
<SimIRSB 0x40da70>
<SimIRSB 0x40dae3>
<SimIRSB 0x402950>
<SimProcedure fwrite>
<SimIRSB 0x40dafe>
<SimIRSB 0x402390>
<SimProcedure abort>
```

Get constraints applied to the path:
```python
>>> print('Constraints:')
>>> for c in path.state.se.constraints:
...    print(c)
Constraints:
<Bool mem_70_7_32 == 0x0>
```

Get memory state at the end of the traversal:
```python
>>> print('rax: {0}'.format(path.state.regs.rax))
rax: <BV64 0x37>
>>> assert path.state.regs.rip.args[0] == path.addr  # regs are BitVectors
```

### PathGroup.Explorer()
Pathgroups are supposed to replace `surveyors.Explorer`, being more clever and
efficient. When launching path_group.Explore with a `find` argument, multiple
paths will be launched and step until one of them finds one of the address we
are looking for. Paths reaching the `avoid`ed addresses, if any, will be put
into the `avoided` stash. If an active path reaches an interesting address, it
will be stashed into the `found` stash, and the other ones will remain active.
You can then explore the found path, or decide to discard it and continue with
the other ones.

Example from a DefconCTF Quals [exercise](./examples.md#reverseme-example-defcon-quals-2016---baby-re):

```python
>>> p = angr.Project('examples/defcon2016quals_baby-re_1/baby-re')
```

Setting the environment (state)
```python
>>> main = 0x4025e7 # Beginning of function we want to explore
>>> win = 0x4028e9  # Address we want to reach
>>> fail = 0x402941 # Address we want to avoid
>>> flag_addr = 0x7fffffffffeff98
[...]
>>> init = p.factory.blank_state(addr=main)
```

Creating and lauching the explorer
```python
>>> pgp = p.factory.path_group(init)
>>> ex = pgp.explore(find=win, avoid=fail)
>>> print(ex)
<PathGroup with 11 avoid, 2 active, 1 found>
>>> s = ex.found[0].state
>>> flag = s.se.any_str(s.memory.load(flag_addr, 50))
>>> print(flag)
Math is hard!
```

Pretty simple, isn't it ?

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
| pruned        | When using LAZY_SOLVES, paths are not checked for satisfiability unless absolutely necessary. When a state is found to be unsat in the presence of LAZY_SOLVES, the path hierarchy is traversed to identify when, in its history, it initially became unsat. All paths that are descendent from that point (which will also be unsat, since a state cannot become un-unsat are pruned and put in this stash. |
| errored       | Paths are put in this stash when they cause a Python exception to be raised during execution. This implies a bug in angr or in your custom code (if any). |
| unconstrained | If the `save_unconstrained` option is provided to the PathGroup constructor, paths that are determined to be unconstrained (i.e., with the instruction pointer controlled by user data or some other source of symbolic data) are placed here. |
| unsat | If the `save_unsat` option is provided to the PathGroup constructor, paths that are determined to be unsatisfiable (i.e., they have constraints that are contradictory, like the input having to be both "AAAA" and "BBBB" at the same time) are placed here. |

You can move paths between stashes by using the `path_group.move` function.
This function accepts many options to control which paths are moved between which stashes.

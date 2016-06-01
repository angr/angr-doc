Bulk Execution and Exploration - Path Groups
============================================

Path groups are just a bunch of paths being executed at once. They are also the future.

```python
>>> import angr


>>> p = angr.Project('/bin/ls', load_options={'auto_load_libs': False})
>>> pg = p.factory.path_group()
```

They are supposed to replace `surveyors.Explorer`, being more clever and efficient:

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

Best way to see how they work is to browse the [examples](./examples.md).

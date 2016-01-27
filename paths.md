# Program Paths

A path through a program is, at its core, a sequence of basic blocks representing what was executed since the program started.
These blocks in the paths can repeat (in the case of loops) and a program can have a near-infinite amount of paths (for example, a program with a single branch will have two paths, a program with two branches nested within each other will have 4, and so on).

angr represents a path by using the Path class.
The Path class will be used in most interactions with angr and in most of angr's analyses.
To create a blank path, do:

```python
# load a binary

>>> import angr
>>> b = angr.Project('/bin/true')

# load the path
>>> p = b.factory.path()

# this is the address that the path is *about to* execute
>>> assert p.addr == b.entry
```

After this, `p` is a path representing the program at the entry point.
We can see that the callstack is blank, for example.

```python
# this is the number of basic blocks that have been analyzed by the path
# TODO: FUCKING FIX THESE
>>> # assert p.length == 0

# normally, this would be a sequence of addresses representing the basic blocks that were executed
>>> # assert len(p.addr_backtrace) == 0

# this holds a set of string representations of what was executed
>>> assert len(p.backtrace) == 0

# this holds the history of *functions* that have been executed
>>> assert len(p.callstack) == 0

# this holds the history of path events. This can include memory accesses by the program, logging statements by the analysis core, and so forth
>>> assert len(p.events) == 0

# convenience access is provided to see just the program actions (i.e., memory accesses)
>>> assert len(p.actions) == 0

```

## Moving Forward

Of course, we can't be stuck at the entry point forever. call `p.step()` to run the single block of symbolic execution.
We can look at the `successors` of a path to see where the program goes after this point. `p.step()` also returns the successors if you'd like to chain calls.
Most of the time, a path will have one or two successors. When there are two successors, it usually means the program branched and there are two possible ways forward with execution. Other times, it will have more than two, such as in the case of a jump table.

```python
>>> p.step()
>>> print "The path has", len(p.successors), "successors!"

# each successor is a path, with its backtrace, events, etc
>>> s = p.successors[0]
>>> # assert len(s.addr_backtrace) == 1
>>> assert len(s.backtrace) == 1
>>> # assert len(s.events) > 0
>>> assert len(s.actions) <= len(s.events)

# and, of course, we can drill down further
>>> ss = s.step()[0].step()[0].step()[0]
>>> # assert len(ss.addr_backtrace) == 4
>>> # assert len(ss.events) > len(s.events)

# we can also access the events and actions from just the last basic block
>>> # assert len(ss.last_events) < len(ss.events)
>>> # assert len(ss.last_actions) < len(ss.actions)
```

Part of the history of a path is the *types* of jumps that occur.
These are stored (as strings representing VEX exit type enums), in the `jumpkinds` attribute.

```python
>>> assert p.jumpkinds[0] == 'Ijk_Boring'
```

Here are the different types of jumpkinds:

| Type | Description |
|------|-------------|
| Ijk_Boring | A normal jump to an address. |
| IjK_Call | A call to an address. |
| Ijk_Ret | A return. |
| Ijk_Sig* | Various signals. |
| Ijk_Sys* | System calls. |

Additionally, the jump *condition* is recorded.

```python
>>> print "The conditions that had to be true to take path `p` are:"
>>> for i in p.guards:
...     print i
```

## Merging Paths

Like states, paths can be merged.
Truly understanding this requires concepts that will be explained in future sections, but in a nutshell, we can combine two paths that reached the same program point in different ways.
For example, let's say that we have a branch:

```python
# step until branch
p = b.factory.path()
p.step()
while len(p.successors) == 1:
    print 'step'
    p = p.successors[0]
    p.step()

print p
print p.backtrace
branched_left = p.successors[0]
branched_right = p.successors[1]
assert branched_left.addr != branched_right.addr

after_branched_left = branched_left.step()[0]
after_branched_right = branched_right.step()[0]
assert after_branched_left.addr == after_branched_right.addr

# this will merge both branches into a single path. Values in memory and registers
# will hold any possible values they could have held in either path.
merged = branched_left.merge(branched_right)

assert merged.addr == branched_left.addr and merged.addr == branched_right.addr
```

Paths can also be unmerged later.

```python
merged_successor = merged.step()[0].step()[0]
unmerged_paths = merged_successor.unmerge()

assert len(unmerged_paths) == 2
assert unmerged_paths[0].addr == unmerged_paths[1].addr
```

## Non-entry point start

Sometimes, you might want to start the analysis of a program partway through the program.
For example, you might be interested in what a specific part of a function does, but don't know how to (or don't want to) guide a path to that point.
To handle this, we allow the creation of a path at any point in the program:

```python
>>> st = b.factory.blank_state(addr=0x800f000)
>>> p = b.factory.path(st)

>>> assert p.addr == 0x800f000
```

At this point, all memory, registers, and so forth of the path are blank.
We'll explore what this means, and its implications, in future sections.

## Semantic Actions

SimuVEX exposes the actions of a basic blocks through the concept of "actions".
An action has an associated `type` (i.e., "mem" for memory, "reg" for registers, "tmp" for temps), and `action` ("read", "write").

Here is an example interaction with the actions:

```python
>>> p = b.factory.path().step()[0]

>>> for a in p.last_actions:
...     if a.type == 'mem':
...         print "Memory write to", a.addr.ast
...         print "... address depends on registers", a.addr.reg_deps, "and temps", a.addr.tmp_deps
...         print "... data is:", a.data.ast
...         print "... data depends on registers", a.data.reg_deps, "and temps", a.data.tmp_deps
...         if a.condition is not None:
...             print "... condition is:", a.condition.ast
...         if a.fallback is not None:
...             print "... alternate write in case of condition fail:", a.fallback.ast
...     elif a.type == 'reg':
...         print 'Register write to registerfile offset', a.offset
...     elif a.type == 'tmp':
...         print 'Tmp write to tmp', a.tmp
```

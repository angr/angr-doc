Program Paths - Controlling Execution
=====================================

Dealing with SimStates and SimEngines directly provides an incredibly awkward interface for performing symbolic execution.
Paths are angr's primary interface to provide an abstraction to control execution, and are used in most interactions with angr and its analyses.

A path through a program is, at its core, a sequence of basic blocks (actually, individual executions of a `angr.SimEngine`) representing what was executed since the program started.
These blocks in the paths can repeat (in the case of loops) and a program can have a near-infinite amount of paths (for example, a program with a single branch will have two paths, a program with two branches nested within each other will have 4, and so on).

To create an empty path at the program's entry point, do:

```python
# load a binary

>>> import angr
>>> b = angr.Project('/bin/true')

# load the state
>>> s = b.factory.entry_state()

# this is the address that the path is *about to* execute
>>> assert s.addr == b.entry
```

After this, `s` is a state representing the program at the entry point.
We can see that the callstack and the state's history are blank:

```python
# this is the number of basic blocks that have been analyzed by the path
>>> assert s.history.block_count == 0

# we can also look at the current backtrace of program execution
# contains only the dummy frame for execution start
>>> assert len(s.callstack) == 1
>>> print s.callstack
Backtrace:
Func 0x401410, sp=0x7fffffffffeffd8, ret=0x0
```

## Moving Forward

Of course, we can't be stuck at the entry point forever. call `p.step()` to run the single block of symbolic execution.
We can look at the `successors` of a path to see where the program goes after this point. `p.step()` also returns the successors if you'd like to chain calls.
Most of the time, a path will have one or two successors. When there are two successors, it usually means the program branched and there are two possible ways forward with execution. Other times, it will have more than two, such as in the case of a jump table.

```python
>>> new_states = b.factory.successors(s).flat_successors
>>> print "The path has", len(new_states), "successors!"

# each successor is a path, keeping track of an execution history
>>> new_state = new_states[0]
>>> assert new_state.history.bbl_addrs[-1] == s.addr
>>> s = new_state

# and, of course, we can drill down further!
# alternate syntax: s.step() returns the same list as s.successors
>>> ss = b.factory.successors(b.factory.successors(s).flat_successors[0]).flat_successors[0]
>>> len(ss.history.bbl_addrs.hardcopy) == 2
```

To efficiently store information about path histories, angr employs a tree structure that resembles the actual symbolic execution tree.
You should never have to worry about this, since through the magic of python we provide efficient accessors for information stored in the tree as it pertains to each stored historical property.
The one thing you have to know is that this data structure doesn't allow efficient iteration through the historical lists in forward order - only in reverse order, from most recent to oldest.
If you need to iterate or access items from these sequences starting from the beginning, you may access the `.hardcopy` property on them, which will extract the entirety of the property's history as a flat list for you to peruse at leisure.

For example: part of the history of a path is the *types* of jumps that occur.
These are stored (as strings representing VEX exit type enums), in the `jumpkinds` attribute.

```python
# recall: s is the path created when we stepped forward the initial path once
>>> print s.history.jumpkinds
<angr.path.JumpkindIter object at 0x7f8161e584d0>

>>> assert s.history.jumpkinds[-1] == 'Ijk_Call'
>>> print s.history.jumpkinds.hardcopy
['Ijk_Call']

# Don't do this! This will throw an exception
>>> # for jk in ss.jumpkinds: print jk

# Do this instead:
>>> for jk in reversed(ss.history.jumpkinds): print jk
Ijk_Call
Ijk_Call
Ijk_Boring
Ijk_Call

# Or, if you really need to iterate in forward order:
>>> for jk in ss.history.jumpkinds.hardcopy: print jk
Ijk_Call
Ijk_Boring
Ijk_Call
Ijk_Call
```

Here is a list of the properties in the path history:

| Property        | Description |
|-----------------|-------------|
| Path.addr_trace | The addresses of basic blocks that have been executed so far, as integers |
| Path.trace      | The SimSuccessors objects that have been generated so far, as strings |
| Path.targets    | The targets of the jumps/successors that have been taken so far |
| Path.guards     | The guard conditions that had to be satisfied in order to take the branch listed in Path.targets |
| Path.jumpkinds  | The type of the exit from each basic block we took, as VEX struct strings |
| Path.events     | A log of the events that have happened in symbolic execution |
| Path.actions    | A filtering of Path.events to only include the actions taken by the execution engine. See below. |

Here are the different types of jumpkinds:

| Type       | Description |
|------------|-------------|
| Ijk_Boring | A normal jump to an address. |
| Ijk_Call   | A call to an address. |
| Ijk_Ret    | A return. |
| Ijk_Sig*   | Various signals. |
| Ijk_Sys*   | System calls. |
| Ijk_NoHook | A jump out of an angr hook. |

## Merging Paths

Like states, paths can be merged.
Truly understanding this requires concepts that will be explained in future sections, but in a nutshell, we can combine two paths that reached the same program point in different ways.
For example, let's say that we have a branch:

```python
# step until branch
s = b.factory.entry_state()
next = b.factory.successors(s).flat_successors
while len(b.factory.successors(s).flat_successors) == 1:
    print 'step'
    s = b.factory.successors(s).flat_successors[0]

print s
branched_left = b.factory.successors(s).flat_successors[0]
branched_right = b.factory.successors(s).flat_successors[1]
assert branched_left.addr != branched_right.addr

# Step the branches until they converge again
after_branched_left = b.factory.successors(branched_left).flat_successors[0]
after_branched_right = b.factory.successors(branched_right).flat_successors[0]
assert after_branched_left.addr == after_branched_right.addr

# this will merge both branches into a single path. Values in memory and registers
# will hold any possible values they could have held in either path.
merged = after_branched_left.merge(after_branched_right)
assert merged.addr == after_branched_left.addr and merged.addr == after_branched_right.addr
```

Paths can also be unmerged later.

```python
merged_successor = b.factory.successors(b.factory.successors(merged).flat_successor)[0]).flat_successors[0]
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

>>> assert st.addr == 0x800f000
```

At this point, all memory, registers, and so forth of the path are blank. In a nutshell, this means that they are fully symbolic and unconstrained, and execution can proceed from this point as an over-approximation of what could happen on a real CPU. If you have outside knowledge about what the state should look like at this point, you can craft the blank state into a more precise description of machine state by adding constraints and setting the contents of memory, registers, and files.

## SimActions Redux

The SimActions from deep within the simulation engine are exported for much easier access through the Path. Actions are part of the path's history (Path.actions), so the same rules as the other history items about iterating over them still apply.

When paths grow long, stored SimActions can be a serious source of memory consumption. Because of this, by default all but the most recent SimActions are discarded. To disable this behavior, enable the `TRACK_ACTION_HISTORY` state option.

There is a convenient interface for filtering through a potentially huge list of actions to find a specific write or read operation. Take a look at the [api documentation for Path.filter_actions](http://angr.io/api-doc/angr.html#angr.path.Path.filter_actions).

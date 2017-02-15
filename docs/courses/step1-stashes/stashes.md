# angr courses - step 1 - stashes

The binary and source code for this course can be found [here](./).

##### Background: Stashes
The path group is angr's interface to symbolic execution.
Like the name says, it organizes different paths throughout the binary in different groups, called *stashes*.
The most common stashes are *active*, *deadended*, *found* and *avoid*.
For more information, visit the [pathgroup doc](/docs/pathgroups.md).

```python
>>> import angr

# Load the binary into the project
# We don't want external libraries to be analyzed so dont load them, they will be replaced by angr
>>> proj = angr.Project("docs/courses/step1-stashes/step1.bin", load_options={'auto_load_libs': False})

# Create a control flow graph to find functions addresses
>>> proj.analyses.CFG()
>>> addr_puts = proj.kb.functions.function(name="puts").addr
>>> addr_main = proj.kb.functions.function(name="main").addr
>>> addr_path_explosion = 0x400591

# Create the path group
>>> pg = proj.factory.path_group()

# Explore until printf (puts) was found while avoiding the path explosion
>>> pg.explore(find=addr_puts, avoid=addr_path_explosion)

>>> assert len(pg.active) == 1
>>> assert len(pg.found) == 1
>>> assert len(pg.avoid) == 1

>>> print pg

# You can also explore the remaining active paths
>>> pg.explore()

>>> assert len(pg.active) == 0
>>> assert len(pg.deadended) == 1

>>> print pg
```
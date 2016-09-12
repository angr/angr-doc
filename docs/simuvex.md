SimuVEX and Bare-Bones Symbolic Execution
=========================================

Most analyses require an understanding of what the code is *doing* (semantic meaning), not just what the code *is* (syntactic meaning).
For this, we developed a module called SimuVEX (https://github.com/angr/simuvex). SimuVEX provides a semantic understanding of what a given piece of VEX code does on a given machine state.

In a nutshell, SimuVEX is a symbolic VEX emulator.
Given a machine state and a VEX IR block, SimuVEX provides a resulting machine state (or, in the case of condition jumps, *several* resulting machine states).

# Semantic Translation

SimuVEX's ultimate goal is to provide a semantic meaning to blocks of binary code.

While the IR gives us syntactic meaning (i.e., what statements the block contains), SimuVEX can provide us semantic meaning (i.e., what the block *does* to a given state).
We'll now move on to how to do that.

## Accessing SimIRSBs

We get semantic meaning by converting an IRSB into a SimIRSB.
While the former focuses on providing a cross-architecture, programmatically-accessible representation of what a block is, the latter provides a cross-platform, programmatically-accessible representation of what a block did, given an input state.

**Note that you will almost never need to interact with SimIRSBs directly.** The higher level angr interfaces complete abstract away simuvex's pedantic execution model, but it's important to understand the way that execution happens.

To create a SimIRSB directly, use the `sim_block(state)` constructor in the project factory. Here's an example.

```python
# This creates a symbolic state with execution starting at 0x400664,
# and then symbolically executes the IRSB at its instruction pointer.
>>> import angr, simuvex
>>> b = angr.Project('examples/fauxware/fauxware')
>>> state = b.factory.blank_state(addr=0x400664)
>>> sirsb = b.factory.sim_block(state)

# this is the address of the first instruction in the block
>>> assert sirsb.addr == 0x400664
```

### What happened?

Symbolic execution happened! `sirsb` is now a record of what happened during the symbolic execution of this basic block. This information is exposed in the form of SimActions. In case you hadn't noticed, everything that comes out of simuvex has "Sim-" on the front of its name.

An IRSB has Statements, so a SimIRSB has SimStatements. Each statement has a list of SimActions recording each of its reads and writes to and from memory, registers, and temps.
A SimAction has an associated `type` (i.e., "mem" for memory, "reg" for registers, "tmp" for temps), and `action` ("read", "write").

```python
# Print out all the actions for this block:
>>> for sstmt in sirsb.statements:
...     print '[+] Actions for statement %d' % sstmt.stmt_idx
...     for a in sstmt.actions:
...         if a.type == 'mem':
...             print "Memory write to", a.addr.ast
...             print "... address depends on registers", a.addr.reg_deps, "and temps", a.addr.tmp_deps
...             print "... data is:", a.data.ast
...             print "... data depends on registers", a.data.reg_deps, "and temps", a.data.tmp_deps
...             if a.condition is not None:
...                 print "... condition is:", a.condition.ast
...             if a.fallback is not None:
...                 print "... alternate write in case of condition fail:", a.fallback.ast
...         elif a.type == 'reg':
...             print 'Register write to registerfile offset', a.offset
...             print "... data is:", a.data.ast
...         elif a.type == 'tmp':
...             print 'Tmp write to tmp', a.tmp
...             print "... data is:", a.data.ast
```

### Where are we going?

For each Exit in the IRSB, there will be a new successor SimState! Each successor will be a copy of the original state you started with, plus the modifications described by the SimActions, plus the *constraints* added to the solver engine by the exit you've taken. For boring jump exits, no constraints are added, but for conditional jumps, the successor that took the jump gets the *guard condition* of the jump exit, while the *default successor* gets the negation.

```python
# The list of successors:
>>> for succ in sirsb.all_successors:
...     print succ

# The default successor, i.e. the one that runs off the end of the block:
>>> print sirsb.default_exit

# Any unconstrained successors, that is, successors with symbolic instruction pointers:
>>> for succ in sirsb.unconstrained_successors:
...     print succ

# Any successors whose constraints contain a contradition (not necessarily a complete list):
>>> for succ in sirsb.unsat_successors:
...     print succ
```

## SimProcedures

Fun fact: SimIRSBs aren't the only way to step symbolic execution forward! SimIRSBs inherit the SimRun class, which is a generic class for describing execution steps.

At the moment, the only other important SimRun is the *SimProcedure*. SimProcedures are, first and foremost, *symbolic function summaries*: angr handles functions imported into the binary by executing a SimProcedure that symbolically implements the given library function, if one exists. SimProcedures are a generic enough interface to do more than this, though - they can be used to run Python code to mutate a state at any point in execution.

SimProcedures are injected into angr's execution pipeline through an interface called *hooking*. The full interface is described [here](toplevel.md#hooking), but the most important part is the `Project.hook(address, procedure)` method. After running this, whenever execution in this project reaches `address`, instead of running the SimIRSB at that address, we run the SimProcedure specified by the `procedure` argument.

`Project.hook` can also take a plain python function as an argument, instead of a SimProcedure class. That function will be automatically wrapped by a SimProcedure and executed (with the current SimState) as its argument.

Nobody actually calls `Project.factory.sim_block`, like in the example above. Instead, use `Project.factory.sim_run`, which has the exact same interface but will chose what kind of SimRun to create. Again, **this is still a very low-level interface that you normally shouldn't have to touch while writing analyses with angr.**

TODO: Programming SimProcedures. Cover all the kinds of control flow, inline calls, etc. If you want to program a SimProcedure now, look at [the library of already-written ones](https://github.com/angr/simuvex/tree/master/simuvex/procedures).

## Putting it all together

Now you have all the components necessary to do the most basic symbolic execution with angr! The below code will execute all possible paths through a binary.

```python
# Note: please don't actually do this. This will eat up all your computer's RAM and you will die.
# Also there's no error handling at all!

states = [b.factory.entry_state()]
while len(states) > 0:
    successors = []
    for state in states:
        successors.extend(b.factory.sim_run(state).all_successors)
    states = successors
```

# Breakpoints!

Like any decent execution engine, SimuVEX supports breakpoints. This is pretty cool! A point is set as follows:

```python
# get our state
>>> s = b.factory.entry_state()

# add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
>>> s.inspect.b('mem_write')

# on the other hand, we can have a breakpoint trigger right *after* a memory write happens. On top of that, we
# can have a specific function get run instead of going straight to ipdb.
>>> def debug_func(state):
...     print "State %s is about to do a memory write!"

>>> s.inspect.b('mem_write', when=simuvex.BP_AFTER, action=debug_func)

# or, you can have it drop you in an embedded ipython!
>>> s.inspect.b('mem_write', when=simuvex.BP_AFTER, action='ipython')
```

There are many other places to break than a memory write. Here is the list. You can break at BP_BEFORE or BP_AFTER for each of these events.

| Event type        | Event meaning |
|-------------------|------------------------------------------|
| mem_read          | Memory is being read. |
| mem_write         | Memory is being written. |
| reg_read          | A register is being read. |
| reg_write         | A register is being written. |
| tmp_read          | A temp is being read. |
| tmp_write         | A temp is being written. |
| expr              | An expression is being created (i.e., a result of an arithmetic operation or a constant in the IR). |
| statement         | An IR statement is being translated. |
| instruction       | A new (native) instruction is being translated. |
| irsb              | A new basic block is being translated. |
| constraints       | New constraints are being added to the state. |
| exit              | A SimExit is being created from a SimIRSB. |
| symbolic_variable | A new symbolic variable is being created. |
| call              | A call instruction is hit. |
| address_concretization | A symbolic memory access is being resolved. |

These events expose different attributes:

| Event type        | Attribute name     | Attribute availability | Attribute meaning                        |
|-------------------|--------------------|------------------------|------------------------------------------|
| mem_read          | mem_read_address   | BP_BEFORE or BP_AFTER  | The address at which memory is being read. |
| mem_read          | mem_read_length    | BP_BEFORE or BP_AFTER  | The length of the memory read. |
| mem_read          | mem_read_expr      | BP_AFTER               | The expression at that address. |
| mem_write         | mem_write_address  | BP_BEFORE or BP_AFTER  | The address at which memory is being written. |
| mem_write         | mem_write_length   | BP_BEFORE or BP_AFTER  | The length of the memory write. |
| mem_write         | mem_write_expr     | BP_BEFORE or BP_AFTER  | The expression that is being written. |
| reg_read          | reg_read_offset    | BP_BEFORE or BP_AFTER  | The offset of the register being read. |
| reg_read          | reg_read_length    | BP_BEFORE or BP_AFTER  | The length of the register read. |
| reg_read          | reg_read_expr      | BP_AFTER               | The expression in the register. |
| reg_write         | reg_write_offset   | BP_BEFORE or BP_AFTER  | The offset of the register being written. |
| reg_write         | reg_write_length   | BP_BEFORE or BP_AFTER  | The length of the register write. |
| reg_write         | reg_write_expr     | BP_BEFORE or BP_AFTER  | The expression that is being written. |
| tmp_read          | tmp_read_num       | BP_BEFORE or BP_AFTER  | The number of the temp being read. |
| tmp_read          | tmp_read_expr      | BP_AFTER               | The expression of the temp. |
| tmp_write         | tmp_write_num      | BP_BEFORE or BP_AFTER  | The number of the temp written. |
| tmp_write         | tmp_write_expr     | BP_AFTER               | The expression written to the temp. |
| expr              | expr               | BP_AFTER               | The value of the expression. |
| statement         | statement          | BP_BEFORE or BP_AFTER  | The index of the IR statement (in the IR basic block). |
| instruction       | instruction        | BP_BEFORE or BP_AFTER  | The address of the native instruction. |
| irsb              | address            | BP_BEFORE or BP_AFTER  | The address of the basic block. |
| constraints       | added_constrints   | BP_BEFORE or BP_AFTER  | The list of contraint expressions being added. |
| call              | function_name      | BP_BEFORE or BP_AFTER  | The name of the function being called. |
| exit              | exit_target        | BP_BEFORE or BP_AFTER  | The expression representing the target of a SimExit. |
| exit              | exit_guard         | BP_BEFORE or BP_AFTER  | The expression representing the guard of a SimExit. |
| exit              | jumpkind           | BP_BEFORE or BP_AFTER  | The expression representing the kind of SimExit. |
| symbolic_variable | symbolic_name      | BP_BEFORE or BP_AFTER  | The name of the symbolic variable being created. The solver engine might modify this name (by appending a unique ID and length). Check the symbolic_expr for the final symbolic expression. |
| symbolic_variable | symbolic_size      | BP_BEFORE or BP_AFTER  | The size of the symbolic variable being created. |
| symbolic_variable | symbolic_expr      | BP_AFTER               | The expression representing the new symbolic variable. |
| address_concretization | address_concretization_strategy | BP_BEFORE or BP_AFTER | The SimConcretizationStrategy being used to resolve the address. This can be modified by the breakpoint handler to change the strategy that will be applied. If your breakpoint handler sets this to None, this strategy will be skipped. |
| address_concretization | address_concretization_action | BP_BEFORE or BP_AFTER | The SimAction object being used to record the memory action. |
| address_concretization | address_concretization_memory | BP_BEFORE or BP_AFTER | The SimMemory object on which the action was taken. |
| address_concretization | address_concretization_expr | BP_BEFORE or BP_AFTER | The AST representing the memory index being resolved. The breakpoint handler can modify this to affect the address being resolved. |
| address_concretization | address_concretization_add_constraints | BP_BEFORE or BP_AFTER | Whether or not constraints should/will be added for this read. |
| address_concretization | address_concretization_result | BP_AFTER | The list of resolved memory addresses (integers). The breakpoint handler can overwrite these to effect a different resolution result. |

These attributes can be accessed as members of `state.inspect` during the appropriate breakpoint callback to access the appropriate values.
You can even modify these value to modify further uses of the values!

```python
>>> def track_reads(state):
...     print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address
...
>>> s.inspect.b('mem_read', when=simuvex.BP_AFTER, action=track_reads)
```

Additionally, each of these properties can be used as a keyword argument to `inspect.b` to make the breakpoint conditional:

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# This will break before a memory write if 0x1000 is the *only* value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
>>> s.inspect.b('instruction', when=simuvex.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

Cool stuff! In fact, we can even specify a function as a condition:
```python
# this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
# that the basic block starting at 0x8004 was executed sometime in this path's history
>>> def cond(state):
...     return state.any_str(state.regs.rax) == 'AAAA' and 0x8004 in state.inspect.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```

That is some cool stuff!

# Symbolic memory indexing

SimuVEX supports *symbolic memory addressing*, meaning that offsets into memory may be symbolic.
Our implementation of this is inspired by "Mayhem".

This resolution behavior is governed by *concretization strategies*, which are subclasses of `simuvex.concretization_strategies.SimConcretizationStrategy`.
Concretization strategies for reads are set in `state.memory.read_strategies` and for writes in `state.memory.write_strategies`.
These strategies are called, in order, until one of them is able to resolve addresses for the symbolic index.
By setting your own concretization managers (or through the use of SimInspect `address_concretization` breakpoints, described above), you can change the way SimuVEX resolves symbolic addresses.

_TODO: elaborate_

# SimuVEX Options

SimuVEX is extremely customizable through the use of _state options_, a set of constants stored in `state.options`.
These options are documented in the [source code](https://github.com/angr/simuvex/blob/master/simuvex/s_options.py).

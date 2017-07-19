The Simulation Engine
=====================

Most analyses require an understanding of what the code is *doing* (semantic meaning), not just what the code *is* (syntactic meaning).
For this, angr includes a simulation engine.
This engine provides a semantic understanding of what a given piece of code does on a given machine state.

Given a machine state and a code block (usually a VEX IR block), angr provides a resulting machine state (or, in the case of condition jumps, *several* resulting machine states).

# SimEngines

angr uses a series of engines (subclasses of the `SimEngine` class) to emulate the effects that of a given section of code has on an input state.
This mechanism has changed recently, so we have removed much related documentation pending a rewrite.
This information is not critical to the use of angr, since it is abstracted away by `Path` and `PathGroup`, but it provides useful insight into angr's functionality.

TODO: much things

## SimSuccessors

`SimEngine.process` takes an input state and engine-specific arguments (such as a block of VEX IR for `SimEngineVEX`) and returns a SimSuccessors object that contains the successor states, with modifications applied.
Since angr supports symbolic execution, there can be *multiple* output successor states for a single input state.
The successor states are stored in individual lists.
They are:


| Attribute | Guard Condition | Instruction Pointer | Description |
|-----------|-----------------|---------------------|-------------|
| `successors` | True (can be symbolic, but constrained to True) | Can be symbolic (but 256 solutions or less; see `unconstrained_successors`). | A normal, satisfiable successor state to the state processed by the engine. The instruction pointer of this state may be symbolic (i.e., a computed jump based on user input), so the state might actually represent *several* potential continuations of execution going forward. |
| `unsat_successors` | False (can be symbolic, but constrained to False). | Can be symbolic. | Unsatisfiable successors. These are successors whose guard conditions can only be false (i.e., jumps that cannot be taken, or the default branch of jumps that *must* be taken). |
| `flat_successors` | True (can be symbolic, but constrained to True). | Concrete value. | As noted above, states in the `successors` list can have symbolic instruction pointers. This is rather confusing, as elsewhere in the code (i.e., in `SimEngineVEX.process`, when it's time to step that state forward), we make assumptions that a single program state only represents the execution of a single spot in the code. To alleviate this, when we encounter states in `successors` with symbolic instruction pointers, we compute all possible concrete solutions (up to an arbitrary threshold of 256) for them, and make a copy of the state for each such solution. We call this process "flattening". These `flat_successors` are states, each of which has a different, concrete instruction pointer. For example, if the instruction pointer of a state in `successors` was `X+5`, where `X` had constraints of `X > 0x800000` and `X < 0x800010`, we would flatten it into 16 different `flat_successors` states, one with an instruction pointer of `0x800006`, one with `0x800007`, and so on until `0x800015`. |
| `unconstrained_successors` | True (can be symbolic, but constrained to True). | Symbolic (with more than 256 solutions). | During the flattening procedure described above, if it turns out that there are more than 256 possible solutions for the instruction pointer, we assume that the instruction pointer has been overwritten with unconstrained data (i.e., a stack overflow with user data). *This assumption is not sound in general*. Such states are placed in `unconstrained_successors` and not in `successors`. |
| `all_successors` | Anything | Can be symbolic. | This is `successors + unsat_successors + unconstrained_successors`. |

# SimProcedures

SimProcedures are *symbolic function summaries*: angr handles functions imported into the binary by executing a SimProcedure that symbolically implements the given library function, if one exists. SimProcedures are a generic enough interface to do more than this, though - they can be used to run Python code to mutate a state at any point in execution.

SimProcedures are injected into angr's execution pipeline through an interface called *hooking*. The full interface is described [here](toplevel.md#hooking), but the most important part is the `Project.hook(address, procedure)` method. After running this, whenever execution in this project reaches `address`, instead of running the binary code at that address, we run the SimProcedure specified by the `procedure` argument.

`Project.hook` can also take a plain python function as an argument, instead of a SimProcedure class. That function will be automatically wrapped by a SimProcedure and executed (with the current SimState) as its argument.
Of course, you can write your own SimProcedures to simplify execution and allow it to scale to larger programs.
Check out the [the library of already-written ones](https://github.com/angr/angr/tree/master/angr/procedures) or the [howto](simprocedures.md).

# Breakpoints

Like any decent execution engine, angr supports breakpoints. This is pretty cool! A point is set as follows:

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')

# get our state
>>> s = b.factory.entry_state()

# add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
>>> s.inspect.b('mem_write')

# on the other hand, we can have a breakpoint trigger right *after* a memory write happens. 
# we can also have a callback function run instead of opening ipdb.
>>> def debug_func(state):
...     print "State %s is about to do a memory write!"

>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

# or, you can have it drop you in an embedded IPython!
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action='IPython')
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
| exit              | A successor is being generated from execution. |
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
| constraints       | added_constraints   | BP_BEFORE or BP_AFTER  | The list of constraint expressions being added. |
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
>>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)
```

Additionally, each of these properties can be used as a keyword argument to `inspect.b` to make the breakpoint conditional:

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# This will break before a memory write if 0x1000 is the *only* value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
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

angr supports *symbolic memory addressing*, meaning that offsets into memory may be symbolic.
Our implementation of this is inspired by "Mayhem".
Specifically, this means that angr concretizes symbolic addresses when they are used as the target of a write.
This causes some surprises, as users tend to expect symbolic writes to be treated purely symbolically, or "as symbolically" as we treat symbolic reads, but that is not the default behavior.
However, like most things in angr, this is configurable.

The address resolution behavior is governed by *concretization strategies*, which are subclasses of `angr.concretization_strategies.SimConcretizationStrategy`.
Concretization strategies for reads are set in `state.memory.read_strategies` and for writes in `state.memory.write_strategies`.
These strategies are called, in order, until one of them is able to resolve addresses for the symbolic index.
By setting your own concretization strategies (or through the use of SimInspect `address_concretization` breakpoints, described above), you can change the way angr resolves symbolic addresses.

For example, angr's default concretization strategies for writes are:

1. A conditional concretization strategy that allows symbolic writes (with a maximum range of 128 possible solutions) for any indices that are annotated with `angr.plugins.symbolic_memory.MultiwriteAnnotation`.
2. A concretization strategy that simply selects the maximum possible solution of the symbolic index.

To enable symbolic writes for all indices, you can either add the `SYMBOLIC_WRITE_ADDRESSES` state option at state creation time or manually insert a `angr.concretization_strategies.SimConcretizationStrategyRange` object into `state.memory.write_strategies`.
The strategy object takes a single argument, which is the maximum range of possible solutions that it allows before giving up and moving on to the next (presumably non-symbolic) strategy.

# Simulation Options

angr's simulation engine is extremely customizable through the use of _state options_, a set of constants stored in `state.options`.
These options are documented in the [source code](https://github.com/angr/angr/blob/master/angr/s_options.py).

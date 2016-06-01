# CFGAccurate

Here we describe angr’s CFGAccurate analysis in details, as well as some important concepts like context sensitivity and Function Manager of angr.

## General ideas

A basic analysis that one might carry out on a binary is a Control Flow Graph.
A CFG is a graph with (conceptually) basic blocks as nodes and jumps/calls/rets/etc as edges.

In angr, there are two types of CFG that can be generated: a fast CFG (CFGFast) and an accurate CFG (CFGAccurate).
As their names suggested, generating a fast CFG is usually much faster than generating the accurate one.
In general, CFGFast is what you need.
This page discusses CFGAccurate.

An accurate CFG can be constructed by doing:

```python
>>> import angr
# load your project
>>> b = angr.Project('/bin/true', load_options={'auto_load_libs': False})

# generate an accurate CFG
>>> cfg = b.analyses.CFGAccurate(keep_state=True)
```

Of course, there are several options for customized CFGs.

| Option | Description |
|--------|-------------|
| context_sensitivity_level | This sets the context sensitivity level of the analysis. See the context sensitivity level section below for more information. This is 1 by default. |
| starts | A list of addresses, to use as entry points into the analysis. |
| avoid_runs | A list of addresses to ignore in the analysis. |
| call_depth | Limit the depth of the analysis to some number calls. This is useful for checking which functions a specific function can directly jump to (by setting `call_depth` to 1).
| initial_state | An initial state can be provided to the CFG, which it will use throughout its analysis. |
| keep_state | To save memory, the state at each basic block is discarded by default. If `keep_state` is True, the state is saved in the CFGNode. |
| enable_symbolic_back_traversal | Whether to enable an intensive technique for resolving indirect jumps |
| enable_advanced_backward_slicing | Whether to enable another intensive technique for resolving direct jumps |
| more! | Examine the docstring on b.analyses.CFGAccurate for more up-to-date options |

## Context Sensitivity Level

angr constructs a CFG by executing every basic block and seeing where it goes.
This introduces some challenges: a basic block can act differently in different *contexts*.
For example, if a block ends in a function return, the target of that return will be different, depending on different callers of the function containing that basic block.

The context sensitivity level is, conceptually, the number of such callers to keep on the callstack.
To explain this concept, let's look at the following code:

```c
void error(char *error)
{
	puts(error);
}

void alpha()
{
	puts("alpha");
	error("alpha!");
}

void beta()
{
	puts("beta");
	error("beta!");
}

void main()
{
	alpha();
	beta();
}
```

The above sample has four call chains: `main>alpha>puts`, `main>alpha>error>puts` and `main>beta>puts`, and `main>beta>error>puts`.
While, in this case, angr can probably execute both call chains, this becomes unfeasible for larger binaries.
Thus, angr executes the blocks with states limited by the context sensitivity level.
That is, each function is re-analyzed for each unique context that it is called in.

For example, the `puts()` function above will be analyzed with the following contexts, given different context sensitivity levels:

| Level | Meaning | Contexts |
|-------|---------|----------|
| 0 | Callee-only | `puts` |
| 1 | One caller, plus callee | `alpha>puts` `beta>puts` `error>puts` |
| 2 | Two callers, plus callee | `alpha>error>puts` `main>alpha>puts` `beta>error>puts` `main>beta>puts` |
| 3 | Three callers, plus callee | `main>alpha>error>puts` `main>alpha>puts` `main>beta>error>puts` `main>beta>puts` |

The upside of increasing the context sensitivity level is that more information can be gleamed from the CFG.
For example, with context sensitivity of 1, the CFG will show that, when called from `alpha`, `puts` returns to `alpha`, when called from `error`, `puts` returns to `error`, and so forth.
With context sensitivity of 0, the CFG simply shows that `puts` returns to `alpha`, `beta`, and `error`.
This, specifically, is the context sensitivity level used in IDA.
The downside of increasing the context sensitivity level is that it exponentially increases the analysis time.

## Using the CFG

The CFG, at its core, is a [NetworkX](https://networkx.github.io/) di-graph.
This means that all of the normal NetworkX APIs are available:

```python
>>> print "This is the graph:", cfg.graph
>>> print "It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges()))
```

The nodes of the CFG graph are instances of class `CFGNode`.
Due to context sensitivity, a given basic block can have multiple nodes in the graph (for multiple contexts).

```python
# this grabs *any* node at a given location:
>>> entry_node = cfg.get_any_node(b.entry)

# on the other hand, this grabs all of the nodes
>>> print "There were %d contexts for the entry block" % len(cfg.get_all_nodes(b.entry))

# if keep_state was given as True, we can also retrieve the actual SimIRSBs
>>> print "A single SimIRSB at the entry point:", cfg.get_any_irsb(b.entry)
>>> print "All SimIRSBs at the entry point:", cfg.get_all_irsbs(b.entry)

# we can also look up predecessors and successors
>>> print "Predecessors of the entry point:", entry_node.predecessors
>>> print "Successors of the entry point:", entry_node.successors
>>> print "Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ]
```

### Viewing the CFG

Control-flow graph rendering is a hard problem.
angr does not provide any built-in mechanism for rendering the output of a CFG analysis, and attempting to use a traditional graph rendering library, like matplotlib, will result in an unusable image.

One solution for viewing angr CFGs is found in [axt's angr-utils repository](https://github.com/axt/angr-utils).

## Shared Libraries

The CFG analysis does not distinguish between code from different binary objects.
This means that by default, it will try to analyze control flow through loaded shared libraries.
This is almost never intended behavior, since this will extend the analysis time to several days, probably.
To load a binary without shared libraries, add the following keyword argument to the `Project` constructor:
`load_options={'auto_load_libs': False}`

## Function Manager

The CFG result produces an object called the *Function Manager*, accessible through `cfg.kb.functions`.
The most common use case for this object is to access it like a dictionnary. It maps addresses to `Function` objects, which can tell you properties about a function.

```python
>>> entry_func = cfg.kb.functions[b.entry]
```

Functions have several important properties!
- `entry_func.block_addrs` is a set of addresses at which basic blocks belonging to the function begin.
- `entry_func.blocks` is the set of basic blocks belonging to the function, that you can explore and disassemble using capstone.
- `entry_func.string_references()` returns a list of all the constant strings that were referred to at any point in the function.
  They are formatted as `(addr, string)` tuples, where addr is the address in the binary's data section the string lives, and string is a python string that contains the value of the string.
- `entry_func.returning` is a boolean value signifying whether or not the function can return.
  `False` indicates that all paths do not return.
- `entry_func.callable` is an angr Callable object referring to this function.
  You can call it like a python function with python arguments and get back an actual result (may be symbolic) as if you ran the function with those arguments!
- `entry_func.transition_graph` is a NetworkX DiGraph describing control flow within the function itself. It resembles the control-flow graphs IDA displays on a per-function level.
- `entry_func.name` is the name of the function.
- `entry_func.has_unresolved_calls` and `entry.has_unresolved_jumps` have to do with detecting imprecision within the CFG.
  Sometimes, the analysis cannot detect what the possible target of an indirect call or jump could be.
  If this occurs within a function, that function will have the appropriate `has_unresolved_*` value set to `True`.
- `entry_func.get_call_sites()` returns a list of all the addresses of basic blocks which end in calls out to other functions.
- `entry_func.get_call_target(callsite_addr)` will, given `callsite_addr` from the list of call site addresses, return where that callsite will call out to.
- `entry_func.get_call_return(callsite_addr)` will, given `callsite_addr` from the list of call site addresses, return where that callsite should return to.

and many more !


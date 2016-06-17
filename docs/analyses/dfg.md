# DFG

A Data Flow Graph represents data dependencies between instructions. In angr, it represents data dependencies on VEX IR.

A vertex in the graph represents either a statement or an expression. An edge between two vertices represents the
data dependency: the value produced (or constant) from one vertex is needed as an input by another vertex.

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware', load_options={'auto_load_libs': False})
>>> d = b.analyses.DFG()
```

The following options are also available:

| Option  | Description |
|---------|-------------|
| cfg     | If you already have a CFG available you can provide it instead of rebuilding it. |
| annocfg | An annotated CFG that can be built from an BackwardSlice to construct only the DFGs from the basic block that are present in the backward slice. |

Each basic block, or node, in the CFG, which is not a SimProcedure, has its DFG built available in the dict `d.dfgs`
where the key is the address of the basic block.

Every DFG constructed is a is a [NetworkX](https://networkx.github.io/) di-graph.
This means that all of the normal NetworkX APIs are available, for example you can print all the input edges of a node
in a DFG:

```python
>>> bbl_addr, dfg = d.dfgs.popitem()
>>> print(bbl_addr)
>>> print(dfg.in_edges())
```

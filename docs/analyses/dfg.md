# DFG

数据流图表示指令之间的数据依赖。
在 angr 中，数据流图代表了 VEX IR 之间的数据依赖

图中的顶点代表一个语句或一个表达式，两个顶点之间的边代表数据依赖：从一个顶点产生的值需要做另一个顶点的输入

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware', load_options={'auto_load_libs': False})
>>> d = b.analyses.DFG()
```

以下选项也可以使用：

| 选项  | 描述 |
|---------|-------------|
| cfg     | 如果你已经有可用的 CFG，可以直接使用而非重建 |
| annocfg | 由 BackwardSlice 构建的带注释的 CFG，只由在后向切片中出现的基本块构建的 DFG |

CFG 中的每个基本块或节点（非 SimProcedure）在字典 `d.dfgs` 中都有 DFG，键为基本块的地址

每个 DFG 都是由 [NetworkX](https://networkx.github.io/) 构建的图。
这意味着所有基本的 NetworkX API 都是可用的。例如，可以打印 DFG 节点的所有输入边：

```python
>>> bbl_addr, dfg = d.dfgs.popitem()
>>> print(bbl_addr)
>>> print(dfg.in_edges())
```

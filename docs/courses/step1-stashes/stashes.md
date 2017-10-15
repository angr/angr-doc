# angr courses - step 1 - stashes

The binary and source code for this course can be found [here](./).

##### 背景： Stashes
路径组合是 angr 符号执行的接口。顾名思义，路径组合用来组织不同组的二进制文件中的不同路径，被叫做 *stashes*
绝大多数 *stashes* 处在 *active*、*deadended*、*found* 和 *avoid* 状态之间
想了解更多关于路径组合的信息，请看路径组合的 [文档](/docs/pathgroups.md)

```python
>>> import angr

# 装载二进制程序到 project
# 我们不想分析外部库，所以不加载这些外部库，angr 会替换它们
>>> proj = angr.Project("docs/courses/step1-stashes/step1.bin", load_options={'auto_load_libs': False})

# 创建控制流图来找到函数地址
>>> proj.analyses.CFG()
>>> addr_puts = proj.kb.functions.function(name="puts").addr
>>> addr_main = proj.kb.functions.function(name="main").addr
>>> addr_path_explosion = 0x400591

# 创建路径组合
>>> pg = proj.factory.path_group()

# 直到找到 puts 函数否则不停止探索，同时避免路径爆炸
>>> pg.explore(find=addr_puts, avoid=addr_path_explosion)

>>> assert len(pg.active) == 1
>>> assert len(pg.found) == 1
>>> assert len(pg.avoid) == 1

>>> print pg

# 也可以探索剩余活动路径
>>> pg.explore()

>>> assert len(pg.active) == 0
>>> assert len(pg.deadended) == 1

>>> print pg
```
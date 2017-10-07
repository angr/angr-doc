# angr courses - Step 0 - Basic symbolic execution

第一个尝试就是使用符号执行。提醒您，关于富豪执行，您可以在 [文档](/docs/symbolic.md) 中了解更多

The binary and source code for this course can be found [here](./).

```python
>>> import angr

# 装载二进制程序到 angr
>>> project = angr.Project('docs/courses/step0-basic_symbol_execution/step0.bin')

# 将一些关键信息提出来易于阅读
>>> addr_main = 0x4004a6
>>> first_jmp = 0x4004b9
>>> endpoint = 0x4004d6
>>> first_branch_left = 0x4004bb
>>> first_branch_right = 0x4004c2
>>> second_branch_left = 0x4004ca
>>> second_branch_right = 0x4004d1


# 我们创建了一个i额 satate，以便 angr 可以在主函数开始
>>> main_state = project.factory.blank_state(addr=addr_main)
>>> pg = project.factory.path_group(main_state)
>>> assert pg.active[0].addr == addr_main


# 我们的路径组合没有任何操作，所以只有一个活动路径
# 现在我们在主函数，继续往下执行
# pathgroup.step 函数接受不同的参数
# 此时，直到我们遇到第一个比较指令，否则会一直向下执行
>>> pg.step(until=lambda p: p.active[0].addr >= first_jmp)


# 我们现在有两个活动路径了
# 它们分别是比较指令的两个分支，且彼此独立
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 2
>>> assert pg.active[0].addr == first_branch_left
>>> assert pg.active[1].addr == first_branch_right


# 如果我们执行第一条路径，程序会一直执行到结束
# 如果我们执行另一条路径，会遇到另一个比较指令再次分裂路径
>>> pg.step()
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 3
>>> assert pg.active[0].addr == endpoint
>>> assert pg.active[1].addr == second_branch_left
>>> assert pg.active[2].addr == second_branch_right


# 我们现在有三条路径了！
# 第一条路径会一直执行到结束，另一条路径也会执行到结束
>>> pg.step()
>>> print(pg)
>>> for i, p in enumerate(pg.active):
...     print("Active path {0}: {1}".format(i, hex(p.addr)))
>>> assert len(pg.active) == 1
>>> assert len(pg.deadended) == 2
>>> assert pg.active[0].addr == endpoint


# 同样的效果可以通过 pathgroup.explore() 来完成
# explorer 会探索每条路径，直到没有更多的活跃路径为止
>>> pg = project.factory.path_group(main_state)
>>> pg.explore()
>>> assert len(pg.active) == 0
```

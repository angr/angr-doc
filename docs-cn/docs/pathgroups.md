# Simulation Managers

angr 中最重要的控制接口是 SimulationManager，它提供对 state 组中符号执行的控制，应用搜索策略探索程序的状态空间。
本节，你将会学会如何使用它

Simulation managers 可以让你以简单的方式来控制多个 state。
State 被组织为 stash，可以按照使用者的意愿步进、过滤、合并与移动。
例如，使用者可以以不同的速率步进两个不同的 state，然后对这两个 state 进行合并。
大多数操作默认的 stash 是 `active` 的，当一个新的 simulation manager 初始化时 state 放置的位置

### 步进

simulation manager 最基本的功能是通过一个基本块将给定 stash 中的所有 state 向前步进，通过 `.step()` 执行

```python
>>> import angr
>>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simgr(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
>>> simgr.active
[<SimState @ 0x400540>]
```

当然，stash 的真正优势在于当一个 state 遇到一个符号分支条件时，两个后继 state 都出现在 stash 中，允许使用者对齐同步步进。
当你不太在意控制分析，只是想步进 state 直到没有后继 state 可以继续的时候，可以使用 `.run()`

```python
# 步进直到第一个符号分支
>>> while len(simgr.active) == 1:
...    simgr.step()

>>> simgr
<SimulationManager with 2 active>
>>> simgr.active
[<SimState @ 0x400692>, <SimState @ 0x400699>]

# 步进直到没有后继
>>> simgr.run()
>>> simgr
<SimulationManager with 3 deadended>
```
我们现在有三个 `deadended` 的 state！
当一个 state 在执行期间没有产生任何的后继，比如到达了 `exit` 系统调用的位置，它将被从 active 的 stash 中移除并放置在 `deadended` 的 stash 中

### Stash 管理

让我们看看其他的 stash 是如何工作的？

为了在 stash 间移动 state，要使用 `.move()`，它带有三个参数 `from_stash`（可选，默认 active）、`to_stash`、`filter_func`（可选，默认全部移动）。
例如，移动输出中有确定字符串的所有内容：

```python
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: 'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```

我们要通过移动 state 来创建一个名为 authenticated 的新 stash。
所有在这个 stash 中的 state 都有 Welcome，目前而言这是一个很好的指标

每个 stash 只是一个列表，使用者可以索引或迭代列表来访问每个单独的 state。同时，也有一些替代方法来访问 state。
如果在 stash 的名字前面加上了 `one_`，将会得到 stash 中的第一个 state。
如果在 stash 的名字前面加上了 `mp_`，将会得到一个 [mulpyplexed](https://github.com/zardus/mulpyplexer) 版本的 stash 

```python
>>> for s in simgr.deadended + simgr.authenticated:
...     print hex(s.addr)
0x1000030
0x1000078
0x1000078

>>> simgr.one_deadended
<SimState @ 0x1000030>
>>> simgr.mp_authenticated
MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
>>> simgr.mp_authenticated.posix.dumps(0)
MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])
```

当然，`step`、`run` 和其他任何操作路径上单独 stash 的函数都可以带上 `stash` 参数来指定操作的 stash

simulation manager 提供了许多有用的工具来管理 stash。
我们现在不会讲解其余的部分，详情可见 API 文档

## Stash 类型

你可以使用任何你指定的 stash，但是有一些 stash 被用来分类特殊的 state

| Stash | 描述 |
|-------|-------------|
| active     | 这个 stash 包含默认步进的 state，除非指定了替代的 stash |
| deadended     | 当一个 state 因为某种原因无法继续执行，可能是没有更多有效指令、所有后继 state 都不成立或者遇到一个无效的指令指针时，state 就会转移到 deadended 的 stash 中 |
| pruned        | When a state is found to be unsat in the presence of `LAZY_SOLVES`, the state hierarchy is traversed to identify when, in its history, it initially became unsat. All states that are descendants of that point (which will also be unsat, since a state cannot become un-unsat) are pruned and put in this stash. |
| unconstrained | 如果 `save_unconstrained` 选项提供给 SimulationManager 的构造函数，那些被确定为无约束的 state（由用户数据或其他符号数据源控制的指令指针） 就会放在这里 |
| unsat | 如果 `save_unsat` 选项提供给 SimulationManager 的构造函数，那些被确定为不可满足的 state（比如具有互斥的约束，输入必须同时是“AAAA”和“BBBB”）就会放在这里 |

还有另一个不是 stash 的 state 列表：errored。
如果在执行过程中发生错误，state 将会被包装在一个 ErrorRecord 的对象中，其中包含 state 和引发的错误，然后记录被插入 errored 列表中。
可以在造成错误的执行位置开始处使用 `record.state` 得到 state，可以通过 `record.error` 看到引发的错误，并且可以在错误处使用 `record.debug()` 启动一个调试 Shell。
这是一个非常有价值的调试工具！

### 简单探索

符号执行中一个常见的操作就是找到能到达某个确定地址的 state，同时丢弃所有经过另一地址的 state。
Simulation manager 提供了一个简便方法： `.explore()`

当 `explore()` 使用 `find` 参数开始时，执行将会一直运行直到找到与条件相匹配的 state，该条件可以是准备停止位置的指令地址、准备停止位置的指令地址列表或者满足一些条件的函数。
当 active 的 stash 中的任何一个 state 匹配了 find 的条件，就会被移动到 `found` 的 stash 中，并且终止执行。
使用者可以探索已发现的 state，或者选择放弃这个 state 继续探索。
还可以使用与 `find` 相同的格式来指定 `avoid` 条件。
当 state 匹配了 `avoid` 的条件，就会被移动至 `avoided` 的 stash，并保持执行。
最后，`num_find` 参数控制返回之前找到的 state 的数量，默认值为 1.当然，如果在找到指定数量的解决方案之前就耗尽了 active 的 stash 中的所有 state 执行将会终止 

让我们看一个简单 crackme 的[例子](./examples.md#reverseme-modern-binary-exploitation---csci-4968):

首先，我们加载二进制程序
```python
>>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
```

接下来，我们创建一个 SimulationManager
```python
>>> simgr = proj.factory.simgr()
```

现在我们进行符号执行，直到找到符合我们条件的 state
```python
>>> simgr.explore(find=lambda s: "Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
```

现在，我们可以得到 state 中的 flag 了！

```python
>>> s = simgr.found[0]
>>> print s.posix.dumps(1)
Enter password: Congrats!

>>> flag = s.posix.dumps(0)
>>> print(flag)
g00dJ0B!
```

相当简单吧~不是吗？

其他例子可以通过 [examples.md](./examples.md) 查看

## 探索技术

angr 附带了几个小功能，可以自定义 simulation manager 的操作行为，称为_探索技术_。探索技术的原型是深度优先搜索，它将除了一个路径外的所有 active 路径都送入被称为 `deferred` 的 stash 中，每当 `active` 为空时，就会弹出一个 `deferred` 的 state 继续执行下去

要使用探索技术，调用 `simgr.use_technique(tech)`，这是 ExplorationTechnique 子类的一个实例。
angr 内置的探索技术可以在 `angr.exploration_techniques` 中找到

以下是关于内置探索技术的概览

- TODO

你也可以编写属于你自己的探索技术！
这一点我们将在以后介绍

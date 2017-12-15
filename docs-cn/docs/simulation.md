# 仿真与插桩

当你想让 angr 继续向下执行一步时，其实要有几个过程。
angr 使用一系列引擎（`SimEngine` 类的子类）来模拟给定代码段对输入状态的影响。
angr 的执行核心会依次简单尝试所有可用引擎，然后选择使用第一个能处理该步的引擎。以下是默认的引擎列表，依次为：

- 上一步转移到某种不可连续的状态时，失败引擎将会启动
- 上一步结束于系统调用时启动系统调用引擎
- 当前地址被 Hook，启动 Hook 引擎
- 当 `UNICORN` 状态选项启用且 state 中没有符号数据时，unicorn 引擎启动
- VEX 引擎作为最后的保底

## SimSuccessors

依次尝试将参数送给每个引擎的代码是 `project.factory.successors(state, **kwargs)`。
这个函数是 `state.step()` 和 `simulation_manager.step()` 的核心。
它返回一个 SimSuccessors 对象，SimSuccessors 对象的目的是对存储在各种列表属性中的后继状态进行简单的分类，它们是：

| 属性 | Guard 条件 | 指令指针 | 描述 |
|-----------|-----------------|---------------------|-------------|
| `successors` | True (可以是符号，但必须为真) | 可以是符号（但不超过256 个解决方案，详见 `unconstrained_successors`） | 正常、可满足的后继。该 state 的指令指针也许是符号（例如，基于用户输入的计算跳转），所以该 state 代表了一系列潜在的继续执行步 |
| `unsat_successors` | False (可以是符号，但必须为假) | 可以是符号 | 不满足的后继。这些后继的条件只能是 false。（例如：jump 不能执行，或者 jump 的默认分支必须执行） |
| `flat_successors` | True (可以是符号，但必须为真). | 具体值 | 如上所述，`successors` 列表中的 state 可以有符号指令指针。这和代码的其他地方一样（在 `SimEngineVEX.process` 处），是很混乱的。我们假定单个程序状态只代表代码中的单点执行。为了缓解这种情况，我们会为它们计算全部可能的解决方案（达到 256 个任意值），并为每个解决方案创建 state 的副本，我们把这个过程叫做扁平化。这些 `flat_successors` 都是 state，每个 state 都有不同的、具体的指令指针。例如，如果 `successors` 中 state 的指令指针是 `X+5`，其中 `X` 的约束为 `X > 0x800000` 且 `X < 0x800010`。我们会将其变为 16 个不同 `flat_successors` 的 state，指令指针从 `0x800006` 一直到 `0x800015` |
| `unconstrained_successors` | True (可以是符号，但必须为真) | 符号（但不超过 256 个解决方案) | 在上述扁平化的过程中，如果发现指令指针有超过 256 个解决方案，我们假设指令指针已经被无约束数据覆盖（即用户数据堆栈溢出）。一般来说，这个假设并不健全。这些 states 被放置在 `unconstrained_successors` 而不是 `successors` |
| `all_successors` | Anything | 可以是符号 | 这是 `successors + unsat_successors + unconstrained_successors` |

## 断点

TODO: 重写这部分来修正描述

和任何强大的执行引擎一样，angr 也支持断点。摘录一些重点如下：

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

除了内存写入还支持其他功能，以下是列表，可以在每个事件的 BP_BEFORE 或者 BP_AFTER 上中断

| 事件类型        | 事件含义 |
|-------------------|------------------------------------------|
| mem_read          | 读内存 |
| mem_write         | 写内存 |
| reg_read          | 读寄存器 |
| reg_write         | 写寄存器 |
| tmp_read          | 临时读 |
| tmp_write         | 临时写 |
| expr              | 创建表达式（IR 中的算术运算或常数结果） |
| statement         | 翻译 IR 表达式 |
| instruction       | 翻译新（原生）指令 |
| irsb              | 翻译新基本块 |
| constraints       | 为 state 添加新约束 |
| exit              | 执行产生后继 |
| symbolic_variable | 创建新符号变量 |
| call              | 命中 call 指令 |
| address_concretization | 符号内存访问求解 |

这些事件都有不同的属性：

| 事件类型 | 属性名称 | 属性可用性 | 属性含义 |
|-------------------|--------------------|------------------------|------------------------------------------|
| mem_read          | mem_read_address   | BP_BEFORE or BP_AFTER  | 读内存的地址 |
| mem_read          | mem_read_length    | BP_BEFORE or BP_AFTER  | 读内存的长度 |
| mem_read          | mem_read_expr      | BP_AFTER               | 读地址表达式 |
| mem_write         | mem_write_address  | BP_BEFORE or BP_AFTER  | 写内存的地址 |
| mem_write         | mem_write_length   | BP_BEFORE or BP_AFTER  | 写内存的长度 |
| mem_write         | mem_write_expr     | BP_BEFORE or BP_AFTER  | 写地址表达式 |
| reg_read          | reg_read_offset    | BP_BEFORE or BP_AFTER  | 读寄存器偏移 |
| reg_read          | reg_read_length    | BP_BEFORE or BP_AFTER  | 读寄存器长度 |
| reg_read          | reg_read_expr      | BP_AFTER               | 读寄存器表达式 |
| reg_write         | reg_write_offset   | BP_BEFORE or BP_AFTER  | 写寄存器偏移 |
| reg_write         | reg_write_length   | BP_BEFORE or BP_AFTER  | 写寄存器长度 |
| reg_write         | reg_write_expr     | BP_BEFORE or BP_AFTER  | 写寄存器表达式 |
| tmp_read          | tmp_read_num       | BP_BEFORE or BP_AFTER  | 临时读数量 |
| tmp_read          | tmp_read_expr      | BP_AFTER               | 临时读表达式 |
| tmp_write         | tmp_write_num      | BP_BEFORE or BP_AFTER  | 临时写数量 |
| tmp_write         | tmp_write_expr     | BP_AFTER               | 临时写表达式 |
| expr              | expr               | BP_AFTER               | 表达式的值 |
| statement         | statement          | BP_BEFORE or BP_AFTER  | IR 语句的索引（在 IR 基本块中） |
| instruction       | instruction        | BP_BEFORE or BP_AFTER  | 原生指令地址 |
| irsb              | address            | BP_BEFORE or BP_AFTER  | 基本块地址 |
| constraints       | added_constraints   | BP_BEFORE or BP_AFTER  | 添加的约束表达式的列表 |
| call              | function_address      | BP_BEFORE or BP_AFTER  | 被调用的函数名 |
| exit              | exit_target        | BP_BEFORE or BP_AFTER  | 表示 SimExit 目标的表达式 |
| exit              | exit_guard         | BP_BEFORE or BP_AFTER  | 表示 SimExit Guard 的表达式 |
| exit              | jumpkind           | BP_BEFORE or BP_AFTER  | 表示 SimExit 类型的表达式 |
| symbolic_variable | symbolic_name      | BP_BEFORE or BP_AFTER  | 创建的符号变量的名字，约束求解器可能会修改这个名称（通过附加一个唯一的ID和长度）。使用 symbolic_expr 检查符号表达式 |
| symbolic_variable | symbolic_size      | BP_BEFORE or BP_AFTER  | 创建的符号变量的尺寸 |
| symbolic_variable | symbolic_expr      | BP_AFTER               | 新符号变量的表达式 |
| address_concretization | address_concretization_strategy | BP_BEFORE or BP_AFTER | 使用 SimConcretizationStrategy 解析地址，可以通过断点处理程序修改，以改变将要应用的策略。如果你的断点处理程序将其设置为 None，这个策略将会被跳过 |
| address_concretization | address_concretization_action | BP_BEFORE or BP_AFTER | 用于记录内存操作的 SimAction 对象 |
| address_concretization | address_concretization_memory | BP_BEFORE or BP_AFTER | 操作 SimMemory 对象 |
| address_concretization | address_concretization_expr | BP_BEFORE or BP_AFTER | 正在解析的内存索引的 AST，断点处理程序可以修改它以影响正在解析的地址 |
| address_concretization | address_concretization_add_constraints | BP_BEFORE or BP_AFTER | 是否为读取添加约束 |
| address_concretization | address_concretization_result | BP_AFTER | 求解内存地址的列表，断点处理程序可以覆盖这些地址产生不同的求解结果 |

这些属性可以在适当的断点回调期间，用 `state.inspect` 作为成员访问。
甚至可以修改这些值来进一步使用！

```python
>>> def track_reads(state):
...     print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address
...
>>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)
```

此外，每个属性都可以用参数 `inspect.b` 来为断点增加条件：

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# This will break before a memory write if 0x1000 is the *only* value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

非常酷！还可以指定一个函数作为条件：

```python
# this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
# that the basic block starting at 0x8004 was executed sometime in this path's history
>>> def cond(state):
...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```

这些功能都很有用吧！

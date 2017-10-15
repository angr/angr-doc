# 机器 State - 内存、寄存器等

到目前为止，我们只是使用了 angr 的 `SimState` 对象来模拟程序 state 来演示有关 angr 的基本概念。在本节中，您将会了解到一个 state 对象的结构以及如何以各种有用的方式与其进行交互

## Review: 读写内存与寄存器

如果您是从头开始阅读的，您应该已经看到了关于如何访问内存和寄存器的这部分基础知识。
`state.regs` 通过每个寄存器的名字这一属性来提供对寄存器的读写访问，`state.mem` 通过索引访问符号来对内存进行类型化读写访问，这些索引访问符号用来指定要访问的地址与你想要把内存解释为的类型

另外，您现在应该知道如何使用 AST 了，所以您现在应该清楚，任何 bitvector 型的 AST 都可以存储在寄存器或内存中

这有一些关于在 state 中拷贝数据或执行操作的示例：

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# 拷贝 rsp 到 rbp
>>> state.regs.rbp = state.regs.rsp

# 存储 rdx 到内存 0x1000 处
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# rbp 解除引用
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved
```

## 基本执行

在前节，我们为您展示了如何使用 Simulation Manager 来进行一些基本的执行。我们将在下一章详细讲解 Simulation Manager 的全部功能，但此时我们可以用一个更简单的接口 `state.step()` 来解释符号执行是如何工作的。
该方法将执行符号执行的一步并返回一个被调用对象 [`SimSuccessors`](http://angr.io/api-doc/angr.html#module-angr.engines.successors)，与正常的仿真不同，符号执行会产生以多种方式分类的后继 state。现在，我们关心的是这个对象的 `.successors` 属性，其中包含了给定 step 下的全部正常后继 state 列表

为什么是一个列表而不是单独的后继 state ？
angr 符号执行的希望就是将编译进程序的每一条指令都执行，以此来畸变 SimState。当执行到例如 `if (x > 4)` 这样的代码时，如果 x 是符号化的 bitvector 会发生什么？
在 angr 的某处，比较表达式 `x > 4` 会被执行，结果 `<Bool x_32_1 > 4>` 会返回

下一个问题就是：我们要执行 true 分支还是 false 分支？
显然我们都想要执行！
我们会生成两个完全独立的后继 state - 一个模拟进入 true 分支，另一个模拟进入 flase 分支。
在第一个 state，我们添加约束 `x > 4`，在第二个 state，我们添加约束 `!(x > 4)`。
这样，在我们进行约束求解使用这些后继 state 时，*state 对应的条件可以确保得到有效的输入，这些输入可以保证以相同的路径执行到相同的 state*

为了说明这一点，我们以一个 [虚假固件镜像](../examples/fauxware/fauxware) 为例。查看[源码](../examples/fauxware/fauxware.c)可以发现验证机制存在后门。任何用户都可以通过密码 "SOSNEAKY" 来作为管理员通过身份认证。
此外，用户输入的第一次比较发生在后门处，如果我们执行到可以获得超过一个后继 state 时，那么这些 state 中一定有一个 state 包含用户输入中包含后门密码的条件约束

以下这段代码实现了这个功能：

```python
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state()
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699
```

不需要直接看这些 state 的约束，因为我们刚经过的分支是 `strcmp` 的结果。这个函数在模拟符号化的过程中很难处理，结果的约束条件 _非常_ 复杂

我们的程序从标准输入获取数据，默认情况下，它被 angr 视为无限符号数据流。
为了执行约束求解得到输入的可能值，这些输入可以满足这些约束条件，我们需要获得标准输入实际内容的引用。
我们在本节稍后会介绍我们的文件与输入子系统是如何工作的。但现在我们使用 `state.posix.files[0].all_bytes()` 来检索一个代表目前为止从标准输入读取所有内容的 bitvector 

```python
>>> input_data = state1.posix.files[0].all_bytes()

>>> state1.solver.eval(input_data, cast_to=str)
'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

>>> state2.solver.eval(input_data, cast_to=str)
'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'
```

如您所见，为了让 `state1` 路径执行下去，您必须给出后门密码字符串 "SOSNEAKY"。为了让 `state2` 路径执行下去，您必须给出非 "SOSNEAKY" 的字符串。
Z3 将会在符合此约束条件的数十亿个字符串中找到一个返回给您

Fauxware 是 2013 年 angr 第一个符号执行的程序。
我们使用 angr 找到了它的后门，angr 的能力由来已久。
希望您能对于如何使用符号执行在二进制程序中提取有意义的信息有一个清楚的认识！

## State Presets

到目前为止，只要我们使用了 state 就需要创建 `project.factory.entry_state()`。
这只是一系列 *state 构造函数* 中的一个：

- `.blank_state()` 构建一个大部分数据为初始化的空白 state，访问未初始化的数据时，将返回无约束的符号值
- `.entry_state()` 构建一个要从二进制程序入口点开始执行的 state
- `.full_init_state()` 准备通过任意初始化器来构造一个 state，这些初始化器需要在二进制程序的入口点前执行，例如，共享库构造器或预初始化器。完成后会跳进入口点
- `.call_state()` 构建一个从给定函数开始执行的 state

您可以通过这些构造函数的参数来自定义 state：

- 所有构造函数都可以通过引用一个 `addr` 参数来指定开始地址

- 如果程序在需要命令行参数或者环境变量的情况下执行，可以将参数列表作为 `args`、环境变量的列表作为 `env` 传递给 `entry_state` 和 `full_init_state`。
  这些结构中的值可以是字符串或 bitvector，序列化后作为模拟执行环境中的参数和环境变量送入 state。
  默认参数 `args` 是一个空列表，所以如果您正在分析的程序希望至少可以获得 `argv[0]`，那么您应该提供一个！

- 如果您希望 `argc` 作为符号变量，您应该传递一个符号化的 bitvector 作为 `argc` 传给 `entry_state` 和 `full_init_state` 的构造函数。
  需要注意的是，如果您需要这样做，还应该为结果 state 添加一些约束，即 argc 的值不能超过你传入 `args` 参数的数量
  
- 为了使用 call state，您应该调用 `.call_state(addr, arg1, arg2, ...)`，其中 `addr` 是你想要调用的函数的地址，`argN` 是函数的第 N 个参数，可以是整型、字符串、数组或者 bitvector。
  如果您想分配内存并实际为对象传递一个指针过去，您应该将其置于 PointerWrapper 中，例如 `angr.PointerWrapper("point to me!")`。
  该 API 的结果可能有些问题，我们会努力确保其正确
  
- 为指定用于 `call_state` 的函数的调用约定，您可以以参数 `cc` 的形式传递一个 [`SimCC` 实例](http://angr.io/api-doc/angr.html#module-angr.calling_conventions)。
  我们会尝试选择合理的默认值，但对于特殊情况需要您手动来解决！
  
还有几个可以在这些构造函数中使用的参数，本节稍后将会为您介绍！

## 内存低级接口

接口 `state.mem` 便于从内存中加载类型数据，但想要加载与存储指定内存范围的数据就非常麻烦了。
`state.mem` 实际实际上只是正确访问低级内存存储的逻辑，只是一个填充了 bitvector 数据：`state.memory` 的平面地址空间。
您可以使用 `.load(addr, size)` 或 `.store(addr, val)` 作为 `state.memory` 的附属：

```python
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
```

如您所见，数据以大端方式加载与存储，因为 `state.memory` 的主要目的是加载没有附属语义的数据。
但是，如果想要在存储或加载数据上进行 byteswap，您可以传递一个关键参数 `endness` - 如果您指定为小段序，则会发生字节交换 byteswap。
endness 应该是 `archinfo` 包中枚举变量 `Endness` 中的一个，`archinfo` 中为 angr 保存着有关 CPU 架构的声明性数据。
另外，正在分析程序的 endness 可以在 `arch.memory_endness` 中找到，例如 `state.arch.memory_endness`

```python
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67453201>
```

对寄存器访问的低级接口 `state.registers`，但是解释其涉及到 angr 中的 [dive](ir.md)，这个抽象定义用于多架构的无缝协作


## State 选项

某些情况下，对 angr 内部的小调整是可以优化其效果的，有时候是有害的。这些都通过控制 state 选项来进行。

每个 SimState 对象，都有一个选项 `state.options`，
每个选项（只需要一个字符串）控制着 angr 执行引擎的行为。
选项的完整列表以及不同 state 类型下的默认值需要参看 [附录](appendices/options.md)。
您可以通过 `angr.options` 来添加一个单独的选项到 state 中。
单个选项以 CAPITAL_LETTERS 命名，当您想联合使用时也可以使用对象组，叫做 lowercase_letters

当您通过构造函数创建 SimState 时，您可以传送关键参数 `add_options` 和 `remove_options`，这些参数是那些默认值被修改了的初始选项的集合

```python
# Example: enable lazy solves, an option that causes state satisfiability to be checked as infrequently as possible.
# This change to the settings will be propagated to all successor states created from this state after this line.
>>> s.options.add(angr.options.LAZY_SOLVES)

# Create a new state with lazy solves enabled
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})

# Create a new state without simplification options enabled
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)
```

## State 插件

TODO: lord almighty

通用插件： state.history, state.globals, state.posix (ew), state.callstack

## 文件系统

TODO: 描述什么是 SimFile

文件系统有很多选项来控制 state 初始化，包括 `fs`、`concrete_fs` 和 `chroot` 选项

`fs` 选项允许您将文件名的字典传给预配置好的 SimFile 对象。
您可以对文件内容具体设置大小的限制。

设置 `concrete_fs` 选项为 `True`，angr 会 respect 磁盘上的文件。
例如，在仿真时尝试打开文件 'banner.txt'，此时 `concrete_fs` 置为 `False`（默认为 False），将会创建一个带有符号内存的 SimFile 对象，尽管文件存在，仿真仍会继续。
当 `concrete_fs` 置为 `True` 时，如果 'banner.txt' 存在，一个新的 SimFile 对象将会具体地创建，这样可以减少在完全符号化的文件上进行操作而导致的状态爆炸。
此时，若 'banner.txt' 不存在，仿真时的调用 SimFile 对象就不会被创建，并且返回一个错误码。
此外，需要强调地是：尝试打开那些以 '/dev/' 开头的文件，即使 `concrete_fs` 被设置为 `True` 也不会被具体打开

`chroot` 选项，允许您在使用 `concrete_fs` 选项时，指定一个可选的 root 来使用。
如果您正在分析的程序使用绝对路径，是很便利的。
例如，程序正在尝试打开 '/etc/passwd'，可以将当前工作目录设置为 chroot，之后对 '/etc/passwd' 的访问尝试都会被视为 '$CWD/etc/passwd'

```python
>>> files = {'/dev/stdin': angr.storage.file.SimFile("/dev/stdin", "r", size=30)}
>>> s = proj.factory.entry_state(fs=files, concrete_fs=True, chroot="angr-chroot/")
```

这个例子会创建一个 state，该 state 限制从标准输入中最多读取 30 个符号字节，对文件的引用都会在新根目录 `angr-chroot` 内被直接解析

## 复制与合并

state 支持快速拷贝，以便探索不同的可能性：

```python
>>> proj = angr.Project('/bin/true')
>>> s = proj.factory.blank_state()
>>> s1 = s.copy()
>>> s2 = s.copy()

>>> s1.mem[0x1000].uint32_t = 0x41414141
>>> s2.mem[0x1000].uint32_t = 0x42424242
```

States 也可以合并在一起

```python
# merge will return a tuple. the first element is the merged state
# the second element is a symbolic variable describing a state flag
# the third element is a boolean describing whether any merging was done
>>> (s_merged, m, anything_merged) = s1.merge(s2)

# this is now an expression that can resolve to "AAAA" *or* "BBBB"
>>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t
```

TODO: 描述合并的局限性

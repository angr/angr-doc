# 核心概念

在使用 angr 之前，您需要了解一些 angr 的基本概念，以及如果构建一些 angr 的基本对象。
在您装载了二进制程序后，我们将会把那些可以直接展现给你的功能介绍一番！

首先要做的永远都是将一个二进制程序装载进 _project_ 里，我们使用 `/bin/true` 作为示例程序

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
```

project 是 angr 的基石。利用它，你可以对刚装载的可执行程序进行分析和模拟。几乎所有在 angr 中的可操纵的对象都在某种程度上依赖 project

## 基本属性

首先，我们有一些关于 project 的基本属性：CPU 架构、文件名、入口点地址

```python
>>> import monkeyhex # this will format numerical results in hexadecimal
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```

* _arch_ 是一个 `archinfo.Arch` 对象的实例，用于表示被编译程序所面向的任意架构，此时是 little-endian amd64。它包含许多关于程序运行所在 CPU 的信息，详情可以参阅 [这段代码](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py) 来进行细致的了解。通常我们关心的往往是 `arch.bits`， `arch.bytes` \(这是一个在 [main `Arch` class](https://github.com/angr/archinfo/blob/master/archinfo/arch.py) 中 `@property` 的声明\)， `arch.name` 和 `arch.memory_endness`
* _entry_ 是二进制程序的入口点
* _filename_ 是二进制程序的绝对路径文件名

## 装载器

将二进制文件映射到虚拟地址空间表示是相当复杂的！我们开发了一个叫做 CLE 的模块来处理二进制文件的装载。CLE 完成装载后的对象有一个 `.loader` 属性。我们可以在 [文件](./loading.md) 看到其进一步的使用细节，但现在我们只需要知道通过它可以看到 angr 装载的共享库，以及对装载的地址空间进行基本的查询

```python
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # 也许你看到的和示例不相同
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object  # 我们装载了一系列二进制程序到 project 中，这是关键的一个！
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack  # 示例查询：该二进制程序是否拥有可执行栈？
False
>>> proj.loader.main_object.pic  # 示例查询：该二进制程序是否是地址无关的？
True
```

## 工厂

angr 中有许多类，其中大多数类都需要进行实例化。为了避免您需要四处查阅源码，我们提供了 `project.factory`，它提供了一系列您频繁使用的公共对象的构造函数。

本节还将介绍几个基本的 angr 概念，坐稳扶好！

#### 基本块

首先，我们提供 `project.factory.block()` 函数在给定的地址提取代码对应的 [基本块](https://en.wikipedia.org/wiki/Basic_block) 。基本块很重要，因为 - _angr 以基本块为分析代码的基本单位_。执行后你会得到一个 Block 对象，它可以提供关于代码基本块很多有趣的信息：

```python
>>> block = proj.factory.block(proj.entry) # lift a block of code from the program's entry point
<Block for 0x401670, 42 bytes>

>>> block.pp()                      # 优雅地输出反汇编
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions                  # 基本块中有多少指令？
0xb
>>> block.instruction_addrs             # 指令的地址？
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```

此外，您还可以使用 Block 对象来得到基本块的其他表示形式：

```python
>>> block.capstone                       # capstone 反汇编
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB （这是一个 Python 内部地址，不是一个程序地址）
<pyvex.block.IRSB at 0x7706330>
```

#### 状态

这是 angr 另一个重要的概念 - `Project` 对象只表示程序的“初始镜像”。当您使用 angr 装载程序时，其实使用的是一个特定的、表示 _simulated program state_ 的对象 - `SimState`。

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```

SimState 中提供程序需要的内存、寄存器、文件系统数据等任何可以在程序执行中被改变的“实时数据”。稍后会介绍如何深入交互操作，现在我们使用 `state.regs` 和 `state.mem` 来访问寄存器和内存：

```python
>>> state.regs.rip        # 得到当前指令指针
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # interpret the memory at the entry point as a C int
<BV32 0x8949ed31>
```

这些不是 Python 的 ints！这些是 _bitvectors_。Python 中的整数和 CPU 中（e.g. wrapping on overflow）并非具有相同的语义，所以我们使用 bitvectors，您可以视其为一系列比特位表示的整数，用以表示 angr 中的 CPU 信息。请注意，每个 bitvector 都具有 `.length` 属性来描述其比特位的宽度

我们将会了解它们如何协同工作，但现在我们首先了解如何将 Python 中的正如转换成 bitvectors 以及如何转换回来：

```python
>>> bv = state.solver.BVV(0x1234, 32)       # 使用 0x1234 创建一个 32 位宽的 bitvector
<BV32 0x1234>                               # BVV stands for bitvector value
>>> state.solver.eval(bv)                # 转换为 Python 中的 int 型
0x1234
```

您可以将 bitvectors 存回寄存器和内存，或者直接存一个 Python 整型数，它也可以直接转换成合适大小的 bitvector：

```python
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

  起初，因为使用了一些 Python 中的奇技淫巧，`mem` 接口有点混乱。简化版本如下：

* 使用 array\[index\] 表示法来指定一个地址
* 使用 `.<type>` 来指定内存类型的 &lt;类型&gt; \(common values: char, short, int, long, size_t, uint8_t, uint16_t...\)
* 从现在起，你可以：
  * 存储一个数，不论是 bitvector 还是 Python 中的整型数
  * 使用 `.resolved` 来获取一个 bitvector 型的数
  * 使用 `.concrete` 来获取一个 Python 整型的数

更高级的用法将会在后面介绍！

最后，如果想要更多关于寄存器的信息，也许会遇到一个非常奇怪的值：

```python
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>
```

该值仍然是一个 64 位的 bitvector，但它没有包含十六进制数据。相反它有一个名字，这被称为 _符号变量_，它是符号执行的基础。
别急，我们会详细讨论其技术细节的！

#### 模拟管理器

如果 state 让我们可以找到程序在某个时刻的代表，那就必须有方法可以得到 _next_ 下一个时间点的位置。模拟管理器是 angr 中用于执行、模拟的主要接口，无论调用它是为了什么，只要和 state 有联系，就与它有关。作为简要介绍，我们将会展示一下如何 tick 我们之前创建的几个基本块的 state

首先，创建我们要使用的模拟管理器。构造函数可以使用 state 或者一个 state 列表

```python
>>> simgr = proj.factory.simgr(state) # TODO: change name before merge
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```

模拟管理器可以包含多个 _stashes_ 的 state。默认的存储空间， `active` 是用我们传入的 state 进行初始化的。如果觉得还不够，可以进一步查看 `simgr.active[0]` 来得到更进一步的 state 信息！

准备完成，我们准备要执行了！

```python
>>> simgr.step()
```

我们刚刚用符号执行的方法执行了一个基本块！我们可以再次查看 active stash，可以发现它已经改变了，而且**没有**修改我们的原始 state。通过执行将 SimState 对象视为不可变，你可以安全地使用一个单独的 state 作为多轮执行的“基底”

```python
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # new and exciting!
<BV64 0x1020300>
>>> state.regs.rip                           # 仍然相同！
<BV64 0x401670>
```

`/bin/true` 不是用来展示符号执行能力的好例子，所以我们点到为止

## 分析

angr 内置了几个预先打包好的分析工具，您可以使用它从程序中提取有用的信息：

```
>>> proj.analyses.            # Press TAB here in ipython to get an autocomplete-listing of everything:
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
 proj.analyses.CFGAccurate          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
 proj.analyses.CFGFast              proj.analyses.Reassembler
```

这些工具有几个将会在后面提到，但一般来说，如果您要查找如何使用给定的分析工具，您应该查看 [API 文档](http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis)。一个非常简单的例子：如何构建快速控制流图：

```python
# 最初，当我们装载这个二进制程序时，会将所有的依赖项都装载到相同的虚拟地址空间中，在大多数分析场景下这是不可取的
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph is a networkx DiGraph full of CFGNode instances
# 您应该查看 networkx 的 API 来学习如何使用它！
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# 想要得到某一地址的 CFGNode 要使用 cfg.get_any_node
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```

## 然后呢？

看完本页后，您应该了解了 angr 的几个基本概念：基本块，state，bitvectors，模拟管理器与分析工具。尽管如此，此刻您仍不能利用 angr 真正完成一些有趣的事情，请继续阅读！将会解锁更强大的力量...


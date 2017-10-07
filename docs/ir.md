# 中间表示

为了在不同的 CPU 架构上分析和执行机器代码，例如 MIPS、ARM 和 PowerPC 与经典的 x86，angr 对其中大部分的中间表示进行了分析，对每一个 CPU 指令所执行基本操作的结构化描述
通过理解 angr 的 IR - VEX \(我们借鉴了 Valgrind\)，你能够快速地进行静态分析并且可以更好的理解 angr 是如何工作的

在处理不同架构时，VEX IR 会提取不同架构之间的差异，从而可以对这些架构进行单个分析

- **寄存器名** 寄存器的数量和名字在不同的架构中存在差别，但现代 CPU 设计都遵循一个共识：每个 CPU 都包含几个通用寄存器，一个用来保存堆栈指针的寄存器，一系列用来存储条件旗标的寄存器，等等。IR 为不同平台的寄存器提供了一致的抽象接口。具体来说，VEX 将寄存器视为单独的、带有整数偏移的内存空间（例如，AMD64 的 `rax` 会从内存空间的 16 位置开始存储）
- **内存访问** 不同的架构访问内存的方式不同。例如，ARM 可以以小端和大端模式访问内存。IR 会抽象这些差异
- **内存分割** 一些架构，比如 x86 通过特殊的段寄存器来实现内存分段，IR 支持这种内存访问机制
- **指令副产物** 大多数指令都有副产物，例如，ARM 上的 Thumb 模式中的大多数操作都会更新条件旗标、栈操作指令会更新栈指针。在分析中以 *ad hoc* 的方式对副产物进行跟踪是疯狂的，所以 IR 使这些操作的副产物变得更明显

IR 有很多选择，我们选择使用 VEX，因为将二进制代码转换到 VEX 有着相当好的支持。VEX 是架构无关的、side-effects-free 的，许多目标机器语言的中间表示。它将机器代码抽象为易于程序分析的中间表示，其有四个主要的类：

- **表达式** IR 表达式表示计算过的值或不变量，包括内存加载、寄存器读取和算术运算的结果
- **运算** IR 运算描述了 IR 表达式的 *修改*。包括整数运算、浮点运算、位运算等，IR 表达式的 IR 操作会产生 IR 表达式
- **临时变量** VEX 使用临时变量作为内部寄存器：IR 表达式存储在临时变量中。可以用 IR 表达式检索临时变量的内容。临时变量是数字型的，从 `t0` 开始，而且是强类型的（例如，64 位整数、32 位浮点数）
- **语句** IR 语句模型随着目标机的语句改变，例如内存存储与寄存器写入的副产物。IR Statements 使用 IR 表达式可能用到得值。例如内存使用一个 *IR 表达式* 存储 *IR Statement* 要写入的地址，使用另一个 *IR 表达式* 来存储内容
- **块** IR 块是 IR 语句的集合，表示目标架构上的扩展基本块（称为 IR 超级块或 IRSB）一个块可以有多个出口。块中的条件退出用特殊的 *Exit* IR 语句表示。IR 表达式用来表示基本块末尾无条件退出的目标

VEX IR 提供了相当好的文档在 `libvex_ir.h` 中(https://github.com/angr/vex/blob/master/pub/libvex_ir.h)。由于懒惰，我们只为您介绍高频使用的部分。首先，这里有一些 IR 表达式：

| IR Expression | Evaluated Value | VEX Output Example |
| ------------- | --------------- | ------- |
| Constant | 恒定不变的值 | 0x4:I32 |
| Read Temp | 存储在 VEX 临时变量中的值 | RdTmp(t10) |
| Get Register | 存储在寄存器中的值 | GET:I32(16) |
| Load Memory | 存储在内存地址中的值，由另一个 IR 表达式指定地址 | LDle:I32 / LDbe:I64 |
| Operation | 指定 IR 操作的结果，应用于指定的 IR 表达式参数 | Add32 |
| If-Then-Else | 如果给定的 IR 表达式求值为 0，返回一个 IR 表达式，否则返回另一个 | ITE |
| Helper Function | VEX 使用 C 辅助函数来进行某些运算，例如计算某些架构下的条件旗标。这些函数会返回 IR 表达式 | function\_name() |

这些表达式也可以被用在 IR 语句中，这有一些常见的：

| IR Statement | Meaning | VEX Output Example |
| ------------ | ------- | ------------------ |
| Write Temp | 将 VEX 临时变量设置为给定的 IR 表达式的值 | WrTmp(t1) = (IR Expression) |
| Put Register | 使用给定的 IR 表达式更新寄存器 | PUT(16) = (IR Expression) |
| Store Memory | 根据 IR 表达式更新内存，位置与值都通过 IR 表达式给出 | STle(0x1000) = (IR Expression) |
| Exit | 基本块中的条件退出，条件与跳转目标位置都由 IR 表达式指定 | if (condition) goto (Boring) 0x4000A00:I32 |

以下是一个在 ARM 上进行 IR 转换的例子。示例中，减法指令被转换成了一个包含五个 IR 语句的 IR 块，每个语句都包含一个 IR 表达式（虽然实际中 IR 块通常包含超过一个指令）。寄存器也转换成了 *GET* 表达式/*PUT* 语句中的数值型指标。

精明的读者应该已经发现了，实际上减法指令是由块中的前四个 IR 语句构成的，程序计数器递增指向下一条指令（本例中是 `0x59FC8`）是由最后一条语句完成的

ARM 指令如下：

    subs R2, R2, #8
    
转换成 VEX IR：

    t0 = GET:I32(16)
    t1 = 0x8:I32
    t3 = Sub32(t0,t1)
    PUT(16) = t3
    PUT(68) = 0x59FC8:I32

现在，您了解了 VEX，您可以在 angr 里使用 VEX 了，我们使用名为 [PyVEX](https://github.com/angr/pyvex) 的库来将 VEX 在 Python 中可用。另外，PyVEX 已经实现了优雅的输出，可以在 PUT/GET 指令中显示寄存器的名字而非寄存器偏移量

可以通过 `Project.factory.block` 接口访问 PyVEX。您有很多不同的表示方法来访问代码块的语义属性，但它们都具有特定字节序列分析的共同特征。通过 `factory.block` 构造函数，您可以得到一个 `Block` 对象，它可以很容易地转换为多种不同的表示形式。尝试使用 `.vex` 来查看 PyVEX IRSB，或者使用 `.capstone` 得到 Capstone 块

来试试 PyVEX 吧！

```python
>>> import angr

# 装载二进制程序
>>> proj = angr.Project("/bin/true")

# 转换起始基本块
>>> irsb = proj.factory.block(proj.entry).vex
# 将其打印出来
>>> irsb.pp()

# 转换并打印一个地址开始的基本块
>>> irsb = proj.factory.block(0x401340).vex
>>> irsb.pp()

# 基本块结尾的无条件退出的跳转目标的 IR 表达式
>>> print irsb.next

# 无条件退出的类型（例如，调用，返回，系统调用等）
>>> print irsb.jumpkind

# 将其打印出来
>>> irsb.next.pp()

# 遍历所有语句并全部打印出来
>>> for stmt in irsb.statements:
...     stmt.pp()

# pretty-print the IR expression representing the data, and the *type* of that IR expression written by every store statement
>>> import pyvex
>>> for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Store):
...         print "Data:",
...         stmt.data.pp()
...         print ""
...         print "Type:",
...         print stmt.data.result_type
...         print ""

# 打印基本块的每个条件退出的条件和目的地址
>>> for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Exit):
...         print "Condition:",
...         stmt.guard.pp()
...         print ""
...         print "Target:",
...         stmt.dst.pp()
...         print ""

# these are the types of every temp in the IRSB
>>> print irsb.tyenv.types

# here is one way to get the type of temp 0
>>> print irsb.tyenv.types[0]
```

## 条件旗标计算（x86 与 ARM）

x86 和 ARM 的 CPU 上最常见的指令副产物之一就是更新条件旗标，例如零标志位，进位标志位或溢出标志位。
计算机中常常将这些标志位连接起来，存在一个特殊的寄存器中（在 x86 中是 `EFLAGS`/`RFLAGS`，在 ARM 中是 `APSR`/`CPSR`）
该寄存器中存储着有关程序状态的重要信息，对 CPU 仿真的正确性至关重要

VEX 使用四个寄存器作为 "Flag thunk descriptors" 来记录最新的旗标信息。VEX 只在操作触发旗标更新时计算旗标，VEX 存储操作的代码表示到 `cc_op` 伪寄存器，参数存在 `cc_dep1` 和 `cc_dep2` 中。
当 VEX 需要获取实际的旗标值时，可以根据 "Flag thunk descriptors" 来计算出与该旗标相对应的位上是什么。这是旗标计算中的优化，因为 VEX 现在可以直接在 IR 中执行相关操作，不用干扰计算、更新旗标

`cc_op` 存放着不同的操作指令，也存放着对应于 `OP_COPY` 操作的特殊值 0。 
这个操作被假定拷贝 `cc_dep1` 的值到旗标中。这意味着 `cc_dep1` 包含旗标的值。
angr 利用这一点来有效地检索旗标的值：当需要实际旗标的值时，angr 计算其值之后存到 `cc_dep1` 中，并设置 `cc_op = OP_COPY` 来缓存计算结果。
我们也允许用户来对旗标进行写入，设置 `cc_op = OP_COPY` 表明一个新值要被写入旗标了，然后设置 `cc_dep1` 为新值

# FAQ

这是一个常见问题的辑录，对于那些懒得阅读整个文档的人是个福音

如果您遇到了“要修复X该怎么做？”的问题，请参阅[安装说明](../INSTALL.md)的故障排除部分

## 为什么叫 angr？
angr 的分析核心是 VEX IR，出现一些问题的时候，你会非常生气！

## angr 应该怎样拼写使用？
全部小写，即使是在句子的开头。这是一个反专有名词（anti-proper noun）

## 如何得到 angr 运行的诊断信息？
angr 使用标准库中的 `logging` 模块来进行日志记录，每个包与其子模块都会创建一个新的日志（logger）

得到调试输出最简单的方法如下：
```python
import logging
logging.getLogger('angr').setLevel('DEBUG')
```

你也许想要使用 `INFO` 级别或其他日志级别来代替。
默认情况下，angr 的日志等级为 `WARNING`

angr 的每个模块都有自己的日志字符串，通常来说按照层次结构排列下来的 Python 模块，逐渐加上点。例如：`angr.analyses.cfg`。
依据 logging 模块的工作方式，可以通过为父模块设置日志级别来设置模块中所有子模块的日志级别。例如 `logging.getLogger('angr.analyses').setLevel('INFO')` 将会生成 CFG，与其他分析相同，日志会记录在 INFO 级别

## 为什么 angr 这么慢？
这个问题十分复杂，请参阅[速度解释](speed.md)

## 如何使用 angr 来发现 bug？
这又是一个复杂的问题！最简单的方法是定义一个“bug 条件”，例如：指令指针变成一个符号变量。然后启动符号探索，直到发现能匹配条件的 state，angr 会将其 dump 为输入用例文件
但是，往往会很快遇到状态爆炸的问题。
如何解决这个问题就取决于你了。也许是通过添加一个 `avoid` 条件，或者利用 CMU 开发的 Mayhem 作为[探索技术](otiegnqwvk.md)

## 为什么选择 VEX 而不是其他 IR(例如 LLVM、REIL、BAP 等)？
angr 最初的两个设计目标影响了我们的选择：

1. angr 需要能够分析多个体系结构的二进制文件。这就要求我们必须使用支持多架构的 IR
2. 我们想要实现一个二进制分析引擎，而不是一个二进制 lifter。许多项目的启动和结束时都需要执行 lifter，这十分耗时。我们需要使用一个已经存在并且已经支持多种体系结构的解决方案

经过搜索研究，有以下几个主要的选择：

- LLVM 是第一选择，但是想要清晰地提升（lift）二进制代码到 LLVM 是一个痛苦的过程。一共有两种解决方案，一种是通过 QEMU 来提升到 LLVM，而 QEMU 是 hsckish（其唯一实现就是紧密整合进了 S2E 中）的；另一种 mcsema 只支持 x86 结构
- TCG 是 QEMU 的 IR，但是提取它也很困难，它的文档非常粗糙
- REIL 看起来不错，但是没找到标准参考实现来执行来支持我们设计的全部架构。这是一个很好的学术工作，但要使用的话，就不得不实现自己的 lifter，而这这是我们竭力避免的
- BAP 是另一个选择，当我们开始设计 angr 时，BAP 只支持 x86，而 BAP 的最新版本只提供给 BAP 作者的学术合作方。同时它只支持 x86_64、x86 与 ARM
- VEX 是提供开放库并支持多架构的唯一选择。它转为程序分析设计，在 angr 中也是非常易用

虽然 angr 现在使用的是 VEX，但并没有多 IR 不能被使用的根本原因。除了 `angr.engines.vex` 包，angr 有两部分是 VEX 独占的：

- jump 表（例如，`Ijk_Ret` 表示返回、`Ijk_Call` 表示调用等等）使用的是 VEX 的枚举变量
- VEX 将寄存器视作内存空间，angr 也是这么做的。虽然我们提供对 `state.regs.rax` 的访问，但在后端实际做的是 `state.registers.load(8, 8)`，第一个 `8` 是 VEX 定义的 `rax` 寄存器的偏移

为了支持多个 IR，要么抽象这些结构，要么把他们的标签转换成 VEX 的类似体

### 创建项目时，自定义的加载选项会被忽略
CLE 选择是可选参数，请确保使用以下语法调用项目：

```python
b = angr.Project('/bin/true', load_options=load_options)
```

不能是以下这样：
```python
b = angr.Project('/bin/true', load_options)
```

## 为什么 ARM 地址 off-by-one？
为了编码 ARM 代码地址的 THUMB-ness，我们设置最低位为1。
这个惯例是从 LibVEX 沿袭下来的，并不完全是我们自己的选择！
如果看到了一个奇怪的 ARM 地址，就意味着代码处于 `address - 1` 的 THUMB 模式

## 如何序列号 angr 对象？
[Pickle](https://docs.python.org/2/library/pickle.html) 就可以。
但是，Python将会默认使用一个不支持复杂 Python 数据机构的非常古老的 Pickle 协议，所以你必须指定一个[更高的数据流格式](https://docs.python.org/2/library/pickle.html#data-stream-format)。最简单的方法是 `pickle.dumps(obj, -1)`

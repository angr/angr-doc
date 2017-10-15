# angr courses - step 5 - finding correct input, SimState

The binary for this course can be found [here](./).

##### 背景： SimState
angr 的模块 SimuVEX 提供了 SimState 来表示符号执行时的每个 state。
每个 state 包括寄存器和内存的值，求解器和系统的状态，像打开的文件描述符和套接字。
每个 state 也都知道它的下一个 state

本节中，我们利用上节中使用的 [关于 CFG](/docs/courses/step4-control_flow_graphs/cfg.md) 的二进制文件。我们已经通过查看 CFG 了解了程序需要一些输入，并执行一些数学运算，再与硬编码的常量进行检查比对。之后会打印输出一些东西。

我们想找到正确的输入，所以我们首先要找到一种办法来确定输入是否是正确的。要了解二进制程序中可能打印的字符串，需要查看 .rodata 段：
`$ objdump --section .rodata --source step5.bin`

现在我们可以定义函数来测试打印输出的字符串：

```python
>>> def correct(path):
...    return "Congratz" in path.state.posix.dumps(1)

>>> def incorrect(path):
...    return "Nope" in path.state.posix.dumps(1)
```

从程序开始处分析整个二进制程序，包括 b64d 函数，需要的时间太长。我们希望可以从某处开始执行。为此，我们必须为开始执行点创建一个空白的 state。
在 CFG 中可以看到，用户输入存在 r9 寄存器中，因此它必须设置到某个内存区域。angr 中的执行只是模拟的一个值，像 0x42，这不会引起段错误

```python
>>> SOME_MEMORY_ADDR = 0x42

>>> init_state = proj.factory.blank_state(addr=0x400843)
>>> init_state.regs.rcx = 0
>>> init_state.regs.rsi = 0
>>> init_state.regs.rdi = 0
>>> init_state.regs.r10 = 0
>>> init_state.regs.r9 = SOME_MEMORY_ADDR
>>> init_state.regs.r8 = 0
```

现在我们可以基于该 state 来创建路径组合了，日志记录级别设置为 `DEBUG`，这样可以跟踪路径组合的变化。
以前指定的函数可以用来告诉路径组合什么样的路径应该被丢弃

```python
>>> angr.path_group.l.setLevel("DEBUG")
>>> pg = proj.factory.path_group(init_state)
>>> pg.explore(find=correct, avoid=incorrect)
>>> print pg
<PathGroup with 4 avoid, 1 found>
```

一条路径到达了打印成功信息输出的 state 处，我们使用该 state 来得到符号变量代表的用户输入的可能值。通过将变量送给求解器，一个具体值就可以被求解出来。
在我们调用 base64 解码后开始执行，我们发现用户输入必须是 base64 编码过的，所以我们对其进行 base64 编码：

```python
>>> found_state = pg.found[0].state
>>> symbolic_input_string = found_state.memory.load(SOME_MEMORY_ADDR, 16)
>>> concrete_input_string = found_state.se.any_str(symbolic_input_string)

>>> import base64
>>> print base64.b64encode(concrete_input_string)
PFVweE7IBZBJgsulkxZVyw==
```

使用这串字符串输入给真实二进制程序，将会打印成功信息："Congratz, you win!" ！
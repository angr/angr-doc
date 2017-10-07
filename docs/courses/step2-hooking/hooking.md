# angr courses - step 2 - hooking, path explosion

The binary and source code for this course can be found [here](./).

##### 背景：路径爆炸
每个条件跳转都会带来可能路径数量的指数级增长。与符号执行相同，对所有活动路径的跟踪也导致了执行时间的指数级增长

##### 创造路径爆炸
为了模拟路径爆炸，我们使用考拉兹猜想（Collatz conjecture）函数
该循环一直循环下去最后都会返回 1

##### 代码示例： Hooking
如果传递给考拉兹猜想函数的第一个命令行参数是 123456，我们对随后的打印输出的 secret 感兴趣。为了排除它，我们使用 angr 的 *hooking* 功能来简单地将其替换成自定义函数。想了解更多关于 hooking 的信息，请查阅相关 [文档](/docs/toplevel.md#hooking)

```python
>>> import angr

# 装载二进制程序
>>> proj = angr.Project('docs/courses/step2-hooking/step2.bin')

# 一些重要的内存地址信息
>>> addr_collatz_first_instruction = 0x400637
>>> addr_collatz_last_instruction  = 0x40069f
>>> addr_after_print_secret        = 0x40070c

>>> collatz_length = addr_collatz_last_instruction - addr_collatz_first_instruction

# 该函数将用来替换考拉兹猜想函数
# 它接受当前 state 作为参数，并设置寄存器 RAX（the return value）的值为 1
>>> def return1(state):
...    state.regs.rax = 1

# Hook 用上面的函数替换考拉兹猜想函数
# 当执行到考拉兹猜想函数的地址时，Hook 函数将会被执行，二进制程序的 'length' 字节将会被跳过
>>> proj.hook(addr_collatz_first_instruction, return1, length=collatz_length)

# 创建一个新的路径组合来执行符号执行
>>> pg = proj.factory.path_group()

# 启动调试打印，可以看到每一次路径组合的 state
>>> angr.path_group.l.setLevel("DEBUG")

# 探索二进制程序，当 secret 被打印出来才会停止
>>> pg.explore(find=addr_after_print_secret)

# 至少有一个路径发现了目标
>>> assert len(pg.found) > 0

# 发现目标的第一个路径的 state
>>> found_state = pg.found[0].state

# 打印 I/O 中的所有字符串，以找到程序打印出的字符串
>>> for file in found_state.posix.files:
...    print found_state.posix.dumps(file)

The secret is >1234<!
```
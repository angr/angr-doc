# angr courses - step 3 - symbolic command line parameters and constraints on them

The binary and source code for this course can be found [here](./).

##### 本次的二进制文件
这次要分析的二进制文件在执行时需要一个命令行参数，如果参数满足某些要求，则会打印成功的字符串。你可以认为这是一个待破解的登录框

##### 背景：Concept of symbolic values
我们和 angr 都不知道正确的密码是什么，该值是完全符号化的，意味着一开始的时候它没有确定的值
看下面的 C 程序示例
当用 angr 分析相应的二进制文件时，state *a* 第一个参数是完全符号化的
由于 if 语句，活动路径被分为两条：

* 第一条路径（if 条件为 true，对应 state *b*）添加了 argv[1] 等于 test 的约束
* 第二条路径（if 条件为 flase，对应 state *c*）与之相反 argv[1] 不等于 test

```c
int main(int argc, char** argv) {
	// a
	if(strcmp(argv[1], "test") == 0) {
		// b
	} else {
		// c
	}
}
```
了解更多信息参看 [文档](/docs/claripy.md)

##### 背景：angr 中的具体化符号值
我们知道 *b* 处有重要的东西，我们想知道什么参数传递过去才能到 *b*。
在 angr 中，我们可以简单地让约束求解器对当前 state 进行求解，得到满足约束的符号变量的可能值。
在下面的例子中，使用了 32 个符号位组成的 bitvector

```python
>>> some_symbolic_variable = claripy.BVS("some_name", 8 * 4)
>>> print state.se.any_str(some_symbolic_variable)
```

注意，符号变量取决于 state，不同 state 下的程序对符号变量有不同的约束（对比 *a* 与 *b* 两处）

##### 代码示例：查找正确的参数

```python
>>> import angr
>>> import claripy

# 装载二进制程序
>>> proj = angr.Project("docs/courses/step3-command_line_params/step3.bin")

# 查找 puts 地址
# 生成的 CFG 存储在知识库中，被用来查找函数
>>> proj.analyses.CFG()
>>> addr_puts = proj.kb.functions.function(name="puts").addr

# 使用 claripy 创建一个符号化 bitvector
# 因为 char 长 8 bit，我们需要将 char 字符的数量乘以 8
>>> num_input_chars = 50
>>> input_str = claripy.BVS("argv1", 8 * num_input_chars)

# 创建具有手动指定命令行参数的初始状态
>>> init_state = proj.factory.entry_state(args=["docs/courses/step3-command_line_params/step3.bin", input_str])

# 将此参数限制为字母数字的符号 (a-z, A-Z, 0-9)
# 为此，我们必须向符号化的 bitvector 每个比特位都添加约束
# claripy.Or/claripy.And 是逻辑上的或和与
>>> for i in xrange(num_input_chars):
...     current_byte = input_str.get_byte(i)
...     init_state.add_constraints(
...         claripy.Or(
...             claripy.And(current_byte >= 'a', current_byte <= 'z'),
...             claripy.And(current_byte >= 'A', current_byte <= 'Z'),
...             claripy.And(current_byte >= '0', current_byte <= '9')
...         )
...     )

# 创建初始 state 时创建路径组合
>>> pg = proj.factory.path_group(init_state)

# 直到发现输出，否则不停止探索
>>> pg.explore(find=addr_puts)

# 至少一个路径发现了输出
>>> assert len(pg.found) > 0

# 发现目标地址的第一条路劲的 state
>>> found_state = pg.found[0].state

# 评估目标 state 下的符号化输入字符串，找出可能到达目的地址的输入
>>> possible_inputs = found_state.se.any_n_str(input_str, 20)

# 打印出来
>>> for input in possible_inputs:
...     print input
```
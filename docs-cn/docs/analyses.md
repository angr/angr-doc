# 分析

angr 的目标是创建简单易用的二进制程序分析工具。本节将讨论如何运行并创建这些分析工具

## 内建分析工具

angr 带有一些内置分析工具

| Name                                        | Description                                                                                                                               |
| --------                                    | -------------                                                                                                                             |
| CFGFast                                     | 为程序快速构建一个 *控制流图*，`b.analyses.CFG()` 是可用的                  |
| [CFGAccurate](analyses/cfg_accurate.md)     | 为程序构建一个精确的 *控制流图*，`b.analyses.CFGAccurate()` 是可用的         |
| VFG                                         | 对程序中的每个函数执行 VSA，创建一个 *Value Flow Graph* 并检测堆栈变量                |
| DDG                                         | 计算一个数据依赖图（Data Dependency Graph）, 用来确定给定值所依赖的语句               |
| [DFG](analyses/dfg.md)                      | 构建 CFG 中的每个基本块的*数据流图*                          |
| [BackwardSlice](analyses/backward_slice.md) | 计算关于某个确定目标程序的向后切片                                       |
| [Identifier](analyses/identifier.md)        | 识别 CGC 可执行程序的共享库函数 |
| More!                                       | angr 有许多分析工具，其中大部分都可以正常使用，如果您想知道如何使用它，请提交 issue |

### 弹性

分析工具可以写成被写成弹性的，可以捕获、记录任意错误。
这些错误，取决于如何捕捉并记录到 `errors` 或 `named_errors` 分析的属性。
但是，也许希望以“故障快速”模式运行一个分析工具，此时程序将不响应任何错误处理。
为此，参数 `fail_fast=True` 可以将此方式传递给分析器构造函数

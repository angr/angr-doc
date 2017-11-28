# 符号内存寻址

angr 支持*符号内存寻址*，意味着内存中的偏移量也许是符号。
我们受到了 “Mayhem” 的启发。
具体来说，这意味着 angr 在使用它们当作写入目标时具体化了符号地址。
这可能会引起一些争议，有些用户可能倾向于期望符号写入可以纯粹地使用符号进行处理，或者像符号读取那样“符号化”。但这不是默认的方法，与大多数情况相同，这是可配置的

地址解析是由*具体化策略*管理的，这些策略是 `angr.concretization_strategies.SimConcretizationStrategy` 的子类。
读具体化策略在 `state.memory.read_strategies` 中，写具体化策略在 `state.memory.write_strategies` 中。
按顺序调用这些策略，知道其中一个能解析符号索引的地址为止。
通过设置自定义的具体化策略（或通过使用 SimInspect 的断点 `address_concretization`）可以更改 angr 解析符号地址的方式

例如，angr 写的默认具体化策略是：

1. 有条件的具体化策略允许符号写入（最大为128个可能解决方案）任何被 `angr.plugins.symbolic_memory.MultiwriteAnnotation` 注释的索引
2. 简单选择符号索引的最大化可能解决方案的具体化策略

要为所有索引启用符号写入，可以在 state 创建时添加选项 `SYMBOLIC_WRITE_ADDRESSES`，或手动插入对象 `angr.concretization_strategies.SimConcretizationStrategyRange` 到 `state.memory.write_strategies` 中。
策略对象使用单一参数，这个策略是那些放弃并转向下一个（可能是非符号）策略之前所有可能解决方案的最大范围，

## 写具体化策略

TODO
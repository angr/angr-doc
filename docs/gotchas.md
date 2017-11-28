# 使用 angr 时易陷入的困境

这一节包含了一些用户经常遇到的陷阱列表

## SimProcedure 不准确

为了使符号执行更加容易处理，angr 用 Python 编写的摘要来替换常见的库函数。我们把这些摘要称为SimProcedures。
SimProcedures 可以帮助我们削弱路径爆炸，否则将会引入大量的路径爆炸，例如在符号字符串上运行 `strlen`

不幸的是，我们的 SimProcedures 没有那么完善。如果 angr 做了预期之外的事情，可能是由于错误/不完整的 SimProcedure 造成的。有以下几种补救办法：

1. 禁用 SimProcedures（也可以将选项传递给 [angr.Project](http://angr.io/api-doc/angr.html#module-angr.project) 类来排除指定的 SimProcedures）。这可能会导致路径爆炸，除非你可以非常小心地限制输入，路径爆炸可以通过 angr 的其他部分（如 Veritesting）来提供部分缓解的能力
2. 将 SimProcedure 替换为直接写入相关情况的内容。例如，我们 `scanf` 的实现并不完善，但是如果只需要支持一个已知格式的字符串，就可以编写一个 Hook 来完成这个工作
3. 完善 SimProcedure.

## 不支持的系统调用

系统调用也是作为 SimProcedures 实现的。不幸的是，有一些系统调用我们还没有在 angr 中实现。对于不支持的系统调用，有几种解决方法：

1. 执行系统调用 *TODO: document this process*
2. Hook 系统调用（使用 `project.hook`）的调用处，为 state 提供临时的必要修改
3. 使用 `state.posix.queued_syscall_returns` 来维护系统调用返回值的队列。如果返回值在队列中，就不会执行系统调用，直接使用该值。而且，一个函数可以作为“返回值”加入队列中。这会导致该系统调用触发时，该函数被应用到 state 中

## 符号内存模型

angr 默认的内存模型受到 [Mayhem](https://users.ece.cmu.edu/~dbrumley/pdf/Cha%20et%20al._2012_Unleashing%20Mayhem%20on%20Binary%20Code.pdf) 的启发。该内存模型支持有限的符号读与写。如果读的内存索引是符号的，并且该索引可能值的范围太宽，该索引就会被具体化为单值。
如果写的内存索引是符号的，该索引会被具体化为单值。
这些都可以通过改变内存的具体化策略（`state.memory`）来进行配置

## 符号长度

SimProcedures，特别是系统调用，例如 `read()` 和 `write()` 可能都会遇到一个缓冲区长度是符号值的情况。
通常来说，对于这个问题的处理总是不令人满意的。在很多情况下，这个值最终会被完全具体化，或在后面的步骤执行中逐渐具体化。
如果没有具体化，源文件、目标文件看起来可能会有些“奇怪”

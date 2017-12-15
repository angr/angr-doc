# 速度考量

angr 作为一个分析工具或模拟器的速度极大地受到 Python 语言的限制，但仍然有很多优化和调整的方法来让 angr 实现更快的速度

## 通用技巧

- *使用 pypy*.
  [Pypy](http://pypy.org/) 是一个可替代的 Python 解释器，可以优化要执行的 Python 代码。
  在我们的测试中，它能提升十倍以上的速度并且开箱即用
- *除非必要，否则不要加载共享库*
  angr 的默认设置是尽可能的查找已装载的二进制文件兼容的共享库，以及在操作系统库中直接装载。
  这往往很复杂，如果您执行的分析比纯符号执行更抽象，特别是像控制流图的构建，您最好做出一些精度上的牺牲。
  当库调用不存在的函数时，angr 可以做出合理的响应
- *使用 Hooking 和 SimProcedures*
  如果您启用了共享库跟踪，您一定想要一个为可以进入任何复杂库函数而编写的 SimProcedures。
  如果没有对项目的特殊要求，您可以在分析过程中分割单独的问题点，并用 Hook 将其 summarize。
- *使用 SimInspect*
  [SimInspect](simulation.html#breakpoints) 是 angr 中使用频度不高但最强大的功能之一。
  您可以 Hook 并修改 angr 的任何一个行为，包括内存索引解析（这通常是 angr 中最慢的一个部分）
- *写一个 concretization strategy*
  内存索引解析更好的解决方案是 [concretization strategy](https://github.com/angr/angr/tree/master/angr/concretization_strategies)
- *使用替换求解器*.
  您可以改变 `angr.options.REPLACEMENT_SOLVER` 启用它。替换求解器允许您在求解时进行 AST 替换。
  如果您添加的替换使得求解时所有符号数据都被具体数据替换了，那么运行时间将大大降低。
  添加替换的 API 为 `state.se._solver.add_replacement(old, new)`。
  替换比较麻烦，也会有一些难题，但这绝对值得！
  
## 如果进行了很多具体执行或部分具体执行

- *使用 unicorn 引擎*
  如果您安装了 [unicorn](https://github.com/unicorn-engine/unicorn/)，可以让 angr 调用它来进行具体的仿真。
  想要启用这个功能，请添加 `angr.options.unicorn` 到您的 state 中。
  请记住，虽然大多数情况下 `angr.options` 都是单独的选项，但 `angr.options.unicorn` 是一组选项，因此它是一个集合。
  *注意*：现在 unicorn 的官方版本还不能和 angr 进行联动，我们为了能和 angr 进行协同做了很多改动。
  这些改动的 PR 都在等待接受，还需要进行等待。如果您不想等待，可以使用我们 fork 的版本！
- *启用快速内存与快速寄存器*
  想启用需要修改 `angr.options.FAST_MEMORY` 和 `angr.options.FAST_REGISTERS` 两个 state 选项。
  这将把内存/寄存器切换到不精确的内存模型，为了速度牺牲了准确性。
  TODO：这些牺牲对大多数 concrete access though 是安全的
  NOTE：这和 concretization strategies 不兼容
- *Concretize your input ahead of time*
  这是 [driller](https://www.internetsociety.org/sites/default/files/blogs-media/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf) 采取的方法，在开始执行之前，我们使用代表输入样本的符号数据来填充 state.posix.files[0]。然后将符号数据约束到那些我们希望输入样本应该的样子上，之后设置具体文件大小(state.posix.files[0].size = whatever)。
  如果您不需要跟踪来自 stdin 的数据，您可以放弃符号部分，只用具体数据进行填充。
  如果除了标准输入还有其他输入源，以此类推
- *使用 afterburner*.
  当使用 unicorn 时，如果添加了 `UNICORN_THRESHOLD_CONCRETIZATION` 选项，angr 将会接受一个符号值具体的阈值，好让更多的时间花在 Unicorn 上。具体来说，存在以下阈值：
  
  - `state.se.unicorn.concretization_threshold_memory` - 这是存储在内存中的符号变量在被具体化送入 Unicorn 之前被允许在 Unicorn 中执行的次数
  - `state.se.unicorn.concretization_threshold_registers` - 这是存储在寄存器中的符号变量在被具体化送入 Unicorn 之前被允许在 Unicorn 中执行的次数
  - `state.se.unicorn.concretization_threshold_instruction` - 这是任何给定的指令在该指令遇到任何符号数据被具体化以送入 Unicorn 之前送入 Unicorn 的次数（通过进入符号数据）

  您可以通过以下设置进一步控制哪些数据应该被具体化：
  
  - `state.se.unicorn.always_concretize` - 一组始终会被具体化并送入 Unicorn 的变量名（实际上，内存与寄存器阈值最终会导致变量添加到此列表中）
  - `state.se.unicorn.never_concretize` - 一组永远不会被具体化并送入 Unicorn 的变量名
  - `state.se.unicorn.concretize_at` - 一组数据应该被具体化并送入 Unicorn 的指令地址。指令阈值将会导致指令添加到此列表中。

  一旦被 afterburner 具体化，您将会失去对某些变量的跟踪。
  state 仍然还是 state，但是您会丢失某些依赖。因为从 Unicorn 出来的东西是具体的，不会记录其来自于哪个变量。
  不过，在某些情况下，您仍能控制哪些数据要具体化，哪些数据不具体化
  
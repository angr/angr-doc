# 最后的建议

恭喜！
如果你已经阅读完了这本书（编者注：当我们完成了所有 TODO 写作时，才真正适用），我们已经介绍了使用 angr 所必需的二进制分析基本组件

最终，angr 只是一个模拟器。
这是一个高度可操作、独特的模拟器，其中有许多关于环境的考量。
Ultimately, angr is just an emulator.
It is a highly instrumentable and very unique emulator with lots of considerations for environment, true, but at its core, the work you do with angr is about extracting knowledge about how a bunch of bytecode behaves on a CPU.
在设计 angr 时，我们试着提供一组工具以及模拟器顶层的抽象来应对常见的任务，同时没有什么问题是通过 SimState 和 `.step()` 不能解决的

随着对本书的深入阅读，我们将介绍更多技术要点，以及如何针对复杂场景调整 angr。这些知识应该可以告诉你如何使用 angr，这样就可以利用最快的途径解决任何问题，但最终你会使用实践创造来解决遇到的任何问题。
如果你想把一个问题转换成一个已定义好的、可处理的输入和输出的形式，而这些问题涉及分析二进制文件，完全可以利用 angr 来实现。我们做提供的抽象或插桩都不是固定不变的 - 如何在特定任务中使用 angr - angr 的设计使得其可以按照用户期望的方式进行整合或临时使用。
如果发现了解决问题的方法，那就实现它！

当然，要完全熟悉 angr 这样一个巨大的框架是非常困难的。因此，可以依靠社区([angr slack](http://angr.io/invite.html) 通常是最好的选择)和大家一起讨论、解决问题

祝你好运！

详解钩子和SimProcedures
=================================

钩子在 `angr` 中非常强大！你可以使用它们以任何你想要的方式修改程序的行为。然而，你想编写一个特定钩子的方法可能并不明显。这章将会在 `SimProcedures` 编程时给予指导。

## 快速开始

这里有一个示例，它将删除任何程序中的所有 `bug` :

```python
>>> from angr import Project, SimProcedure
>>> project = Project('examples/fauxware/fauxware')

>>> class BugFree(SimProcedure):
...    def run(self, argc, argv):
...        print 'Program running with argc=%s and argv=%s' % (argc, argv)
...        return 0

# this assumes we have symbols for the binary
>>> project.hook(project.kb.labels.lookup('main'), BugFree)

# Run a quick execution!
>>> sm = project.factory.simgr()
>>> sm.run()  # step until no more active paths
Program running with argc=<SAO <BV64 0x0>> and argv=<SAO <BV64 0x7fffffffffeffa0>>
<SimulationManager with 1 deadended>
```

现在，当程序执行到达主函数，而不是执行实际的主函数时，它将执行这个程序!这个程序只是打印出一条消息，然后返回。我们来讨论下函数发生了什么，当进入函数的时候，当进入函数时，函数的参数从哪里来？
您可以定义你自己的 `run()` 函数不管您的函数的参数有多少，`SimProcedure` 运行时都会自动从程序中提取这些参数，
通过[调用约定](structured_data.md#working-with-calling-conventions), 并且调用您的运行函数。类似的，当你从运行函数返回一个值，它被放置到相关状态（也是根据调用约定），并且执行从函数返回的实际控制流动作，根据体系结构可能涉及到链接寄存器或者跳转到堆栈弹出的结果。

应该清楚的是，我们刚才所写的 `SimProcedure` 应该完全替换它所挂钩的函数。
事实上，`SimProcedures` 最初是用来取代库函数。
稍后将进行更详细的讨论。

## 明确的层次结构

我们使用了Hook和SimProcedure这两个词。现在让我们来看下区别
- `SimProcedure` 是一个类，它描述了对一个状态进行的一系列操作。其关键是 `run()` 的方法。
- `Hook`是一个 `angr` 类，它包含了 `SimProcedure` 和关于如何实例化它的信息。

在 `Project` 类中，`project._sim_procedures`是一个从地址到 `Hook` 实例的映射。(这个名字是一个历史产物——`SimProcedure` 是 `angr` 中最古老的类之一，而 `Hook` 则相对较新的。)
当[执行管道](pipeline.md)到达该字典中存在的地址，即被挂钩的地址时，它将执行`procedure = project._sim_procedures[address].instantiate(address, arch)`。
这个调用的结果是一个 `SimProcedure` 实例！
我建议你看看[angr/project.py](https://github.com/angr/angr/blob/master/angr/project.py)底层的Hook类的源代码，以便明白这是如何工作的。

每次运行 `SimProcedure` 时都要生成一个新的 `SimProcedure` 实例，这一点很重要，因为运行 `SimProcedure`的过程必然涉及 `SimProcedure` 实例的变异状态，所以我们需要为每一步分别设置一个，以免我们遇到竞争条件 多线程环境。

### kwargs

这个层次意味着您可能想要在多个钩子中重用单个SimProcedure。如果你想在几个钩子上使用相同的SimProcedure，但每次都稍微调整一下，该怎么办呢? `angr` 支持将你传递给 `Hook()`初始值设定项的任何附加关键字参数都会作为关键字参数传递给你的 `SimProcedure` 的 `run()`方法。

## 数据类型

如果你注意到之前的例子，你注意到当我们将 `run()` 函数的参数打印出来时，它们出现了一个奇怪的 `<SAO <BV64 0xSTUFF>>` 类。这是一个`SimActionObject`。基本上，你不需要担心它太多，它只是一个普通的位向量的包装。它可以跟踪你在 `SimProcedure` 中处理的内容——这有助于静态分析。你也可能注意到我们直接从程序中返回了 `python int 0`。这将自动提升为一个字大小的位向量！您可以返回一个本地数字，一个位图矢量或一个 `SimActionObject`。
当你想编写一个处理浮点数的程序时，你需要手动指定调用约定。这并不难，只需要为 `hook` 提供一个 `cc`:[`cc = project.factory.cc_from_arg_kinds((True, True), ret_fp=True)`](http://angr.io/api-doc/angr.html#angr.factory.AngrObjectFactory.cc_from_arg_kinds) , `project.hook(Hook(ProcedureClass, cc=mycc))`
这种传入调用约定的方法适用于所有的调用约定，所以如果 `angr` 的自动检测方法不正确，那么可以用它解决这个问题。

## 控制流

如何退出 `SimProcedure`？ 我们已经完成了最简单的方法，从 `run()` 返回一个值。这实际上是调用 `self.ret(value)` 的简写。`self.ret` 是知道如何执行从函数返回的特定动作的函数。
SimProcedures可以使用很多像这样的不同的函数！

- `ret(expr)`: 从函数返回
- `jump(addr)`: J跳到指定地址
- `exit(code)`: 终结程序
- `call(addr, args, continue_at)`: 调用一个函数
- `inline_call(procedure, *args)`: 调用另一个 `SimProcedure` 并返回结果

倒数第二个值得一看。

### 条件退出

如果我们想为 `SimProcedure` 添加一个条件分支呢？为了做到这一点，您需要直接使用 `SimSuccessors` 对象来执行当前的执行步骤。
这个接口是[`self.successors.add_successor(state, addr, guard, jumpkind)`](http://angr.io/api-doc/angr.html#angr.engines.successors.SimSuccessors.add_successor).
所有这些参数都应该有一个明显的含义，如果你一直遵循的话。请记住，您传入的 `state` 将不会被复制，所以如果您想再次使用它，请务必复制它!

### SimProcedure Continuation

我们怎样才能调用一个二进制文件中的函数，并在我们的 `SimProcedure` 恢复执行？有一系列的被称作 `SimProcedure Continuation` 的基础设施可以满足你的要求。当你使用 `self.call(addr, args, continue_at)` 时，`addr` 应该是你想要调用的地址， `continue_at` 是 `SimProcedure` 类中另一个方法的名称，您希望在它返回时继续执行它。该方法必须具有与 `run()` 方法相同的签名。此外，您可以将关键字参数 `cc` 作为调用约定，该约定应该用于与 `callee` 通信。
当你这样做的时候，你完成了你现在的步骤，然后在你指定的函数的下一步重新开始执行。当这个函数返回时，它必须返回一些具体的地址！
该地址由 `SimProcedure` 运行时指定。

每个希望使用 `continuation` 子系统的 `SimProcedure` 都被分配一个 `"continuation 地址"`，这个地址被指定为该过程中所有调用的返回地址。当控制流再次到达这个地址时，`SimProcedure` 再次启动，指定的`continue_at`函数被调用，而不是 `run()`，与第一次使用相同的args和kwargs。

为了正确地使用 `continuation` 子系统，您需要将两个元数据附加到 `SimProcedure` 类中:

- 设置类变量 `IS_FUNCTION = True`
- 设置类变量 `local_vars` 为元组字符串, 其中每个字符串都是您 `SimProcedure` 上的实例变量的名称，您希望在返回时保留其值。
   局部变量可以是任何类型，只要你不改变他们的实例。

您可能已经猜到，为了保存所有这些数据，存在某种辅助存储。你是正确的! `state` 插件 `state.procedure_data`  是为了保存所有的数据，以便在运行过程中继续执行。这应该是存储在内存的东西，但数据不能被序列化，内存分配很难。在这种情况下，`state.procedure_data.callstack` 是一个 `"call frames"` 的列表。

每当我们跳到一个 `continuation` 地址并尝试恢复一个 `SimProcedure` 时，我们从这个 `"call stack" `中弹出一帧，并使用它的数据重新初始化我们正在使用的 `SimProcedure` 实例。
例如，让我们看一下 `angr` 在内部使用的 `SimProcedure` 运行所有共享库初始化器，以实现 `"full_init_state"`:

```python
class LinuxLoader(SimProcedure):
    NO_RET = True
    IS_FUNCTION = True

    # pylint: disable=unused-argument,arguments-differ,attribute-defined-outside-init
    local_vars = ('initializers',)
    def run(self, project=None):
        self.initializers = project.loader.get_initializers()
        self.run_initializer(project)

    def run_initializer(self, project=None):
        if len(self.initializers) == 0:
            project._simos.set_entry_register_values(self.state)
            self.jump(project.entry)
        else:
            addr = self.initializers[0]
            self.initializers = self.initializers[1:]
            self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')
```

这是 `SimProcedure continuations` 特别聪明的一个用法。首先，注意当前的项目是作为关键字 `arg` 传入的，所以我们可以访问内部的加载器逻辑。我们从获取初始化程序的列表开始。然后，只要列表不是空的，我们从列表中弹出一个单独的函数指针（注意不要改变列表），然后调用它，再次返回`run_initializer`函数。当初始化器用完时，我们设置入口状态并跳转到程序入口点。

## 全局变量

简而言之，您可以将全局变量存储在`state.procedure_data.global_variables`中。这是一个从 `state` 到后继 `state` 的浅拷贝的字典。
因为它只是一个浅拷贝，它的成员是相同的实例，所以在 `SimProcedure continuations` 中使用本地变量的规则同样适用。您需要注意，不要对用作全局变量的任何项进行突变。

## 帮助静态分析

我们已经研究了类变量 `IS_FUNCTION`，它允许您使用 `SimProcedure continuation`。
您可以设置更多的类变量，尽管这些变量对您没有直接的好处——它们仅仅标记了您的函数的属性，以便静态分析知道它在做什么。

- `NO_RET`: 如果控制流将无法从这个函数返回，请将其设置为true
- `ADDS_EXITS`: 如果你做了任何控制流而不是返回，那么将这个设置为true
- `IS_SYSCALL`: 不需加以说明的

此外，如果设置 `ADDS_EXITS`，您可能还需要定义方法的 `static_exits()`。这个函数接受一个参数，一个 `IRSB` 列表，这个列表在你的函数运行的时候会被执行，并且要求你返回你知道在这种情况下你所知道的所有出口的列表。返回值预期为一个元组的列表 `(address (int), jumpkind (str))`。这是一个快速的，最好的分析，你不应该尝试做任何疯狂的或密集的事情来得到你的答案。

## 使用钩子

编写和使用 `SimProcedure` 的过程会做出很多假设，这些假设都是您想要在整个函数中进行的。你不打算这样做?
有一个接口用于挂钩，一个用户钩子，它可以让你简化代码的挂钩过程。


```python
>>> @project.hook(0x1234, length=5)
... def set_rax(state):
...     state.regs.rax = 1

```

这很简单！这个想法是使用一个单一的函数，而不是整个SimProcedure子类。
没有提取参数，没有复杂的控制流程发生。

控制流由 `"Hook.wrap"` 的长度参数控制。函数完成执行后，下一个步骤将在挂钩地址之后的5个字节开始。如果长度参数被省略或设置为零，那么执行将恢复执行二进制代码，而不需要重新触发钩子。`"Ijk_NoHook"` 的 `"jumpkind"` 允许这种情况发生。如果您想更好地控制来自用户钩子的控制流，你可以返回后继 `state` 列表。每个后继者都应该有 `state.ip`，`state.scratch.guard` 和 `state.scratch.jumpkind` 集合。一般规则是，如果您希望 `SimProcedure` 能够提取函数参数或导致程序返回，请使用 `SimProcedure`。否则，使用用户挂钩。

## 挂钩符号

首先是一些背景。在二进制加载中，有符号的概念 - 地址空间中有一个符号名称的内存范围。
对于动态链接的二进制文件，有一个*导入符号*的概念，这是一个没有地址的符号，只是一个名字。
这些符号用于标记二进制文件和共享对象之间的依赖关系，通常用于函数。在加载过程中，每个导入符号应该由一个不同的二进制*提供*，这个二进制文件的*导出*符号与其同名。
将导入符号与导出符号进行匹配的过程称为* dependency resolution *。将导入符号与导出符号匹配的过程称为 *依赖解析*。当一个符号被解析时，指向提供者符号的指针需要被注入到被提供者的地址空间中。这是一个称为*重定位*的过程。动态链接的二进制文件包含一个*重定位*表，个别指令说明，只要您解析导入符号X，请更新地址Y的代码或数据以引用相应的导出符号。重定位的种类很多，所以这个过程很复杂！
当 `angr` 加载一个程序，它从 `CLE` 获取 `Loader` 对象时，它将做两件事情：确保每个导入的函数都被解析为 `_something_` ，并尽可能地用 `SimProcedures` 替换导入函数。为了做到这一点，CLE导出了一个名为 `"provide_symbol"` 的接口，它允许 `angr` 为自己的导出符号做广告，并使迁移过程指向我们想要的特定符号的位置。

这发生在 `angr` 级别上，使用方法 `"Project.hook_symbol"`。你可以使用这个函数来分配一个新的地址，用你想要的任何东西来挂钩这个地址，并将一个给定名称的任何导入符号重新指向你的钩子!

这意味着您可以用自己的代码替换库函数。
例如，替换 `"rand()"` 函数为带有一个总是返回一致的值序列的函数:

```python
>>> class NotVeryRand(SimProcedure):
...     def run(self, return_values=None):
...         if 'rand_idx' in self.state.procedure_data.global_variables:
...             rand_idx = self.state.procedure_data.global_variables['rand_idx']
...         else:
...             rand_idx = 0
... 
...         out = return_values[rand_idx % len(return_values)]
...         self.state.procedure_data.global_variables['rand_idx'] = rand_idx + 1
...         return out

>>> project.hook_symbol('rand', NotVeryRand(return_values=[413, 612, 1025, 1111]))
```
现在，每当程序试图调用 `rand()`，它将循环从`"return_values"` 数组中返回整数。


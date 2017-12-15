# 写一个 Analyses

可以通过继承类 `angr.Analysis` 来创建一个 analysis。
在本节中，我们将会创建一个模拟 analysis 来展示各种功能。
让我们从简单的开始吧~

```python
>>> import angr

>>> class MockAnalysis(angr.Analysis):
...     def __init__(self, option):
...         self.option = option

>>> angr.register_analysis(MockAnalysis, 'MockAnalysis')
```

这是一个非常简单的 analysis -- 需要一个选项然后把它存储起来。
当然，这没什么用，只是一个简单的示例。

让我们看看如何运行一个新的 analysis

```python
>>> proj = angr.Project("/bin/true")
>>> mock = proj.analyses.MockAnalysis('this is my option')
>>> assert mock.option == 'this is my option'
```

如果在加载了项目后注册了一个新的 analysis，需要使用 `proj.analyses.reload_analyses()` 刷新项目中的注册 analyses 列表

### Working with projects

通过一些 Python 魔法，你的 analysis 将会自动添加到项目中，可以在 `self.project` 属性下运行它。
可以使用它来和项目进行交互并进行分析！

```python
>>> class ProjectSummary(angr.Analysis):
...     def __init__(self):
...         self.result = 'This project is a %s binary with an entry point at %#x.' % (self.project.arch.name, self.project.entry)

>>> angr.register_analysis(ProjectSummary, 'ProjectSummary')
>>> proj = angr.Project("/bin/true")

>>> summary = proj.analyses.ProjectSummary()
>>> print summary.result
This project is a AMD64 binary with an entry point at 0x401410.
```

### Analyses 命名

调用 `register_analysis` 实际上是添加 analysis 到 angr 中。
它的参数是实际 analysis 的类，和 analysis 的名字。
该名字是如何出现在对象 `project.analyses` 下的呢？通常来说，应该使用与 analysis 类同样的名字，但是如果想自定义也是可以的：

```python
>>> class FunctionBlockAverage(angr.Analysis):
...     def __init__(self):
...         self._cfg = self.project.analyses.CFG()
...         self.avg = len(self._cfg.nodes()) / len(self._cfg.function_manager.functions)

>>> angr.register_analysis(FunctionBlockAverage, 'FuncSize')
```

在此之后，就可以使用这个自定义的名字来调用这个 analysis 了，例如：`b.analyses.FuncSize()`

### Analysis 弹性

有时，你的（或者我们的）代码可能会抛出异常。
我们明白，有部分结果总比什么都没有好。
例如，对程序中的所有函数进行 analysis 时，情况就是如此。
即使某些函数失败了，我们仍然想知道成功那部分函数的结果

为了方便，基类 `Analysis` 提供了一个弹性上下文管理器 `self._resilience`。示例如下：

```python
>>> class ComplexFunctionAnalysis(angr.Analysis):
...     def __init__(self):
...         self._cfg = self.project.analyses.CFG()
...         self.results = { }
...         for addr, func in self._cfg.function_manager.functions.iteritems():
...             with self._resilience():
...                 if addr % 2 == 0:
...                     raise ValueError("can't handle functions at even addresses")
...                 else:
...                     self.results[addr] = "GOOD"
```

上下文管理器捕获抛出的任何异常，并将它们（异常类型、异常消息、traceback）记录到 `self.errors` 中。
当 analysis 被保存、加载时，这些数据也将被保存、加载（traceback 因为不可序列化被丢弃）

你可以使用 `self._resilience()` 的两个可选参数来调整弹性的粒度

首先是 `name` 参数，它会影响错误记录的位置。默认情况下，错误被放在 `self.errors`。但如果指定了 `name` 参数，则会被记录到 `self.named_errors`，这是一个映射 `name` 到所有在这个名字下被捕获的错误列表的字典
这可以轻松找到抛出异常的位置，而不无需检查 traceback

第二个参数是 `exception`，指定了应该捕获的异常类型。
默认为 `Exception`，即记录所有类型的错误。
也可以使用元组来传递想捕获的异常类型给该参数，这种情况下，指定类型的异常都会被捕获

使用 `_resilience` 有以下几个优势：

1. 异常会被优雅地记录下来，便于以后访问。这对编写测试用例非常友好
2. 创建自定义的 analysis 时，用户可以设置 `fail_fast=True` 来透明禁用弹性设置，利于手动测试
3. 比随处可见的 `try`/`except` 更漂亮

一旦你掌握了 angr 的全部，就可以利用 angr 来完成任何分析、计算！

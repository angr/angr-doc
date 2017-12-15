# 符号执行 - Surveyors

本质上， `angr` 是一个符号执行引擎。 `angr` 公开了一种标准的方式去编写和执行动态符号执行：`Surveyor` 类。 `Surveyor` 是驱动符号执行的引擎：它跟踪哪些路径是活动的，确定哪些路径可以继续前进，哪些路径舍弃，优化资源分配。

/!\ `Surveyors` 是一个相当笨拙的 `API` ,建议使用 [PathGroups](./pathgroups.md) 。 /!\

`Surveyor` 类并不是直接使用的。相反，它由开发人员细分子类去实现不同功能的分析。也就是说，最常见的符号执行已经在 `Explorer` 类里实现了。

## Explorer

`angr.surveyors.Explorer` 是 `Surveyor` 实现符号执行的一个子类。它可以被告知从哪里开始，到哪里，避免什么及走什么路线。它也试图避免陷入循环。

很难去解释 `Explorer` 是什么，你必须自己去理解：

```python
>>> import angr
>>> proj = angr.Project('examples/fauxware/fauxware')

# By default, a Surveyor starts at the entry point of the program, with
# an exit created by calling `Project.initial_exit` with default arguments.
# This involves creating a default state using `Project.initial_state`.
# A custom SimExit, with a custom state, can be provided via the optional
# "start" parameter, or a list of them via the optional "starts" parameter.
>>> e = proj.surveyors.Explorer()

# Now we can take a few steps! Printing an Explorer will tell you how
# many active paths it currently has.
>>> print e.step()

# You can use `Explorer.run` to step multiple times.
>>> print e.run(10)

# Or even forever. By default, an Explorer will not stop running until
# it runs out of paths (which will likely be never, for most programs),
# so be careful. In this case, we should be ok because the program does
# not loop.
>>> e.run()

# We can see which paths are active (running), and which have deadended
# (i.e., provided no valid exits), and which have errored out. Note that,
# in some instances, a given path could be in multiple lists (i.e., if it
# errored out *and* did not produce any valid exits)
>>> print "%d paths are still running" % len(e.active)
>>> print "%d paths are backgrounded due to lack of resources" % len(e.spilled)
>>> print "%d paths are suspended due to user action" % len(e.suspended)
>>> print "%d paths had errors" % len(e.errored)
>>> print "%d paths deadended" % len(e.deadended)
```

到目前为止，我们所讨论的都适用于 `Surveyors` 。`Explorer` 的另一个好处是可以去搜索和避免某些块。例如，在 `fauxware` 例子中，我们可以去搜寻 ` "authentication success" ` 函数并且避免 `"authentication failed"` 函数。

```python
# This creates an Explorer that tries to find 0x4006ed (successful auth),
# while avoiding 0x4006fd (failed auth) or 0x4006aa (the authentication
# routine). In essense, we are looking for a backdoor.
>>> e = proj.surveyors.Explorer(find=(0x4006ed,), avoid=(0x4006aa,0x4006fd))
>>> e.run()

# Print our found backdoor, and how many paths we avoided!
>>> if len(e.found) > 0:
...     print "Found backdoor path:", e.found[0]

>>> print "Avoided %d paths" % len(e.avoided)
```

提供了一些辅助属性可以更容易的访问 `IPython` :

```python
>>> print "The first found path is", e._f
# Also available are _d (deadended), _spl (spilled), and _e (errored)
```

## Caller

`Caller` 是一个负责处理指定函数的 `surveyor` 以便更容易弄清楚函数做了什么，它可以这样使用：

```python
# load fauxware
>>> proj = angr.Project('examples/fauxware/fauxware')

# get the state ready, and grab our username and password symbolic expressions for later
# checking. Here, we'll cheat a bit since we know that username and password should both
# be 8 chars long
>>> s = proj.factory.entry_state()
>>> username = s.memory.load(0x1000, 9)
>>> password = s.memory.load(0x2000, 9)

# call the authenticate function with *username being 0x1000 and *password being 0x2000
>>>#c = proj.surveyors.Caller(0x400664, (0x1000,0x2000), start=s)

# look at the different paths that can return. This should print 3 paths:
>>>#print tuple(c.iter_returns())

# two of those paths return 1 (authenticated):
>>>#print tuple(c.iter_returns(solution=1))

# now let's see the required username and password to reach that point. `c.map_se`
# calls state.se.eval_upto (or whatever other function is provided) for the provided
# arguments, on each return state. This example runs state.se.eval_upto(credentials, 10)
>>>#credentials = username.concat(password)
>>>#tuple(c.map_se('eval_upto', credentials, 10, solution=1, cast_to=str))

# you can see the secret password "SOSNEAKY" in the first tuple!
```
`Caller` 是一个非常强大的工具。查看函数的注释可以获得更多使用信息。然而有一个更简单的方法去调用其他函数，称为 `callable`。在其他文档有[描述](./structured_data.md#callables)。

## Interrupting Surveyors

`surveyor` 在每一次滴答后会保存它的内部状态。在 `IPython` 中，你可以使用 `Ctrl-C` 去中断一个 `surveyor` ,然后去检查到目前为止的结果，但这是一种很丑陋的方法。有两种正式的方式可以做这件事情：`SIGUSR1` 和 `SIGUSR2`。

如果你给一个运行着 `surveyor` 的 `python` 进程发送 `SIGUSR1` ，将会导致 `Surveyor.run()`的主循环在当前的 `surveyor.step()` 结束时终止。你可以分析结果。为了继续运行 `surveyor` ,你可以调用 `function.angr.surveyor.resume_analyses()` （清除 `"signalled"` 标志） 并且调用 `surveyor` 的 `run` 函数。  因为`SIGUSR1` 导致 `run()` 返回，所以在脚本分析中很少用，因为程序的其他部分将在 `run()` 返回之后继续运行。相反，`SIGUSR1` 是为 `ctrl - c` 提供一个的替代。

在另一方面，如果给 `python` 进程发送 `SIGUSR2`，将会 `run()` 在每一步执行之后调用 `ipdb` 断点。这允许你去调试，继续运行你的程序。在继续运行前请调用 `angr.surveyor.disable_singlestep()` 函数去清除 `"signalled"` 标志。

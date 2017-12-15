理解执行管道
====================================

如果你已经看到了这节，想必你已经了解了，Angr 的核心是一个高度灵活、强大、可操作的模拟器。为了更熟练的使用 angr，就需要了解在使用 `path_group.step()` 时都发生了什么

这是一个更加深入的文档，你需要理解 `PathGroup`、`ExplorationTechnique`、`Path`、`SimState` 和 `SimEngine` 的函数和意图。你也可以打开 angr 的源码跟着我们逐一体会

## Path Groups

当你准备调用下一步时，也就开始了

### `step()`

`PathGroup.step()` 函数有许多可选参数，最重要的有 `stash`、`n`、`until` 和 `step_func`。
`n` is used immediately - the `step()` function loops, calling the `_one_step()` function and passing on all its parameters until either `n` steps have happened or some other termination condition has occurred. If `n` is not provided, it defaults to 1, unless an `until` function is provided, in which case it is 100000 - effectively infinite.

Before any of the termination conditions are checked, however, `step_func` is applied - this function takes the current path group and returns a new path group to replace it.
In writing a step function, it is useful to recall that most common path group functions also return a path group - if the path group is immutable (`immutable=True` in the constructor), it is a new object, but otherwise it is the same object as before.

Now, we check the termination conditions - either the stash we are operating on ("active" by default) has gone empty, or the `until` callback function returns True.
If neither of these conditions are satisfied, we loop back around to call `_one_step()` again.

### `_one_step()`

This is where an `ExplorationTechnique` can start to affect things.
If any active exploration technique has provided a `step` override, this is where it is called.
The cleverness of the techniques is that their effects can combine; how can this happen?
Any given exploration technique that implements `step` is given a path group and is expected to return a new path group, stepped forward by one tick and having the exploration technique's effects applied.
This will inevitably involve the exploration technique calling `step()` on the path group.
What happens then is that the cycle described in this document restarts, except that when the process reaches `_one_step()`, we discover that *the current exploration technique has been popped out of the list of step callbacks*.
Then, if there are any more exploration techniques providing step callbacks, the next one will be called, recursing until we exhaust the list.
Upon returning from the callback, `_one_step` will push the callback back onto the callback stack, and return.

To recap, exploration techniques providing the `step` callback are handled as follows:

- End user calls `step()`
- `step()` calls `_one_step()`
- `_one_step()` pops a single exploration technique from the list of active `step` exploration technique callbacks, and calls it with the path group we are operating on
- This callback calls `step()` on the path group that it gets called with
- This process repeats until there are no more callbacks

Once there are no more `step` callbacks, or if there was never a step callback to begin with, we fall back to the default stepping procedure.
This involves one more parameter that could have been originally passed to `PathGroup.step()` - `selector_func`.
If it is present, then it is used to filter the paths in the working stash that we will actually operate on.
For each of these paths, we call `PathGroup._one_path_step()` on it, again passing along all yet-unused parameters.
`_one_path_step()` will return a tuple of lists categorizing the successors of stepping that path: (normal, unconstrained, unsat, pruned, errored).
The utility function `PathGroup._record_step_results()` will operate on these lists to iteratively construct the new set of stashes that the path group will contain when all this is said and done, and also applies the `filter` callbacks that an exploration technique can provide.

### `_one_path_step()`

We've almost made it out of PathGroup.
First, we need to apply the `step_path` exploration technique hooks.
These hooks do not nest as nicely as the `step` callbacks - only one can be applied, and the rest are used only in case of failure.
If any `step_path` hook succeeds, the results are returned immediately from `_one_path_step()`.
Recall that the requirement for the `filter` callback is to return the same tuple of lists that `_one_path_step()` is supposed to return!
If all of them fail, or there were never any to begin with, we again fall back to the default procedure.

Note: while writing this I've realized that the below procedure is a bit of a mess, so we'll probably refactor it soon.

First, we check if this path is errored.
This is done via the `check_func` parameter to `step()`, which has been passed all the way down into `_one_path_step()`, or if no such function is provided, via the `.errored` attribute the path.
If the path is errored, we abort immediately, putting the path in the `errored` stash.
Then, we tick the path forward.
If a `successor_func` was provided as a parameter to `step()`, it is used - we expect that it will return the list of "normal" successors.
If this parameter was not provided, we call `.step()` on the path, which has the same property of returning the list of normal successors.
Then, we retrieve the list of unconstrained and unsat successors by accessing the `unconstrained_successors` and `unsat_successors` attributes on the path.
All of these are then returned, in the appropriate spots in the huge tuple.

## Paths

Path is a bit of a disaster, and will go away soon.
All you need to know about it for now is that it passes most of the arguments to `Path.step()` onto the successor generation process, and then takes each of the successors and wraps them in a new path.
Somewhere along the way, it performs error-catching, and also keeps an efficient record of some metadata about execution lineage.
The kicker is that `Path`, upon having `step()` called, eventually calls `project.factory.successors(state, **kwargs)`.

If you are using paths directly, without path groups, you may find it useful to know that `Path.step()` caches its arguments, so that if you call `Path.step()` again with the same arguments, you will recieve cached results, otherwise the results will be recalculated.

## Engine Selection

Hopefully, the angr documentation has been organized in a way such that by the time you reach this page, you know that a `SimEngine` is a device that knows how to take a state and produce its successors.
How do we know what engine to use?
Each project has a list of engines in its `factory`, and the default behavior of `project.factory.successors` is to try all of them, in order, and take the results of the first one that works.
There are several ways this behavior can be altered, of course!

- If the parameter `default_engine=True` is passed, the only engine that will be tried is the last-resort default engine, usually `SimEngineVEX`.
- If a list is passed in the parameter `engines`, it will be used instead of the default list of engines

The default list of engines is, by default:

- `SimEngineFailure`
- `SimEngineSyscall`
- `SimEngineHook`
- `SimEngineUnicorn`
- `SimEngineVEX`

Each engine has a `check()` method, which quickly determines whether it is appropriate for usage.
If `check()` passes, `process()` will be used to actually produce the successors.
Even if `check()` passes, `process()` may fail, by returning a `SimSuccessors` object with the `.processed` attribute set to `False`.
Both of these methods are passed as parameters all keyword arguments that haven't yet been filtered out by this preponderance of piled procedures.
Some useful parameters are `addr` and `jumpkind`, which serve as overrides for the respective pieces of information that would usually be extracted for the state.

Finally, once an engine has processed a state, the results are briefly postprocessed in order to fix up the instruction pointer in the case of a syscall.
If the execution ended with a jumpkind matching `Ijk_Sys*`, then a call into `SimOS` is made to retrieve an address for the current syscall, and the instruction pointer of the result state is changed to that address.
The original address is stored in the state register named `ip_at_syscall`.
This is not necessary for pure execution, but in static analysis it is helpful to have syscalls be at separate addresses from normal code.

## Engines

`SimEngineFailure` handles error cases. 
It is only used when the previous jumpkind is one of `Ijk_EmFail`, `Ijk_MapFail`, `Ijk_Sig*`, `Ijk_NoDecode` (but only if the address is not hooked), or `Ijk_Exit`.
In the first four cases, its action is to raise an exception.
In the last case, its action is to simply produce no successors.

`SimEngineSyscall` services syscalls.
It is used when the previous jumpkind is anything of the form `Ijk_Sys*`.
It works by making a call into `SimOS` to retrieve the SimProcedure that should be run to respond to this syscall, and then running it! Pretty simple.

`SimEngineHook` provides the hooking functionality in angr.
It is used when a state is at an address that is hooked, and the previous jumpkind is *not* `Ijk_NoHook`.
It simply looks up the given hook, calls `hook.instantiate()` on it in order to retrieve a `SimProcedure` instance, and then runs that procedure.
This class is a thin subclass of the `SimEngineProcedure` class, specialized for hooking.
It takes the parameter `procedure`, which will cause `check` to always succeed, and this procedure will be used instead of the SimProcedure that would be obtained from a hook.

`SimEngineUnicorn` performs concrete execution with the Unicorn Engine.
It is used when the state option `o.UNICORN` is enabled, and a myriad of other conditions designed for maximum efficiency (described below) are met.

`SimEngineVEX` is the big fellow.
It is used whenever any of the previous can't be used.
It attempts to lift bytes from the current address into an IRSB, and then executes that IRSB symbolically.
There are a huge number of parameters that can control this process, so I will merely link to the [API reference](http://angr.io/api-doc/angr.html#angr.engines.vex.engine.SimEngineVEX.process) describing them.

The exact process by which SimEngineVEX digs into an IRSB and executes it deserves some documentation as well.
At time of writing I'm not sure if this exists anywhere but it really should.

### Engine instances

In addition to parameters to the stepping process, you can also instantiate new versions of these engines!
Look at the API docs to see what options each engine can take.
Once you have a new engine instance, you can either pass it into the step process, or directly put it into the `project.factory.engines` list for automatic use.

# 使用 Unicorn 引擎时

如果添加 `o.UNICORN` 选项，`SimEngineUnicorn` 就会逐步调用，并尝试查看是否允许使用Unicorn来具体执行

也许你真正想要的是将预定义 `o.unicorn`（小写）的选项添加到 state 中

```python
unicorn = { UNICORN, UNICORN_SYM_REGS_SUPPORT, INITIALIZE_ZERO_REGISTERS, UNICORN_HANDLE_TRANSMIT_SYSCALL }
```

这些将会启用一些额外的功能和默认设置，都可以提高 angr 的表现。此外，还有很多选项可以调整 `state.unicorn` 插件

了解 Unicorn 是如何工作的一个好方法是通过检查 Unicorn 的日志输出（`logging.getLogger('angr.engines.unicorn_engine').setLevel('DEBUG'); logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')`）

```
INFO    | 2017-02-25 08:19:48,012 | angr.state_plugins.unicorn | started emulation at 0x4012f9 (1000000 steps)
```

在此处，angr 会转向 unicorn 引擎，从基本块 0x4012f9 开始，最大步数设置为 1000000。如果在 Unicorn 中执行了一百万块，将会自动弹出。这是为了避免遇到无限循环时崩溃，块的数量也可以通过变量 `state.unicorn.max_steps` 来设置

```
INFO    | 2017-02-25 08:19:48,014 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,016 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,019 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
INFO    | 2017-02-25 08:19:48,022 | angr.state_plugins.unicorn | mmap [0x602000, 0x602fff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,023 | angr.state_plugins.unicorn | mmap [0x400000, 0x400fff], 5
INFO    | 2017-02-25 08:19:48,025 | angr.state_plugins.unicorn | mmap [0x7000000, 0x7000fff], 5
```

angr 执行由 unicorn 引擎访问的数据的 lazy 映射。0x401000 是正在执行的指令的页面，0x7fffffffffe0000 是堆栈，依此类推。其中一些页面是符号的，这意味着它们至少会包含一些数据，当访问这些数据时，Unicorn 的执行会终止

```
INFO    | 2017-02-25 08:19:48,037 | angr.state_plugins.unicorn | finished emulation at 0x7000080 after 3 steps: STOP_STOPPOINT
```

在 Unicorn 中执行三个基本块后，执行停留在 Unicorn 中，然后到达simproceduce 的位置并跳出在 angr 中执行 simproc

```
INFO    | 2017-02-25 08:19:48,076 | angr.state_plugins.unicorn | started emulation at 0x40175d (1000000 steps)
INFO    | 2017-02-25 08:19:48,077 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,079 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,081 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
```

simprocedure 后，执行跳回到 Unicorn

```
WARNING | 2017-02-25 08:19:48,082 | angr.state_plugins.unicorn | fetching empty page [0x0, 0xfff]
INFO    | 2017-02-25 08:19:48,103 | angr.state_plugins.unicorn | finished emulation at 0x401777 after 1 steps: STOP_EXECNONE
```

因为二进制文件访问了零页，所以几乎立即就从 Unicorn 中弹出了

```
INFO    | 2017-02-25 08:19:48,120 | angr.engines.unicorn_engine | not enough runs since last unicorn (100)
INFO    | 2017-02-25 08:19:48,125 | angr.engines.unicorn_engine | not enough runs since last unicorn (99)
```

为了避免在 Unicorn 内外出现反复，在 Unicorn 运行时，我们可以设置一些等待条件的冷却时间（作为插件 `state.unicorn` 的属性）。然后跳回 Unicorn 而不是 simprocedure 或系统调用而被中止。在这里，等待的条件是在返回之前执行一百个块

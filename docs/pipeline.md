Understanding the Execution Pipeline
====================================

If you've made it this far you know that at its core, angr is a highly flexible and intensely instrumentable emulator.
In order to get the most mileage out of it, you'll want to know what happens at every step of the way when you say `path_group.step()`.

This is intended to be a more advanced document; you'll need to understand the function and intent of `PathGroup`, `ExplorationTechnique`, `Path`, `SimState`, and `SimEngine` in order to understand what we're talking about at times!
You may want to have the angr source open to follow along with this.

## Path Groups

So you've called for a step to occur. Time to begin our journey.

### `step()`

`PathGroup.step()` function takes many optional parameters.
The most important of these are `stash`, `n`, `until`, and `step_func`.
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

# When using Unicorn Engine

If you add the `o.UNICORN` state option, at every step `SimEngineUnicorn` will be invoked, and try to see if it is allowed to use Unicorn to execute concretely.

What you REALLY want to do is to add the predefined set `o.unicorn` (lowercase) of options to your state:

```python
unicorn = { UNICORN, UNICORN_SYM_REGS_SUPPORT, INITIALIZE_ZERO_REGISTERS, UNICORN_HANDLE_TRANSMIT_SYSCALL }
```

These will enable some additional functionalities and defaults which will greatly enhance your experience.
Additionally, there are a lot of options you can tune on the `state.unicorn` plugin.

A good way to understand how unicorn works is by examining the logging output (`logging.getLogger('angr.engines.unicorn_engine').setLevel('DEBUG'); logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')` from a sample run of unicorn.

```
INFO    | 2017-02-25 08:19:48,012 | angr.state_plugins.unicorn | started emulation at 0x4012f9 (1000000 steps)
```

Here, angr diverts to unicorn engine, beginning with the basic block at 0x4012f9.
The maximum step count is set to 1000000, so if execution stays in Unicorn for 1000000 blocks, it'll automatically pop out.
This is to avoid hanging in an infinite loop.
The block count is configurable via the `state.unicorn.max_steps` variable.

```
INFO    | 2017-02-25 08:19:48,014 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,016 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,019 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
INFO    | 2017-02-25 08:19:48,022 | angr.state_plugins.unicorn | mmap [0x602000, 0x602fff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,023 | angr.state_plugins.unicorn | mmap [0x400000, 0x400fff], 5
INFO    | 2017-02-25 08:19:48,025 | angr.state_plugins.unicorn | mmap [0x7000000, 0x7000fff], 5
```

angr performs lazy mapping of data that is accessed by unicorn engine, as it is accessed. 0x401000 is the page of instructions that it is executing, 0x7fffffffffe0000 is the stack, and so on. Some of these pages are symbolic, meaning that they contain at least some data that, when accessed, will cause execution to abort out of Unicorn.

```
INFO    | 2017-02-25 08:19:48,037 | angr.state_plugins.unicorn | finished emulation at 0x7000080 after 3 steps: STOP_STOPPOINT
```

Execution stays in Unicorn for 3 basic blocks (a computational waste, considering the required setup), after which it reaches a simprocedure location and jumps out to execute the simproc in angr.

```
INFO    | 2017-02-25 08:19:48,076 | angr.state_plugins.unicorn | started emulation at 0x40175d (1000000 steps)
INFO    | 2017-02-25 08:19:48,077 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,079 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,081 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
```

After the simprocedure, execution jumps back into Unicorn.

```
WARNING | 2017-02-25 08:19:48,082 | angr.state_plugins.unicorn | fetching empty page [0x0, 0xfff]
INFO    | 2017-02-25 08:19:48,103 | angr.state_plugins.unicorn | finished emulation at 0x401777 after 1 steps: STOP_EXECNONE
```

Execution bounces out of Unicorn almost right away because the binary accessed the zero-page.

```
INFO    | 2017-02-25 08:19:48,120 | angr.engines.unicorn_engine | not enough runs since last unicorn (100)
INFO    | 2017-02-25 08:19:48,125 | angr.engines.unicorn_engine | not enough runs since last unicorn (99)
```

To avoid thrashing in and out of Unicorn (which is expensive), we have cooldowns (attributes of the `state.unicorn` plugin) that wait for certain conditions to hold (i.e., no symbolic memory accesses for X blocks) before jumping back into unicorn when a unicorn run is aborted due to anything but a simprocedure or syscall.
Here, the condition it's waiting for is for 100 blocks to be executed before jumping back in.

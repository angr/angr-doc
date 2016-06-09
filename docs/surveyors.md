# Symbolic Execution - Surveyors

At heart, angr is a symbolic execution engine.
angr exposes a standard way to write and perform dynamic symbolic execution: the `Surveyor` class.
A `Surveyor` is the *engine* that drives symbolic execution: it tracks what paths are active, identifies which paths to step forward and which paths to prune, and optimizes resource allocation.

/!\ `Surveyors` are an old API that is rather unweildy. It's recommended to use [PathGroups](./pathgroups.md) instead. /!\

The `Surveyor` class is not meant to be used directly.
Rather, it should be subclassed by developers to implement their own analyses.
That being said, the most common symbolic analysis (i.e., "explore from A to B, trying to avoid C") has already been implemented in the `Explorer` class.

## Explorer

`angr.surveyors.Explorer` is a `Surveyor` subclass that implements symbolic exploration.
It can be told where to start, where to go, what to avoid, and what paths to stick to.
It also tries to avoid getting stuck in loops.

In the end, one cannot be told what the `Explorer` is.
You have to see it for yourself:

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')

# By default, a Surveyor starts at the entry point of the program, with
# an exit created by calling `Project.initial_exit` with default arguments.
# This involves creating a default state using `Project.initial_state`.
# A custom SimExit, with a custom state, can be provided via the optional
# "start" parameter, or a list of them via the optional "starts" parameter.
>>> e = b.surveyors.Explorer()

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

So far, everything we have discussed applies to all `Surveyors`.
However, the nice thing about an Explorer is that you can tell it to search for, or avoid certain blocks.
For example, in the `fauxware` sample, we can try to find the "authentication success" function while avoiding the "authentication failed" function.

```python
# This creates an Explorer that tries to find 0x4006ed (successful auth),
# while avoiding 0x4006fd (failed auth) or 0x4006aa (the authentication
# routine). In essense, we are looking for a backdoor.
>>> e = b.surveyors.Explorer(find=(0x4006ed,), avoid=(0x4006aa,0x4006fd))
>>> e.run()

# Print our found backdoor, and how many paths we avoided!
>>> if len(e.found) > 0:
...     print "Found backdoor path:", e.found[0]

>>> print "Avoided %d paths" % len(e.avoided)
```

Some helper properties are provided for easier access to paths from ipython:

```python
>>> print "The first found path is", e._f
# Also available are _d (deadended), _spl (spilled), and _e (errored)
```

## Caller

The `Caller` is a surveyor that handles calling functions to make it easier to figure out what the heck they do.
It can be used as so:

```python
# load fauxware
>>> b = angr.Project('examples/fauxware/fauxware')

# get the state ready, and grab our username and password symbolic expressions for later
# checking. Here, we'll cheat a bit since we know that username and password should both
# be 8 chars long
>>> p = b.factory.path()
>>> username = p.state.memory.load(0x1000, 9)
>>> password = p.state.memory.load(0x2000, 9)

# call the authenticate function with *username being 0x1000 and *password being 0x2000
>>> c = b.surveyors.Caller(0x400664, (0x1000,0x2000), start=p)

# look at the different paths that can return. This should print 3 paths:
>>> print tuple(c.iter_returns())

# two of those paths return 1 (authenticated):
>>> print tuple(c.iter_returns(solution=1))

# now let's see the required username and password to reach that point. `c.map_se`
# calls state.se.any_n_str (or whatever other function is provided) for the provided
# arguments, on each return state. This example runs state.se.any_n_str(credentials, 10)
>>> credentials = username.concat(password)
>>> tuple(c.map_se('any_n_str', credentials, 10, solution=1))

# you can see the secret password "SOSNEAKY" in the first tuple!
```

Caller is a pretty powerful tool. Check out the comments on the various functions for more usage info! HOWEVER, there is a much easier tool you can use to call functions, called `callable`. This is described [elsewhere in the docs](https://github.com/angr/angr-doc/blob/master/toplevel.md).

## Interrupting Surveyors

A surveyor saves its internal state after every tick.
In ipython, you should be able to interrupt a surveyor with `Ctrl-C`, and then check what results it has so far, but that's a pretty ugly way of doing it.
There are two official ways of doing this cleanly: `SIGUSR1` and `SIGUSR2`.

If you send `SIGUSR1` to a python process running a surveyor, it causes the main loop in `Surveyor.run()` to terminate at the end of the current `Surveyor.step()`.
You can then analyze the result.
To continue running the surveyor, call `angr.surveyor.resume_analyses()` (to clear the "signalled" flag) and then call the surveyor's `run()` function.
Since `SIGUSR1` causes `run()` to return, this is rarely useful in a scripted analysis, as the rest of the program will run after `run()` returns.
Instead, `SIGUSR1` is meant to provide a clean alternative to `Ctrl-C`.

Sending SIGUSR2 to the python process, on the other hand, causes `run()` to invoke an `ipdb` breakpoint after every `step()`.
This allows you to debug, then continue your program.
Make sure to run `angr.surveyor.disable_singlestep()` before continuing to clear the "signalled" flag.

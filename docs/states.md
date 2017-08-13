# Machine State - memory, registers, and so on

So far, we've only used angr's simulated program states (`SimState` objects) in the barest possible way in order to demonstrate basic concepts about angr's operation. Here, you'll learn about the structure of a state object and how to interact with it in a variety of useful ways.

## Review: Reading and writing memory and registers

If you've been reading this book in order (and you should be, at least for this first section), you already saw the basics of how to access memory and registers.
`state.regs` provides read and write access to the registers through attributes with the names of each register, and `state.mem` provides typed read and write access to memory with index-access notation to specify the address followed by an attribute access to specify the type you would like to interpret the memory as.

Additionally, you should now know how to work with ASTs, so you can now understand that any bitvector-typed AST can be stored in registers or memory.

Here are some quick examples for copying and performing operations on data from the state:

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# copy rsp to rbp
>>> state.regs.rbp = state.regs.rsp

# store rdx to memory at 0x1000
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# dereference rbp
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved
```

## State Presets

So far, whenever we've been working with a state, we've created it with `project.factory.entry_state()`.
This is just one of several *state constructors* available on the project factory:

- `.blank_state()` constructs a "blank slate" blank state, with most of its data left uninitialized.
  When accessing uninitialized data, an unconstrained symbolic value will be returned.
- `.entry_state()` constructs a state ready to execute at the main binary's entry point.
- `.full_init_state()` constructs a state that is ready to execute through any initializers that need to be run before the main binary's entry point, for example, shared library constructors or preinitializers.
  When it is finished with these it will jump to the entry point.
- `.call_state()` constructs a state ready to execute a given function.

You can customize the state through several arguments to these constructors:

- All of these constructors can take an `addr` argument to specify the exact address to start.

- If you're executing in an environment that can take command line arguments or an environment, you can pass a list of arguments through `args` and a dictionary of environment variables through `env` into `entry_state` and `full_init_state`.
  The values in these structures can be strings or bitvectors, and will be serialized into the state as the arguments and environment to the simulated execution.
  The default `args` is an empty list, so if the program you're analyzing expects to find at least an `argv[0]`, you should always provide that!

- If you'd like to have `argc` be symbolic, you can pass a symbolic bitvector as `argc` to the `entry_state` and `full_init_state` constructors.
  Be careful, though: if you do this, you should also add a constraint to the resulting state that your value for argc cannot be larger than the number of args you passed into `args`.
  
- To use the call state, you should call it with `.call_state(addr, (arg1, arg2, ...))`, where `addr` is the address of the function you want to call and `argN` is the Nth argument to that function, either as a python integer, string, or an AST.
  If you want to have memory allocated and actually pass in a pointer to an object, you should wrap it in a PointerWrapper, i.e. `proj.factory.call_state.PointerWrapper("point to me!")`.
  The results of this API can be a little unpredictable, but we're working on it.
  
- To specify the calling convention used for a function with `call_state`, you can pass a [`SimCC` instance](http://angr.io/api-doc/angr.html#module-angr.calling_conventions) as the `cc` argument.    

There are several more options that can be used in any of these constructors, which we will describe below.

## Basic Execution

TODO: state.step()

## Low level interface for memory and registers

TODO: state.memory, state.registers

## Copying and Merging

A state supports very fast copies, so that you can explore different possibilities:

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
>>> s = proj.factory.blank_state()
>>> s1 = s.copy()
>>> s2 = s.copy()

>>> s1.mem[0x1000].uint32_t = 0x41414141
>>> s2.mem[0x1000].uint32_t = 0x42424242
```

States can also be merged together.

```python
# merge will return a tuple. the first element is the merged state
# the second element is a symbolic variable describing a state flag
# the third element is a boolean describing whether any merging was done
>>> (s_merged, m, anything_merged) = s1.merge(s2)

# this is now an expression that can resolve to "AAAA" *or* "BBBB"
>>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t
```

TODO: describe limitations of merging

## State Options

There are a lot of little tweaks that can be made to the internals of angr that will optimize behavior in some situations and be a detriment in others.
These tweaks are controlled through state options.

On each SimState object, there is a set (`state.options`) of all its enabled options.
The full domain of options, along with the defaults for different state types, can be found in [sim_options.py](https://github.com/angr/angr/blob/master/angr/sim_options.py), available as `angr.options`.

When creating a SimState through any method, you may pass the keyword arguments `add_options` and `remove_options`, which should be sets of options that modify the initial options set from the default.

```python
# Example: enable lazy solves, a behavior that causes state satisfiability to be checked as infrequently as possible.
# This change to the settings will be propogated to all successor states created from this state after this line.
>>> s.options.add(angr.options.LAZY_SOLVES)

# Create a new state with lazy solves enabled
>>> s9 = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
```

## State Plugins

TODO: lord almighty

Common plugins: state.history, state.globals, state.posix (ew), state.callstack

## Working with the Filesystem

TODO: Describe what a SimFile is

There are a number of options which can be passed to the state initialization routines which affect filesystem usage.
These include the `fs`, `concrete_fs`, and `chroot` options.

The `fs` option allows you to pass in a dictionary of file names to preconfigured SimFile objects.
This allows you to do things like set a concrete size limit on a file's content.

Setting the `concrete_fs` option to `True` will cause angr to respect the files on disk.
For example, if during simulation a program attempts to open 'banner.txt' when `concrete_fs` is set to `False` \(the default\), a SimFile with a symbolic memory backing will be created and simulation will continue as though the file exists.
When `concrete_fs` mode is set to `True`, if 'banner.txt' exists a new SimFile object will be created with a concrete backing, reducing the resulting state explosion which would be caused by operating on a completely symbolic file.
Additionally in `concrete_fs` mode if 'banner.txt' mode does not exist, a SimFile object will not be created upon calls to open during simulation and an error code will be returned.
Additionally, it's important to note that attempts to open files whose path begins with '/dev/' will never be opened concretely even with `concrete_fs` set to `True`.

The `chroot` option allows you to specify an optional root to use while using the `concrete_fs` option.
This can be convenient if the program you're analyzing references files using an absolute path.
For example, if the program you are analyzing attempts to open '/etc/passwd', you can set the chroot to your current working directory so that attempts to access '/etc/passwd' will read from '$CWD/etc/passwd'.

```python
>>> files = {'/dev/stdin': angr.storage.file.SimFile("/dev/stdin", "r", size=30)}
>>> s = proj.factory.entry_state(fs=files, concrete_fs=True, chroot="angr-chroot/")
```

This example will create a state which constricts at most 30 symbolic bytes from being read from stdin and will cause references to files to be resolved concretely within the new root directory `angr-chroot`.

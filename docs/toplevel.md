Top-level interfaces
====================

So you've loaded a project. Now what?

This document explains all the attributes that are available directly from instances of `angr.Project`.

## Basic properties
```python
>>> import angr, monkeyhex, claripy
>>> b = angr.Project('/bin/true')

>>> b.arch
<Arch AMD64 (LE)>
>>> b.entry
0x401410
>>> b.filename
'/bin/true'
>>> b.loader
<Loaded true, maps [0x400000:0x4004000]>
```
- *arch* is an instance of an `archinfo.Arch` object for whichever architecture the program is compiled.
  There's [lots of fun information](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py) on there!
  The common ones you care about are `arch.bits`, `arch.bytes` (that one is a `@property` declaration on the [main `Arch` class](https://github.com/angr/archinfo/blob/master/archinfo/arch.py)), `arch.name`, and `arch.memory_endness`.
- *entry* is the entry point of the binary!
- *filename* is the absolute filename of the binary. Riveting stuff!
- *loader* is the [cle.Loader](https://github.com/angr/cle/blob/master/cle/loader.py) instance for this project. Details on how to use it are found [here](./loading.md).

## Analyses and Surveyors
```python
>>> b.analyses
<angr.analysis.Analyses object at 0x7f5220d6a890>
>>> b.surveyors
<angr.surveyor.Surveyors object at 0x7f52191b9dd0>

>>> filter(lambda x: '_' not in x, dir(b.analyses))
['BackwardSlice',
 'BinDiff',
 'BoyScout',
 'BufferOverflowDetection',
 'CDG',
 'CFG',
 'DDG',
 'GirlScout',
 'SleakMeta',
 'Sleakslice',
 'VFG',
 'Veritesting',
 'XSleak']
>>> filter(lambda x: '_' not in x, dir(b.surveyors))
['Caller', 'Escaper', 'Executor', 'Explorer', 'Slicecutor', 'started']
```

`analyses` and `surveyors` are both just container objects for all the Analyses and Surveyors, respectively.

Analyses are customizable analysis routines that can extract some sort of information from the program.
The most common two are `CFG`, which constructs a control-flow graph, and `VFG`, which performs value-set analysis.
Their use, as well as how to write your own analyses, is documented [here](./analyses.md).

Surveyors are basic tools for performing symbolic execution with common goals.
The most common one is `Explorer`, which searches for a target address while avoiding some others.
Read about using surveyors [here](./surveyors.md).
Note that while surveyors are cool, an alternative to them is Path Groups (below), which are the future.

## The factory

`b.factory`, like `b.analyses` and `b.surveyors`, is a container object that has a lot of cool stuff in it.
It is not a factory in the java sense, it is merely a home for all the functions that produce new instances of important angr classes and should be sitting on Project.

```python
>>> import claripy # used later

>>> block = b.factory.block(addr=b.entry)
>>> block = b.factory.block(addr=b.entry, insn_bytes='\xc3')
>>> block = b.factory.block(addr=b.entry, num_inst=1)

>>> state = b.factory.blank_state(addr=b.entry)
>>> state = b.factory.entry_state(args=['./program', claripy.BVS('arg1', 20*8)])
>>> state = b.factory.call_state(0x1000, "hello", "world")
>>> state = b.factory.full_init_state(args=['./program', claripy.BVS('arg1', 20*8)])

>>> path = b.factory.path()
>>> path = b.factory.path(state)

>>> group = b.factory.path_group()
>>> group = b.factory.path_group(path)
>>> group = b.factory.path_group([path, state])

>>> strlen_addr = b.loader.main_bin.plt['strlen']
>>> strlen = b.factory.callable(strlen_addr)
>>> assert claripy.is_true(strlen("hello") == 5)

>>> cc = b.factory.cc()
```

- *factory.block* is the angr's lifter. passing it an address will lift a basic block of code from the binary at that address, and return an angr Block object that can be used to retrieve multiple representations of that block. More below.
- *factory.blank_state* returns a SimState object with little initialization besides the parameters passed to it. States as a whole are discussed in depth [here](states.md).
- *factory.entry_state* returns a SimState initialized to the program state at the binary's entry point.
- *factory.call_state* returns a SimState initialized as if you'd just called the function at the given address, with the given args.
- *factory.full_init_state* returns a SimState that initialized similarly to `entry_state`, but instead of at the entry point, the program counter points to a SimProcedure that serves the purpose of the dynamic loader and will call the initializers of each shared library before jumping to the entry point.
- *factory.path* returns a Path object. Since Paths are at their start just light wrappers around SimStates, you can call `path` with a state as an argument and get a path wrapped around that state.
  Alternately, for simple cases, any keyword arguments you pass `path` will be passed on to `entry_state` to create a state to wrap. It is discussed in depth [here](paths.md).
- *factory.path_group* creates a path group! Path groups are the future. They're basically very smart lists of paths, so you can pass it a path, a state (which will be wrapped into a path), or a list of paths and states. They are discussed in depth [here](pathgroups.md).
- *factory.callable* is _very_ cool. Callables are a FFI (foreign functions interface) into arbitrary binary code. They are discussed in depth [here](structured_data.md).
- *factory.cc* intiializes a calling convention object. This can be initialized with different args or even a function prototype, and then passed to factory.callable or factory.call_state to customize how arguments and return values and return addresses are laid out into memory. It is discussed in depth [here](structured_data.md).

### Lifter

Access the lifter through *factory.block*.
This method has a number of optional parameters, which you can read about [here](http://angr.io/api-doc/angr.html#module-angr.lifter)!
The bottom line, though, is that `block()` gives you back a generic interface to a basic block of code.
You can get properties like `.size` (in bytes) from the block, but if you want to do interesting things with it, you need a more specific representation.
Access `.vex` to get a [PyVEX IRSB](http://angr.io/api-doc/pyvex.html#pyvex.block.IRSB), or `.capstone` to get a [Capstone block](http://www.capstone-engine.org/lang_python.html).

### Filesystem Options

There are a number of options which can be passed to the state initialization routines which affect filesystem usage. These include the `fs`, `concrete_fs`, and `chroot` options.

The `fs` option allows you to pass in a dictionary of file names to preconfigured SimFile objects. This allows you to do things like set a concrete size limit on a file's content.

Setting the `concrete_fs` option to `True` will cause angr to respect the files on disk. For example, if during simulation a program attempts to open 'banner.txt' when `concrete_fs` is set to `False` (the default), a SimFile with a symbolic memory backing will be created and simulation will continue as though the file exists. When `concrete_fs` mode is set to `True`, if 'banner.txt' exists a new SimFile object will be created with a concrete backing, reducing the resulting state explosion which would be caused by operating on a completely symbolic file. Additionally in `concrete_fs` mode if 'banner.txt' mode does not exist, a SimFile object will not be created upon calls to open during simulation and an error code will be returned. Additionally, it's important to note that attempts to open files whose path begins with '/dev/' will never be opened concretely even with `concrete_fs` set to `True`.

The `chroot` option allows you to specify an optional root to use while using the `concrete_fs` option. This can be convenient if the program you're analyzing references files using an absolute path. For example, if the program you are analyzing attempts to open '/etc/passwd', you can set the chroot to your current working directory so that attempts to access '/etc/passwd' will read from '$CWD/etc/passwd'.

```python
>>> import simuvex
>>> files = {'/dev/stdin': simuvex.storage.file.SimFile("/dev/stdin", "r", size=30)}
>>> s = b.factory.entry_state(fs=files, concrete_fs=True, chroot="angr-chroot/")
```

This example will create a state which constricts at most 30 symbolic bytes from being read from stdin and will cause references to files to be resolved concretely within the new root directory `angr-chroot`.

Important note that needs to go in this initial version before I write the rest of the stuff:
the `args` and `env` keyword args work on `entry_state` and `full_init_state`, and are a list and a dict, respectively, of strings or [claripy](./claripy.md) BV objects, which can represent a variety of concrete and symbolic strings. Read the source if you wanna know more about these!

## Hooking

```python
>>> def set_rax(state):
...    state.regs.rax = 10

>>> b.hook(0x10000, set_rax, length=5)
>>> b.is_hooked(0x10000)
True
>>> b.unhook(0x10000)
>>> b.hook_symbol('strlen', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
```

A hook is a modification of how program execution should work.
When you hook a program at a certain address, whenever the program's execution reaches that point, it will run the python code you supplied in the hook.
Execution will then skip `length` bytes ahead of the hooked address and resume.
You can omit the `length` argument for execution to skip zero bytes and resume at the address you hooked.

In addition to a basic function, you can hook an address with a `SimProcedure`, which is a more complex system for having fine-grained control over program execution.
To do this, use the exact same `hook` function, but supply a class (not an instance!) that subclasses `simuvex.SimProcedure`.

The `is_hooked` and `unhook` methods should be self-explanitory.

`hook_symbol` is a different function that serves a different purpose. Instead of an address, you pass it the name of a function that that binary imports.
The internal (GOT) pointer to the code that function resolved to will be replaced with a pointer to the SimProcedure or hook function you specify in the third argument. You can also pass a plain integer to make replace pointers to the symbol with that value.

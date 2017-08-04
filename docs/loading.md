# Loading a Binary - CLE and angr Projects

Previously, you saw just the barest taste of angr's loading facilities - you loaded `/bin/true`, and then loaded it again without its shared libraries. You also saw `proj.loader` and a few things it could do. Now, we'll dive into the nuances of these interfaces and the things they can tell you.

We briefly mentioned angr's binary loading component, CLE. CLE stands for "CLE Loads Everything", and is responsible for taking a binary \(and any libraries that it depends on\) and presenting it to the rest of angr in a way that is easy to work with. The CLE loader \(`cle.Loader`\) represents an entire conglomerate of loaded _binary objects_, loaded and mapped into a single memory space. Each binary object is loaded by a loader backend that can handle its filetype \(a subclass of `cle.Backend`\). For example, `cle.ELF` is used to load ELF binaries.

CLE can be interfaced with as follows:

```python
# this is the CLE Loader object, as we have seen
>>> import angr
>>> proj = angr.Project('/bin/true')
>>> print proj.loader

# this is a dictionary of the objects that are loaded as part of loading the binary (their types depend on the backend)
>>> print b.loader.shared_objects

# this is the memory space of the process after being loaded. It maps addresses to the byte at that address.
# The exact type of the memory object is a special class called a Clemory, but you can treat it as a dict.
>>> print b.loader.memory[b.loader.min_addr()]

# this is the object for the main binary (its type depends on the backend)
>>> print b.loader.main_object

# this retrieves the binary object which maps memory at the specified address
>>> print b.loader.addr_belongs_to_object(b.loader.max_addr())

# Get the address of the Global Offset Table slot for a symbol (in the main binary)
>>> print b.loader.find_symbol_got_entry('__libc_start_main')
```

It is also possible to interface directly with individual binary objects:

```python
# this is a list of the names of libraries the program depend on. We obtain it
# *statically* by reading the DT_NEEDED field of the dynamic section of the ELF
# binary.
>>> print b.loader.main_object.deps

# this is the memory contents of *just* the main binary, based at the zero-address
>>> print b.loader.main_object.memory

# this is a dict (name->ELFRelocation) of imports required by the libc which was loaded
>>> b.loader.shared_objects['libc.so.6'].imports
```

In order to see all the things you can do with the CLE loader and its backends, look at the [CLE API docs.](http://angr.io/api-doc/cle.html)

## Loading Options

If you are loading something with `angr.Project` and you want to pass an option to the `cle.Loader` instance that Project implicitly creates, you can just pass the keyword argument directly to the Project constructor, and it will be passed on to CLE.

Again, you should look at the API docs in order to learn about all the possible parameters that can be used to customize the binary loading process, but some important ones are detailed here.

#### Basic Options

We've discussed `auto_load_libs` already - it enables or disables CLE's attempt to automatically resolve shared library dependencies, and is on by default. Additionally, there is the opposite, `except_missing_libs`, which, if set to true, will cause an exception to be thrown whenever a binary has a shared library dependency that cannot be resolved.

You can pass a list of strings to `force_load_libs` and anything listed will be treated as an unresolved shared library dependency right out of the gate, or you can pass a list of strings to `skip_libs` to prevent any library of that name from being resolved as a dependency. Additionally, you can pass a list of strings \(or a single string\) to `custom_ld_path`, which will be used as an additional search path for shared libraries, before any of the defaults: the same directory as the loaded program, the current working directory, and your system libraries.

#### Per-Binary Options

If you want to specify some options that only apply to a specific binary object, CLE will let you do that too. The parameters `main_ops` and `lib_opts` do this by taking dictionaries of options. `main_opts` is a mapping from option names to option values, while `lib_opts` is a mapping from library name to dictionaries mapping option names to option values.

The options that you can use vary from backend to backend, but some common ones are:

* `backend` - which backend to use, as either a class or a name
* `custom_base_address` - a base address to use
* `custom_entry_point` - an entry point to use
* `custom_arch` - the name of an architecture to use

Example:

```python
angr.Project(main_opts={'backend': 'ida', 'custom_arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```

## Backends

CLE currently has backends for statically loading ELF, PE, CGC, Mach-O and ELF core dump files, as well as loading binaries with IDA and loading files into a flat address space. CLE will automatically detect the correct backend to use in most cases, so you shouldn't need to specify which backend you're using unless you're doing some pretty weird stuff.

You can force CLE to use a specific backend for an object by by including a key in its options dictionary, as described above. Some backends cannot autodetect which architecture to use and _must_ have a `custom_arch` specified. The key doesn't need to match any list of architectures; angr will identify which architecture you mean given almost any common identifier for any supported arch.

To refer to a backend, use the name from this table:

| backend name | description | requires `custom_arch`? |
| --- | --- | --- |
| elf | Static loader for ELF files based on PyELFTools | no |
| pe | Static loader for PE files based on PEFile | no |
| mach-o | Static loader for Mach-O files. Does not support dynamic linking or rebasing. | no |
| cgc | Static loader for Cyber Grand Challenge binaries | no |
| backedcgc | Static loader for CGC binaries that allows specifying memory and register backers | no |
| elfcore | Static loader for ELF core dumps | no |
| ida | Launches an instance of IDA to parse the file | yes |
| blob | Loads the file into memory as a flat image | yes |

## Dynamic Linking and Dependency Resolution

If you're unfamiliar with how dynamic linking works, here is a quick summary.

Consider the case that you write a C program that uses the function `strlen`. There are a lot of programs who want to use strlen, so it is advantageous to store it in a _shared library_ and make that library available to any program who wants to use `strlen`. At runtime, your operating system's loader must see that your program has a _dependency_ on a shared library, in this case the C standard library, libc. The libc object is then loaded into the same address space as your binary, but your binary needs to be given a pointer to it somehow. The mechanism for this is called _relocations_. Your binary will contain a relocation saying "hello, I need strlen. When you find it, please write its address _here_." The process of satisfying all these dependencies and updating all the references to the imported functions at runtime is called _dynamic linking_.

When a shared library dependency cannot be satisfied, angr forces any unresolved relocations to point to a special region of memory called the _angr extern object_, which can pretend to provide any library function for the sake of having resolved it to somewhere at all. This object is visible in `project.loader.all_objects`.

## Symbolic Function Summaries

By default, Project tries to replace external calls to library functions by using symbolic summaries termed _SimProcedures_ - effectively just python functions that imitate the library function's effect on the state. We've implemented [a whole bunch of functions](https://github.com/angr/angr/tree/master/angr/procedures) as SimProcedures. These builtin procedures are available in the `angr.SIM_PROCEDURES` dictionary, which is two-leveled, keyed first on the package name \(libc, posix, win32, stubs\) and then on the name of the library function. Executing a SimProcedure instead of the actual library function that gets loaded from your system makes analysis a LOT more tractable, at the cost of [some potential inaccuracies](/docs/gotchas.md).

When no such summary is available for a given function:

* if `auto_load_libs` is `True` \(this is the default\), then the _real_ library function is executed instead. This may or may not be what you want, depending on the actual function. For example, some of libc's functions are extremely complex to analyze and will most likely cause an explosion of the number of states for the path trying to execute them.
* if `auto_load_libs` is `False`, then external functions are unresolved, and Project will resolve them to a generic "stub" SimProcedure called `ReturnUnconstrained`. It does what its name says: it returns a unique unconstrained symbolic value each time it is called.
* if `use_sim_procedures` \(this is a parameter to `angr.Project`, not `cle.Loader`\) is `False` \(it is `True` by default\), then no SimProcedures besides `ReturnUnconstrained` will be used.
* you may specify specific symbols to exclude from being replaced with SimProcedures with the parameters to `angr.Project`: `exclude_sim_procedures_list` and `exclude_sim_procedures_func`.
* Look at the code for `angr.Project._use_sim_procedures` for the exact algorithm.

#### Hooking

The mechanism by which angr replaces library code with a python summary is called hooking, and you can do it too! When performing simulation, at every step angr checks if the current address has been hooked, and if so, runs the hook instead of the binary code at that address. The API to let you do this is `proj.hook(addr, hook)`, where `hook` is a SimProcedure instance. You can manage your project's hooks with `.is_hooked`, `.unhook`, and `.hooked_by`, which should hopefully not require explanation.

There is an alternate API for hooking an address that lets you specify your own off-the-cuff function to use as a hook, by using `proj.hook(addr)` as a function decorator. If you do this, you can also optionally specify a `length` keyword argument to make execution jump some number of bytes forward after your hook finishes.

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.unhook(0x10000)
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

Furthermore, you can use `proj.hook_symbol(name, hook)`, providing the name of a symbol as the first argument, to hook the address where the symbol lives.

## So far so good!

By now, you should have a reasonable understanding of how to control the environment in which your analysis happens, on the level of the CLE loader and the angr Project. You should also understand that angr makes a reasonable attempt to simplify its analysis by hooking complex library functions with SimProcedures that summarize the effects of the functions.


# Loading a Binary - CLE and angr Projects

angr's binary loading component is CLE, which stands for CLE Loads Everything. CLE is responsible for taking a binary (and any libraries that it depends on) and presenting it to the rest of angr in a way that is easy to work with.

CLE's main goal is to load binaries in a robust way, i.e., the same way the actual loader (e.g., GNU LD in the case of ELF binaries) would load them. It means that some information that may be present in the binaries will be ignored by CLE, because such information may be stripped, voluntarily or involuntarily corrupted, etc.. It is not rare in the embedded world to see such things happening.

angr, in turn, encompasses this in a *Project* class. A Project class is the entity that represents your binary. Much of your interaction with angr will go through it.

To load a binary with angr (let's say "/bin/true"), you would do the following:

```python
>>> import angr

>>> b = angr.Project("/bin/true")
```

After this, *b* is angr's representation of your binary (the "main" binary), along with any libraries that it depends on. There are several basic things that you can do here without further knowledge of the rest of the platform:

```python
# this is the entry point of the binary
>>> print b.entry

# these are the minimum and maximum addresses of the binary's memory contents
>>> print b.loader.min_addr(), b.loader.max_addr()

# this is the full name of the binary
>>> print b.filename
```

CLE exposes the binary's information through the Loader class. The CLE loader (cle.Loader) represents an entire conglomerate of loaded CLE binary objects, loaded and mapped into a single memory space. Each binary object is loaded by a loader backend that can handle its filetype (a subclass of cle.Backend). For example, cle.ELF is used to load ELF binaries.

CLE can be interfaced with as follows:

```python
# this is the CLE Loader object
>>> print b.loader

# this is a dictionary of the objects that are loaded as part of loading the binary (their types depend on the backend)
>>> print b.loader.shared_objects

# this is the memory space of the process after being loaded. It maps addresses to the byte at that address.
>>> print b.loader.memory[b.loader.min_addr()]

# this is the object for the main binary (its type depends on the backend)
>>> print b.loader.main_bin

# this retrieves the binary object which maps memory at the specified address
>>> print b.loader.addr_belongs_to_object(b.loader.max_addr())

# Get the address of the GOT slot for a symbol (in the main binary)
>>> print b.loader.find_symbol_got_entry('__libc_start_main')

```

It is also possible to interface directly with individual binary objects:
```python
# this is a list of the names of libraries the program depend on. We obtain it
# *statically* by reading the DT_NEEDED field of the dynamic section of the Elf
# binary.
>>> print b.loader.main_bin.deps

# this is a dict of the memory contents of *just* the main binary
>>> print b.loader.main_bin.memory

# this is a dict (name->ELFRelocation) of imports required by the libc which was loaded
>>> b.loader.shared_objects['libc.so.6'].imports

# this is a dict (name->ELFRelocation) of imports of the main binary, where addr is usually 0 (see the misc section below).
>>> print b.loader.main_bin.imports
```

## Loading dependencies

By default, CLE will attempt to load all the dependencies of the main binary (e.g., libc.so.6, ld-linux.so.2, etc.), unless `auto_load_libs` is set to `False` in the loading options. When loading libraries, if it cannot find one of them, it will silently ignore the error and mark all the dependencies on that library as unresolved. If you like, you can change this behavior.

## Loading Options

Loading options can be passed to Project (which in turn will pass it to CLE). 

CLE expects a dict as a set of parameters. Parameters which must be applied to libraries which 
are not the target binary must be passed through the lib_opts parameter in the following form:
```python
load_options = {'main_opts':{options0}, 'lib_opts': {libname1:{options1}, path2:{options2}, ...}}

# Or in a more readable form:
load_options = {}
load_options['main_opts'] = {k1:v1, k2:v2 ...}
load_options['lib_opts'] = {}
load_options['lib_opts'][path1] = {k1:v1, k2:v2, ...}
load_options['lib_opts'][path2] = {k1:v1, k2:v2, ...}
etc.
```

### Valid options

```python
>>> load_options = {}

# shall we also load dynamic libraries?
>>> load_options['auto_load_libs'] = False

# A list of libraries to load regardless of whether they're required by the loaded object
>>> load_options['force_load_libs'] = ['libleet.so']

# specific libs to skip
>>> load_options['skip_libs'] = ['libc.so.6']

# Options to be used when loading the main binary
>>> load_options['main_opts'] = {'backend': 'elf'}

# A dictionary mapping library names to a dictionary of objects to be used when loading them.
>>> load_options['lib_opts'] = {'libc.so.6': {'custom_base_addr': 0x13370000}}

# A list of paths we can additionally search for shared libraries
>>> load_options['custom_ld_path'] = ['/my/fav/libs']

# Whether libraries with different version numbers in the filename will be considered equivilant, for example libc.so.6 and libc.so.0
>>> load_options['ignore_import_version_numbers'] = False

# The alignment to use for rebasing shared objects
>>> load_options['rebase_granularity'] = 0x1000

# Throw an Exception if a lib cannot be found (the default is fail silently on missing libs)
>>> load_options['except_missing_libs'] = True
```

The following options are applied on a per object basis and override CLE's automatic detection. 
They can be applied through either 'main_opts' or 'lib_opts'.

```python
# Base address to load the binary
>>> load_options['main_opts'] = {'custom_base_addr':0x4000}

# Specify the object's backend (backends discussed below)
>>> load_options['main_opts'] = {'backend': 'elf'}

```

Example with multiple options for the same binary:
```python
>>> load_options['main_opts'] = {'backend':'elf', 'custom_base_addr': 0x10000}
```
## Backends

CLE currently has backends for statically loading ELF, PE, CGC and ELF core dump files, as well as loading binaries with IDA and loading files into a flat address space. CLE will automatically detect the correct backend to use in most all cases, so you shouldn't need to specify which backend you're using unless you're doing some pretty weird stuff.

You can specify the backend for a binary by including a key in its options dictionary. If you need to force the architecture of a certain binary instead of having it auto-detected, you can specify it with the `custom_arch` key. The key doesn't need to match any list of arches; angr will identify which architecture you mean given almost any common identifier for any supported arch.

```python
>>> load_options = {}
>>> load_options['main_opts'] = {'backend': 'elf', 'custom_arch': 'i386'}
>>> load_options['lib_opts'] = {'libc.so.6': {'backend': 'elf'}}
```

| backend key | description | requires `custom_arch`? |
| --- | --- | --- |
| elf | Static loader for ELF files based on PyELFTools | no |
| pe | Static loader for PE files based on PEFile | no |
| cgc | Static loader for Cyber Grand Challenge binaries | no |
| backedcgc | Static loader for CGC binaries that allows specifying memory and register backers | no |
| elfcore | Static loader for ELF core dumps | no |
| ida | Launches an instance of IDA to parse the file | yes |
| blob | Loads the file into memory as a flat image | yes |

Now that you have loaded a binary, interesting information about the binary is now accessible in ```b.loader.main_bin```. For example, the shared library dependencies, the list of imported libraries, memory, symbols and others. 
Make heavy use of IPython's tab-completion to see available functions and options here.

Now it's time to look at the [IR support](./ir.md)


## Misc

### Imports

The following is ELF specific.
On most architectures, imports, i.e., symbols that refer to functions or global names that are outside of the binary (in shared libraries) appear in the symbol table, most of the time with an undefined address (0). On some architectures like MIPS, it contains the address of the function's PLT stub (which resides in the text segment).
If you are looking for the address of the GOT entry related to a specific symbol (which resides in the data segment), take a look at jmprel. It is a dict (symbol-> GOT addr):

Whether you are after a PLT or GOT entry depends on the architecture. Architecture specific stuff is defined in a class in the Archinfo repository. The way we deal with absolute addresses of functions depending on the architecture is defined in this class, in the got_section_name property.

For more details about ELF loading and architecture specific details, check the [Executable and linkable format document](http://www.cs.northwestern.edu/~pdinda/icsclass/doc/elf.pdf) as well as the ABI supplements for each architecture ([MIPS](http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf), [PPC64](http://math-atlas.sourceforge.net/devel/assembly/PPC-elf64abi-1.7.pdf), [AMD64](http://www.x86-64.org/documentation/abi.pdf))..
```python
>>> rel = b.loader.main_bin.jmprel
```

### Symbolic analysis: function summaries

By default, Project tries to replace external calls to libraries' functions by using [symbolic summaries](./todo.md) termed *SimProcedures* (these are summaries of how functions affect the state). 

When no such summary is available for a given function:

- if `auto_load_libs` is `True` (this is the default), then the *real* library function is executed instead. This may or may not be what you want, depending on the actual function. For example, some of libc's functions are extremely complex to analyze and will most likely cause an explosion of the number of states for the [path](./paths.md) trying to execute them.
- if `auto_load_libs` is `False`, then external functions are unresolved, and Project will resolve them to a generic "stub" SimProcedure called `ReturnUnconstrained`. It does what its name says: it returns unconstrained values.
- if `use_sim_procedures` (this is a parameter to `angr.Project`, not `cle.Loader`) is `False` (it is `True` by default), then no SimProcedures besides `ReturnUnconstrained` will be used.
- you may specify specific symbols to exclude from being replaced with SimProcedures with the parameters to `angr.Project`: `exclude_sim_procedures_list` and `exclude_sim_procedures_func`.
- Look at the code for `angr.Project._use_sim_procedures` for the exact algorithm.

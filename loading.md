# Loading a Binary - CLE and angr Projects

Angr's binary loading component is CLE, which stands for Christophe's Loader for Everything. CLE is responsible for taking a binary (and any libraries that it depends on) and presenting it to the rest of Angr in a way that is easy to work with.

CLE's main goal is to load binaries in a robust way, i.e., the same way the actual loader (e.g., GNU LD in the case of ELF binaries) would load them. It means that some information that may be present in the binaries will be ignored by CLE, because such information may be stripped, voluntarily or unvoluntarily corrupted, etc.. It is not rare in the embedded world to see such things happening.

Angr, in turn, encompasses this in a *Project* class. A Project class is the entity that represents your binary, and much of your interaction with angr will go through it.

To load a binary with angr (let's say "/tmp/program"), you would do the following:

```python
import angr

b = angr.Project("/tmp/program")
```

After this, *b* is angr's representation of your binary (the "main" binary), along with any libraries that it depends on. There are several basic things that you can do here without further knowledge of the rest of the platform:

```python
# this is the entry point of the binary
print b.entry

# these are the minimum and maximum addresses of the binary's memory contents
print b.min_addr, b.max_addr

# this is the base filename and directory name of the binary
print b.dirname + '/' + b.basename
```

CLE exposes the binary's information through two main interfaces: a CLE loader (Cle.Ld) represents an entire conglomerate of loaded CLE binary objects. Different CLE.Binary types are used for different types of binaries. For example, CLE.ELF is used to load ELF binaries. (These are different "backends", see the backends section).

CLE can be interfaced with as follows:

```python
# this is the CLE Loader object
print b.ld

# this is a dictionary of the objects that are loaded as part of loading the binary (their types depend on the backend)
print b.ld.shared_objects

# this is a dict of the memory space of the process after being loaded. It maps addresses to the byte at that address.
print b.ld.memory[b.max_addr]

# this is the object for the main binary (its type depends on the backend)
print b.ld.main_bin

# this retrieves the binary object which maps memory at the specified address
print b.ld.addr_belongs_to_object(b.max_addr)

# Get the address of the GOT slot for a symbol (in the main binary)
print b.ld.find_symbol_got_entry(symbol)

```

It is also possible to interface directly with individual binary objects:
```python
# this is a list of the names of libraries the program depend on. We obtain it
# *statically* by reading the DT_NEEDED field of the dynamic section of the Elf
# binary.
print b.ld.main_bin.deps

# this is a dict of the memory contents of *just* the main binary
print b.ld.main_bin.memory

# this is a dict (name->ELFRelocation) of imports from the libc which was loaded
b.ld.shared_objects['libc.so.6'].imports

# this is a dict (name->ELFRelocation) of imports of the main binary, where addr is usually 0 (see the misc section below).
print b.ld.main_bin.imports
```

## Loading dependencies

By default, CLE won't attempt to load all the dependencies of the main binary (e.g., libc.so.6, ld-linux.so.2, etc.), unless `auto_load_libs` is set to `True` in the loading options. When loading libraries, if it cannot find one of them, it will stop the execution by raising an exception. In this case, you can attempt to manually copy the missing dependency in the same directory as the main binary, or alternatively, ignore the missing dependency (see the paragraph on loading option):

```python
load_options = {}
load_options = {skip_libs='ld.so.2'}
b = angr.Project("/bin/ls", load_options=load_options)
```

To load external libraries, CLE first attempts to *dynamically* get dependency information by running the binary in an emulated target environment, in which it hooks GNU LD through the LD_AUDIT interface. This yields a dict of *paths to libraries* along with the *base addresses* where to load them.

If this fails (this can happen for various reasons, e.g., incompatible ABI between the target environment and the binary we are trying to execute), then CLE falls back to *statically* extracting dependency names from the binary, and :
- looks in the current directory (i.e., where the main binary is) for *matching libraries*
- for libs not found there, it recursively looks for system libraries in the standard locations such as `/lib/x86_64_linux_gnu` (depending on the main binary's architecture).
- a *matching library* is a library with both the correct name+version and the right architecture for the loaded binary.

## Loading Options

Loading options can be passed to Project (which in turn will pass it to CLE). 

Cle expects a dict as a set of parameters. Parameters which must be applied to libraries which 
are not the target binary must be passed through the lib_opts parameter in the following form:
```python
load_options = {'lib_opts': {path1:{options1}, path2:{options2}, ...}}

# Or in a more readable form:
load_options = {}
load_options['lib_opts'] = {}
load_options['lib_opts'][path1] = {k1:v1, k2:v2, ...}
load_options['lib_opts'][path2] = {k1:v1, k2:v2, ...}
etc.
```
where:
- each path is a distinct binary. 
- each set of options is a dict.

Instead of using a path, you can also set the load options for all binaries on the main level.
```python
p = angr.Project("...", load_options={"auto_load_libs": True})
```

### Valid options
The following options are only relevant for the main binary (i.e., the
first binary passed to CLE):

```python
# shall we also load dynamic libraries ?
load_options['auto_load_libs'] = True

# A list of libraries to load regardless of whether they're required by the loaded object
load_options['force_load_libs'] = ['libleet.so']

# specific libs to skip
load_options['skip_libs'] = ['libc.so.6']

# Options to be used when loading the main binary
load_options['main_opts'] = {'backend': 'elf'}

# A dictionary mapping library names to a dictionary of objects to be used when loading them.
load_options['lib_opts'] = {'libc.so.6': {'auto_load_libs': True}}

# A list of paths we can additionally search for shared libraries
load_options['custom_ld_path'] = ['/my/fav/libs']

# Whether libraries with different version numbers in the filename will be considered equivilant, for example libc.so.6 and libc.so.0
load_options['ignore_import_version_numbers'] = False

# The alignment to use for rebasing shared objects
load_options['rebase_granularity'] = 0x1000

# Throw an Exception if a lib cannot be found (the default is fail silently on missing libs)
load_options['except_missing_libs'] = True
```

The following options are applied on a per object basis and override CLE's automatic detection. 
They can be applied through either 'main_opts' or 'lib_opts'.

```python
# Base address to load the binary
load_options['main_opts'] = {'custom_base_addr':0x4000}

# Specify the object's backend (backends discussed below)
load_options['main_opts'] = {'backend': 'elf'}

```

Example with multiple options for the same binary:
```python
load_options['main_opts'] = {'backend':'elf', 'custom_base_addr': 0x10000}
```
## Backends

Cle currently supports Elf, PE, IDA, Blob and CLEextract backends.

Elf is the default backend and is recommended unless you are not working with Elf binaries or have some specific needs that cannot be achieved with Cle (such as relying on information from the Elf sections).

IDA runs an instance of IDA for each binary and communicates with it through idalink. 

Blob is a special backend for binaries of unknown types. It provides no abstractions other than mapping the binary into memory, using a custom entry point, a custom base address or skipping the first @offset bytes of the image.

You can specify the backend for the main binary by specifying it in the main_opts arguments. Library backends can be specified via the lib_opts argument.

```python

load_options = {}
load_options['main_opts'] = {'backend': 'elf'}
load_options['lib_opts'] = {'libc.so.6': {'backend': 'elf'}}
```

Now that you have loaded a binary.
Interesting information about the binary is now accessible in ```p.main_binary```, for example deps, the list of imported libs, memory, symbols and others. 
Make heavy use of the tabbing feature of ipython to see available functions and options here.

Now it's time to look at the [IR support](./ir_support.md)


## Misc
### Imports
The following is ELF specific.
On most architectures, imports, i.e., symbols that refer to functions or global names that are outside of the binary (in shared libraries) appear in the symbol table, most of the time with an undefined address (0). On some architectures like MIPS, it contains the address of the function's PLT stub (which resides in the text segment).
If you are looking for the address of the GOT entry related to a specific symbol (which resides in the data segment), take a look at jmprel. It is a dict (symbol-> GOT addr):

Whether you are after a PLT or GOT entry depends on the architecture. Cle's architecture specific stuff is defined in the Archinfo class. The way we deal with absolute addresses of functions depending on the architecture is defined in this class, in the got_section_name() function. 

For more details about Elf loading and architecture specific details, check the [Executable and linkable format document](http://www.cs.northwestern.edu/~pdinda/icsclass/doc/elf.pdf) as well as the ABI supplements for each architecture ([MIPS](http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf), [PPC64](http://math-atlas.sourceforge.net/devel/assembly/PPC-elf64abi-1.7.pdf), [AMD64](http://www.x86-64.org/documentation/abi.pdf))..
```python
rel = b.main_bin.jmprel
```

### Symbolic analysis: stepping into functions
By default, Project tries to replace external calls to libraries' functions by using [symbolic summaries](./todo.md) termed *SimProcedures* (these are summaries of how functions affect the state). 

When no such summary is available for a given function:
- if `load_libs` is `True` (this is the default), then the *real* library function is executed instead. This may or may not be what you want, depending on the actual function. For example, some of libc's functions are extremely complex to analyze and will most likely cause an explosion of the number of states for the [path](./todo.md) trying to execute them.

- if `load_libs` is `False`, then external functions are unresolved, and Project will resolve them to a generic "stub" SimProcedure called `ReturnUnconstrained`. It does what its name says: it returns unconstrained values.

- if you need something more fine grained, you can selectively exclude specific libraries from loading, in this case, the analysis will only step into functions that can be resolved (that is, the functions of the libraries you did not exclude). You can do so with CLE's `skip_libs` option.

- If excluding a whole library is too coarse grained for you, and you want to exclude specific functions, you can do so by manually replacing it with a `ReturnUnconstrained` stub as follows:

```python
# Get the GOT address of the function (depending on the architecture, it might return the address of the PLT stub instead, which is fine too):
addr = b.ld.find_symbol_got_entry(symbol_name)

# You can also get the actual address of the function instead, this shouldn't make much difference:
addr = b.ld.find_symbol_addr(symbol_name)

# Replace the function with stub
b.add_custom_sim_procedure(addr, simuvex.SimProcedures["stubs"]["ReturnUnconstrained"])
```

### Manually using clextract
Clextract is a small C program that extracts information from binaries. Angr compiles it for each supported architecture and runs it through qemu-user. It is a good idea to have it in your PATH, for this, add the following to you ~/.bashrc:
```
PATH=$PATH:/path/to/ccle
```
As it relies on libcle, you'll also need:
```
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/ccle/x86_64
```

You can also use the clextract.sh script in cle/ccle to run it on foreign architectures.

### Manually using cle_ld_audit.so

The GNU Elf loader has an builtin auditing interface providing hooks that can be used to monitor what's going on internally when loading binaries. We use this to get information about libraries and their loading addresses. `cle_ld_audit.so` is a small library that gets this information and writes it down to a file. To invoke it:
```
cd cle/ld_audit
make

# Run the binary, using cle_ld_audit.so as the auditing library
LD_AUDIT=${arch}/cle_ld_audit.so /path/to/binary

# Results are here:
cat ld_audit.out
```

## Troubleshooting

### Q: My options are ignored
A: Cle options are an optional argument. Make sure you call Project with the following syntax:
```python
b = angr.Project(ping, load_options=load_options)
```

rather than:
```python
b = angr.Project(ping, load_options)
```


### Q: I keep getting errors of the following type:
Qemu returned error `x` while running `a_long_qemu_command`

A: You most likely have something wrong with your Cle installation. Try to rebuild and reinstall it as follows:
```python
cd angr/cle
make
make install
```


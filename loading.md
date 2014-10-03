# Loading a Binary - CLE and angr Projects

Angr's binary loading component is CLE, which stands for Christophe's Loader for Everything. CLE is responsible for taking a binary (and any libraries that it depends on) and presenting it to the rest of Angr in a way that is easy to work with.

CLE's main goal is to load binaries in a robust way, i.e., the same way the actual loader (e.g., GNU LD in the case of ELF binaries) would load them. It means that some information that may be present in the binaries will be ignored by CLE, because such information may be stripped, voluntarily or unvoluntarily corrupted, etc.. It is not rare in the embedded world to see such things happening.

Angr, in turn, encompasses this in a *Project* class. A Project class is the entity that represents your binary, and much of your interaction with angr will go through it.

To load a binary with angr (let's say "/tmp/program"), you would do the following:

```python
import angr

p = angr.Project("/tmp/program")
```

After this, *p* is angr's representation of your binary (the "main" binary), along with any libraries that it depends on. There are several basic things that you can do here without further knowledge of the rest of the platform:

```python
# this is the entry point of the binary
print p.entry

# these are the minimum and maximum addresses of the binary's memory contents
print p.min_addr, p.max_addr

# this is the base filename and directory name of the binary
print p.dirname, p.filename
```

CLE exposes the binary's information through two main interfaces: a CLE loader (Cle.Ld) represents an entire conglomerate of loaded CLE binary objects. Different CLE.Binary types are used for different types of binaries. For example, CLE.ELF is used to load ELF binaries. (These are different "backends", see the backends section).

CLE can be interfaced with as follows:

```python
# this is the CLE Loader object
print p.ld

# this is a list of (names of) the dependencies that the main binary depends on
print p.ld.dependencies

# this is a list of the objects that are loaded as part of loading the binary (their types depend on the backend)
print p.ld.shared_objects

# this is a dict of the memory space of the process after being loaded. It maps addresses to the byte at that address.
print p.ld.memory[p.max_addr]

# this is the object for the main binary (its type depends on the backend)
print p.ld.main_bin

# this retrieves the binary object which maps memory at the specified address
print print p.ld.addr_belongs_to_object(p.max_addr)
```

It is also possible to interface directly with individual binary objects:
```
# these are the libraries that the main binary depends on
print p.ld.main_bin.deps

# this is a dict of the memory contents of *just* the main binary
print p.ld.main\_bin.memory

# this is a dict (name->addr) of exports of the first shared library that was loaded
p.ld.shared_objects[0].get_exports()

# this is a dict (name-> addr) of imports of the main binary, where addr is usually 0 (see the misc section below).
print p.ld.main\_bin.imports
```

## Loading dependencies

By default, CLE attempts to load all the dependencies of the main binary (e.g., libc.so.6, ld-linux.so.2, etc.). If it cannot find one of them, it will stop the execution by raising an exception. In this case, you can attempt to manually copy the missing dependency in the same directory as the main binary, or alternatively, ignore the missing dependency (see the paragraph on loading option):

```python
load_options = {'/bin/ls':{skip_libs='ld.so.2'}}
p = angr.Project("/bin/ls", cle_ops)

```

## Backends

Cle currently supports Elf, IDA and Blob backends.

Elf is the default backend and is recommended unless you are not working with Elf binaries or have some specific needs that cannot be achieved with Cle (such as relying on information from the Elf sections).

IDA runs an instance of IDA for each binary and communicates with it through idalink. 

Blob is a special backend for binaries of unknown types. It provides no abstractions other than mapping the binary into memory, using a custom entry point, a custom base address or skipping the first @offset bytes of the image.


## Loading Options

Loading options can be passed to Project (which in turn will pass it to CLE). 

Cle expects a dict as a set of parameters of the following form:
```python
load_options = {path1:{options1}, path2:{options2}, ...}
```
where:
- each path is a distinct binary. The first binary is expected to be the main binary. Every other binary is expected to be a dependency of the fist binary.

- each set of options is a dict.

### Valid options
```
backend: 'ida' or 'elf' or 'blob' (defaults to 'elf')
```

The following options are only relevant for the main binary (i.e., the
first binary passed to CLE):

```
auto_load_libs : bool ; shall we also load dynamic libraries ?
skip_libs = [] ; specific libs to skip, e.g., skip_libs=['libc.so.6']
```

The following options override CLE's automatic detection:

```
custom_entry_point ; address of a custom entry point that will override CLE's automatic detection.
custom_base_addr ; base address to load the binary
custom_offset ; discard everything in the binary until this address

provides ; which dependency is provided by the binary. This is used instead of what CLE would normally load for this dependency. e.g., provides = 'libc.so.6'.
```

Example of valid parameters:
```python
load_options = {'/bin/ls': {backend:'elf', auto_load_libs:True, skip_libs:['libc.so.6']}}
```


Now that you have loaded a binary, it's time to look at the [IR support](./ir_support.md)


## Misc
### Imports
The following is ELF specific.
On most architectures, imports, i.e., symbols that refer to functions or global names that are outside of the binary (in shared libraries) appear in the symbol table, most of the time with an undefined address (0). On some architectures like MIPS, it contains the address of the function's PLT stub (which resides in the text segment).
If you are looking for the address of the GOT entry related to a specific symbol (which resides in the data segment), take a look at jmprel. It is a dict (symbol-> GOT addr):

Whether you are after a PLT or GOT entry depends on the architecture. Cle's architecture specific stuff is defined in the Archinfo class. The way we deal with absolute addresses of functions depending on the architecture is defined in this class, in the got_section_name() function. 

For more details about Elf loading and architecture specific details, check the [Executable and linkable format document](http://www.cs.northwestern.edu/~pdinda/icsclass/doc/elf.pdf) as well as the ABI supplements for each architecture ([MIPS](http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf), [PPC64](http://math-atlas.sourceforge.net/devel/assembly/PPC-elf64abi-1.7.pdf), [AMD64](http://www.x86-64.org/documentation/abi.pdf).
```
rel = p.main_bin.jmprel
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



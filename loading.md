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

CLE exposes the binary's information through two main interfaces: a CLE.Loader represents an entire conglomerate of loaded CLE.Binary objects. Different CLE.Binary types are used for different types of binaries. For example, CLE.ELF is used to load ELF binaries.

CLE can be interfaced with as follows:

```python
# this is the CLE Loader object
print p.ld

# this is a list of the dependencies loaded as part of loading the binary
print p.ld.dependencies

# this is a dict of the memory space of the process after being loaded. It maps addresses to the byte at that address.
print p.ld.memory[p.max_addr]

# this is the CLE object for the main binary
print p.ld.main_bin

# these are the CLE Binary objects for the binary's libraries
print p.shared_objects

# this retrieves the CLE Binary object that contains memory at a specified address
print print p.ld.addr_belongs_to_object(p.max_addr)

# these are the libraries that the main binary depends on
print p.ld.main_bin.deps

# this is a dict of the memory contents of *just* the main binary
print p.ld.main\_bin.memory

# this is a dict (name->addr) of exports of the first shared library that was loaded
p.ld.shared_objects[0].get_exports()

# this is a dict (name->???) of imports of the main binary
print p.ld.main\_bin.imports
```

## Loading dependencies

By default, CLE attempts to load all the dependencies of the main binary (e.g., libc.so.6, ld-linux.so.2, etc.). If it cannot find one of them, it will stop the execution by raising an exception. In this case, you can attempt to manually copy the missing dependency in the same directory as the main binary, or alternatively, ignore the missing dependency (see the paragraph on loading option):

```python
load_options = {'/bin/ls':{skip_libs='ld.so.2'}}
p = angr.Project("/bin/ls", cle_ops)

```

## Loading Options

Loading options can be passed to Project (which in turn will pass it to CLE). 

Cle expects a dict as a set of parameters of the following form:
```python
load_options = {path1:{options1}, path2:{options2}, ...}
```
where:
	- each path is a distinct binary. The first binary is expected to be the main binary. Every other binary is expected to be a dependency of the fist binary.

        - each set of options is a dict.

        - Valid options are:

            @backend : 'ida' or 'elf' or 'blob' (defaults to 'elf')

        The following options are only relevant for the main binary (i.e., the
        first binary passed to CLE):

            @auto_load_libs : bool ; shall we also load dynamic libraries ?
            @skip_libs = [] ; specific libs to skip, e.g., skip_libs=['libc.so.6']

        The following options override CLE's automatic detection:

            @custom_entry_point: the address of a custom entry point that will override CLE's automatic detection.
            @custom_base_addr: base address to load the binary
            @custom_offset: discard everything in the binary until this address

            @provides: which dependency is provided by the binary.
            This is used instead of what CLE would normally load for this dependency.
            e.g., provides = 'libc.so.6'.

        Example of valid parameters:
```python
load_options = {'/bin/ls': {backend:'elf', auto_load_libs:True, skip_libs:['libc.so.6']}}
```


Now that you have loaded a binary, it's time to look at the [IR support](./ir_support.md)



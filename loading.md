# Loading a Binary - CLE and angr Projects

Angr's binary loading component is CLE, which stands for Christophe's Loader for Everything. CLE is responsible for taking a binary (and any libraries that it depends on) and persenting it to the rest of Angr in a way that is easy to work with. Angr, in turn, encompasses this in a *Project* class. A Project class is the entity that represents your binary, and much of your interaction with angr will go through it.

To load a binary with angr (let's say "/tmp/program"), you would do the following:

```python
import angr

p = angr.Project("/tmp/program")
```

After this, *p* is angr's representation of your binary, along with any libraries that it depends on. There are several basic things that you can do here without further knowledge of the rest of the platform:

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

Now that you have loaded a binary, it's time to look at the [IR support](./ir_support.md)



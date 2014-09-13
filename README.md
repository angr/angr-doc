# How to be Angry

This is a collection of documentation for angr. By reading this, you'll become and angr pro and will be able to fold binaries to your whim.

## What is Angr?

Angr is a multi-architecture binary analysis platform, with the capability to perform dynamic symbolic execution (like Mayhem, KLEE, etc) and various static analyses on binaries. Several challenges must be overcome to do this. They are, roughly:

- Loading a binary into the analysis program.
- Translating a binary into an intermediate representation (IR).
- Translating that IR into a semantic representation (i.e., what it *does*, not just what it *is*).
- Performing the actual analysis. This could be:
 - A full-program static analysis (i.e., type inference, program slicing).
 - A symbolic exploration of the program's state space (i.e., "Can we execute it until we find an overflow?").
 - Some combination of the above (i.e., "Let's execute only program slices that lead to a memory write, to find an overflow.")

Angr has components that meet all of these challenges. This document will explain how each one works, and how they can all be used to accomplish your evil goals.

## Loading a Binary - CLE and angr Projects

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

Now that you have loaded a binary, it's time to look at the IR support.

## Intermediate Representation

Because angr deals with widely diverse architectures, it must carry out its analysis on an intermediate representation. The IR abstracts away several architecture differences when dealing with different architectures, allowing a single analysis to be run on all of them:

- **Register names.** The quantity and names of registers differ between architectures, but modern CPU designs hold to a common theme: each CPU contains several general purpose registers, a register to hold the stack pointer, a set of registers to store condition flags, and so forth. The IR provides a consistent, abstracted interface to registers on different platforms. Specifically, VEX models the registers as a separate memory space, with integer offsets (i.e., AMD64's `rax` is stored starting at address 16 in this memory space).
- **Memory access.** Different architectures access memory in different ways. For example, ARM can access memory in both little-endian and big-endian modes. The IR must abstracts away these differences.
- **Memory segmentation.** Some architectures, such as x86, support memory segmentation through the use of special segment registers. The IR understands such memory access mechanisms.
- **Instruction side-effects.** Most instructions have side-effects. For example, most operations in Thumb mode on ARM update the condition flags, and stack push/pop instructions update the stack pointer. Tracking these side-effects in an *ad hoc* manner in the analysis would be crazy, so the IR makes these effects explicit.

There are lots of choices for an IR. We use VEX, since the uplifting of binary code into VEX is quite well supported.
VEX is an architecture-agnostic, side-effects-free representation of a number of target machine languages.
It abstracts machine code into a representation designed to make program analysis easier.
This representation has four main classes of objects:

- **Expressions.** IR Expressions represent a calculated or constant value. This includes memory loads, register reads, and results of arithmetic operations.
- **Operations.** IR Operations describe a *modification* of IR Expressions. This includes integer arithmetic, floating-point arithmetic, bit operations, and so forth. An IR Operation applied to IR Expressions yields an IR Expression as a result.
- **Temporary variables.** VEX uses temporary variables as internal registers: IR Expressions are stored in temporary variables between use. The content of a temporary variable can be retrieved using an IR Expression. These temporaries are numbered, starting at `t0`.
- **Statements.** IR Statements model changes in the state of the target machine, such as the effect of memory stores and register writes. IR Statements use IR Expressions for values they may need. For example, a memory store *IR Statement* uses an *IR Expression* for the target address of the write, and another *IR Expression* for the content.
- **Blocks.** An IR Block is a collection of IR Statements, representing an extended basic block in the target architecture. A block can have several exits. For conditional exits from the middle of a basic block, a special *Exit* IR Statement is used. An IR Expression is used to represent the target of the unconditional exit at the end of the block.

VEX IR is actually quite well documented in the `libvex_ir.h` file (https://git.seclab.cs.ucsb.edu/gitlab/angr/vex/blob/master/pub/libvex_ir.h) in the VEX repository. For the lazy, we'll detail some parts of VEX that you'll likely interact with fairly frequently. To begin with, here are some IR Expressions:

| IR Expression | Evaluated Value | VEX Output Example |
| ------------- | --------------- | ------- |
| Constant | A constant value. | 0x4:I32 |
| Read Temp | The value stored in a VEX temporary variable. | RdTmp(t10) |
| Get Register | The value stored in a register. | GET:I32(16) |
| Load Memory | The value stored at a memory address, with the address specified by another IR Expression. | LDle:I32 / LDbe:I64 |
| Operation | A result of a specified IR Operation, applied to specified IR Expression arguments. | Add32 |
| If-Then-Else | If a given IR Expression evaluates to 0, return one IR Expression. Otherwise, return another. | ITE |
| Helper Function | VEX uses C helper functions for certain operations, such as computing the conditional flags registers of certain architectures. These functions return IR Expressions. | function\_name() |

These expressions are then, in turn, used in IR Statements. Here are some common ones:

| IR Statement | Meaning | VEX Output Example |
| ------------ | ------- | ------------------ |
Write Temp | Set a VEX temporary variable to the value of the given IR Expression. | WrTmp(t1) = (IR Expression) |
Put Register | Update a register with the value of the given IR Expression. | PUT(16) = (IR Expression) |
Store Memory | Update a location in memory, given as an IR Expression, with a value, also given as an IR Expression. | STle(0x1000) = (IR Expression) |
Exit | A conditional exit from a basic block, with the jump target specified by an IR Expression. The condition is specified by an IR Expression. | if (condition) goto (Boring) 0x4000A00:I32 |

An example of an IR translation, on ARM, is produced below. In the example, the subtraction operation is translated into a single IR block comprising 5 IR Statements, each of which contains at least one IR Expression (although, in real life, an IR block would typically consist of more than one instruction). Register names are translated into numerical indices given to the *GET* Expression and *PUT* Statement.
The astute reader will observe that the actual subtraction is modeled by the first 4 IR Statements of the block, and the incrementing of the program counter to point to the next instruction (which, in this case, is located at `0x59FC8`) is modeled by the last statement.

| ARM Assembly | VEX Representation |
| ------------ | ------------------ |
| subs R2, R2, #8 | t0 = GET:I32(16)<br>t1 = 0x8:I32<br>t3 = Sub32(t0,t1)<br>PUT(16) = t3<br>PUT(68) = 0x59FC8:I32 |

We use a library called PyVEX (https://git.seclab.cs.ucsb.edu/gitlab/angr/pyvex) that exposes VEX into Python. Now that you understand VEX, you can actually play with some VEX in angr:

```
# translate a basic block starting at an address
irsb = p.block(0x4000A00)

# pretty-print the basic block
irsb.pp()

# iterate through each statement and print all the statements
for stmt in irsb.statements():
	stmt.pp()

# pretty-print the IR expression representing the data written by every store statement
import pyvex
for stmt in irsb.statements():
	if isinstance(stmt, pyvex.IRStmt.Store):
		stmt.data.pp()
```

Keep in mind that this is a *syntactic* respresentation of a basic block. That is, it'll tell you what the block means, but you don't have any context to say, for example, what *actual* data is written by a store instruction. We'll get to that next.

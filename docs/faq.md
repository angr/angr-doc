# FAQ

This is a collection of commonly-asked "how do I do X?" questions and other general questions about angr, for those too lazy to read this whole document.

## How do I load a binary?

A binary is loaded by doing:

```python
p = angr.Project("/path/to/your/binary")
```

## Why am I getting terrifying error messages from LibVEX printed to stderr?

This is something that LibVEX does when it gets fed invalid instructions.
VEX is not designed for static analysis, it's designed for instrumentation, so it's mode of handling bad data is to freak out as badly as it possibly can.
There's no way of shutting it up, short of patching it.

We've already patched VEX so that instead of exiting, bringing down the python interpreter with it, it sends up a message that turns into a python exception than can later be caught by analysis.
Long story short, *this should not affect your analysis if you're just using builtin angr routines.*

## How can I get verbose debug messages for specific angr modules ?

angr uses the standard `logging` module for logging, with every package and submodule creating a new logger.

### Debug messages for everything
The most simple way to get a debug output is the following:
```python
import logging
logging.basicConfig(level=logging.DEBUG) # ajust to the wanted debug level
```

You may want to use `logging.INFO` or whatever else instead.

### More granular control
Each angr module has its own logger string, usually all the python modules
above it in the hierarchy, plus itself, joined with dots. For example,
`angr.analyses.cfg`. Because of the way the python logging module works, you
can set the verbosity for all submodules in a module by setting a verbosity
level for the parent module. For example, `logging.getLogger('angr.analyses').setLevel(logging.INFO)`
will make the CFG, as well as all other analyses, log at the INFO level.

### Automatic log settings
If you're using angr through ipython, you can add a startup script in your
ipython profile to set various logging levels.


## Why is a CFG taking forever to construct?
You want to load the binary without shared libraries loaded. If they are loaded,
like they are by default, the analysis will try to construct a CFG through your
libraries, which is almost always a really bad idea. Add the following option
to your `Project` constructor call: `load_options={'auto_load_libs': False}`


## Why did you choose VEX instead of another IR (such as LLVM, REIL, BAP, etc)?

We had two design goals in angr that influenced this choice:

1. angr needed to be able to analyze binaries from multiple architectures. This mandated the use of an IR to preserve our sanity, and required the IR to support many architectures.
2. We wanted to implement a binary analysis engine, not a binary lifter. Many projects start and end with the implementation of a lifter, which is a time consuming process. We needed to take something that existed and already supported the lifting of multiple architectures.

Searching around the internet, the major choices were:

- LLVM is an obvious first candidate, but lifting binary code to LLVM cleanly is a pain. The two solutions are either lifting to LLVM through QEMU, which is hackish (and the only implementation of it seems very tightly integrated into S2E), or mcsema, which only supports x86.
- TCG is QEMU's IR, but extracting it seems very daunting as well and documentation is very scarse.
- REIL seems promising, but there is no standard reference implementation that supports all the architectures that we wanted. It seems like a nice academic work, but to use it, we would have to implement our own lifters, which we wanted to avoid.
- BAP was another possibility. When we started work on angr, BAP only supported lifting x86 code, and up-do-date versions of BAP were only available to academic collaborators of the BAP authors. These were two deal-breakers. BAP has since become open, but it still only supports x86_64, x86, and ARM.
- VEX was the only choice that offered an open library and support for many architectures. As a bonus, it is very well documented and designed specifically for program analysis, making it very easy to use in angr.

While angr uses VEX now, there's no fundamental reason that multiple IRs cannot be used. There are two parts of angr, outside of the `simuvex.vex` package, that are VEX-specific:

- the jump lables (i.e., the `Ijk_Ret` for returns, `Ijk_Call` for calls, and so forth) are VEX enums.
- VEX treats registers as a memory space, and so does angr. While we provide accesses to `state.regs.rax` and friends, on the backend, this does `state.registers.load(8, 8)`, where the first `8` is a VEX-defined offset for `rax` to the register file.

To support multiple IRs, we'll either want to abstract these things or translate their labels to VEX analogues.


### My load options are ignored when creating a Project.

CLE options are an optional argument. Make sure you call Project with the following syntax:

```python
b = angr.Project('/bin/true', load_options=load_options)
```

rather than:
```python
b = angr.Project('/bin/true', load_options)
```

## Why are some ARM addresses off-by-one?

In order to encode THUMB-ness of an ARM code address, we set the lowest bit to one.
This convention comes from LibVEX, and is not entirely our choice!
If you see an odd ARM address, that just means the code at `address - 1` is in THUMB mode.

## I get an exception that says ```AttributeError: 'FFI' object has no attribute 'unpack'``` What do I do?

You have an outdated version of the `cffi` Python module.  angr now requires at least version 1.7 of cffi.
Try `pip install --upgrade cffi`.  If the problem persists, make sure your operating system hasn't pre-installed an old version of cffi, which pip may refuse to uninstall.
If you're using a Python virtual environment with the pypy interpreter, ensure you have a recent version of pypy, as it includes a version of cffi which pip will not upgrade.

# FAQ

This is a collection of commonly-asked "how do I do X?" questions, for those too lazy to read this whole document.

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

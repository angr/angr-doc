# FAQ

This is a collection of commonly-asked "how do I do X?" questions, for those too lazy to read this whole document.

## How do I load a binary?

A binary is loaded by doing:

```python
p = angr.Project("/path/to/your/binary")
```

## I get an error "no module called idalink" though I can see idalink in my virtual environment, wtf ?
IDAlink must also be linked to IDA's python environment (yes, IDA has its own python stuff).

```
ln -s /home/angr/angr/idalink/idalink /home/angr/ida/ida-6.6/python
```

## Idalink cannot talk to IDA
You need to run `idal` or `idal64` once from the command line before it it can be launched non-interactively.

## How can I get verbose debug messages for specific Angr modules ?
### Debug messages for everything
The most simple way to get a debug output is the following:
```python
import logging
logging.basicConfig(level=logging.DEBUG) # ajust to the wanted debug level
```

You may want to use `logging.INFO` or whatever else instead

### Getting more control of the debug output
You'll notice that some files include the following:

```python
try:
    import standard_logging
    import angr_debug
except ImportError:
    pass
```

- [standard_logging](./standard_logging.py) is a Python script that attributes different colors to the debug output of each module.
- angr_debug.py contains a list debug options for the modules you want to debug:

```python

# Simuvex related stuff

#logging.getLogger("simuvex").setLevel(logging.DEBUG)
#logging.getLogger("s_irsb").setLevel(logging.DEBUG)
#logging.getLogger("s_irstmt").setLevel(logging.DEBUG)
#logging.getLogger("s_irexpr").setLevel(logging.DEBUG)
#logging.getLogger("s_irop").setLevel(logging.DEBUG)
#logging.getLogger("s_ccall").setLevel(logging.DEBUG)
#logging.getLogger("s_value").setLevel(logging.DEBUG)
#logging.getLogger("s_irexit").setLevel(logging.DEBUG)
#logging.getLogger("s_state").setLevel(logging.DEBUG)
logging.getLogger("s_path").setLevel(logging.DEBUG)
logging.getLogger("s_memory").setLevel(logging.DEBUG)
#logging.getLogger("s_arch").setLevel(logging.DEBUG)
#logging.getLogger("s_absfunc").setLevel(logging.DEBUG)
logging.getLogger("simuvex.s_run").setLevel(logging.DEBUG)


# IDALink

#logging.getLogger("idalink").setLevel(logging.DEBUG)
#logging.getLogger("idalink.ida_mem").setLevel(logging.DEBUG)


# Angr

logging.getLogger("angr.project").setLevel(logging.DEBUG)
logging.getLogger("angr.vexer").setLevel(logging.DEBUG)
logging.getLogger("angr.cfg").setLevel(logging.DEBUG)


# CLE
logging.getLogger("cle.ld").setLevel(logging.DEBUG)
logging.getLogger("cle.archinfo").setLevel(logging.DEBUG)
logging.getLogger("cle.idabin").setLevel(logging.DEBUG)
logging.getLogger("cle.elf").setLevel(logging.DEBUG)
logging.getLogger("cle.archinfo").setLevel(logging.DEBUG)


# Symexec

#logging.getLogger("symexec.node").setLevel(logging.WARNING)
#logging.getLogger("symexec.solver").setLevel(logging.DEBUG)
#logging.getLogger("simuvex.procedures.syscalls").setLevel(logging.DEBUG)
```

You can make use of this by creating a file called *angr_debug.py* and linking it to your python virtual environment, as follows:

```
mkdir ~/angr/angr/angr_debug/
cd ~/angr/angr/angr_debug/
touch __init__.py
touch angr_debug.py # Put whatever you like here
# Place standard_logging.py there too
ln -s /home/angr/angr/angr_debug /home/angr/.virtualenvs/angr/lib/python2.7/site-packages/angr_debug
```


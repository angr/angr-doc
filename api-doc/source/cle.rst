:mod:`cle` --- Binary Loader
============================

.. automodule:: cle


Loading Interface
-----------------

.. automodule:: cle.loader


Backends
--------

.. automodule:: cle.backends
.. automodule:: cle.backends.symbol
.. automodule:: cle.backends.regions
.. automodule:: cle.backends.region
.. automodule:: cle.backends.elf
.. automodule:: cle.backends.elf.elf
.. automodule:: cle.backends.elf.elfcore
.. automodule:: cle.backends.elf.lsda
.. automodule:: cle.backends.elf.metaelf
.. automodule:: cle.backends.elf.symbol
.. automodule:: cle.backends.elf.symbol_type
.. automodule:: cle.backends.elf.regions
.. automodule:: cle.backends.elf.hashtable
.. automodule:: cle.backends.elf.variable
.. automodule:: cle.backends.elf.subprogram
.. automodule:: cle.backends.elf.variable_type
.. automodule:: cle.backends.elf.compilation_unit
.. automodule:: cle.backends.named_region
.. automodule:: cle.backends.pe
.. automodule:: cle.backends.pe.pe
.. automodule:: cle.backends.pe.symbol
.. automodule:: cle.backends.pe.regions
.. automodule:: cle.backends.macho
.. automodule:: cle.backends.macho.macho
.. automodule:: cle.backends.macho.symbol
.. automodule:: cle.backends.macho.section
.. automodule:: cle.backends.macho.segment
.. automodule:: cle.backends.macho.binding
.. automodule:: cle.backends.minidump
.. automodule:: cle.backends.cgc
.. automodule:: cle.backends.cgc.cgc
.. automodule:: cle.backends.cgc.backedcgc
.. automodule:: cle.backends.blob
.. automodule:: cle.backends.ihex
.. automodule:: cle.backends.binja
.. automodule:: cle.backends.externs
.. automodule:: cle.backends.externs.simdata
.. automodule:: cle.backends.externs.simdata.common
.. automodule:: cle.backends.java.apk
.. automodule:: cle.backends.java.jar
.. automodule:: cle.backends.java
.. automodule:: cle.backends.java.soot
.. automodule:: cle.backends.xbe
.. automodule:: cle.backends.static_archive


Relocations
-----------

CLE's loader implements program relocation data on a plugin basis.
If you would like to add more relocation implementations, do so by subclassing the ``Relocation`` class and overriding any relevant methods or properties.
Put your subclasses in a module in the ``relocations`` subpackage of the appropraite backend package.
The name of the subclass will be used to determine when to use it!
Look at the existing versions for details.

.. automodule:: cle.backends.relocation
.. automodule:: cle.backends.elf.relocation
.. automodule:: cle.backends.elf.relocation.elfreloc
.. automodule:: cle.backends.elf.relocation.mips64
.. automodule:: cle.backends.elf.relocation.generic
.. automodule:: cle.backends.elf.relocation.armel
.. automodule:: cle.backends.elf.relocation.ppc
.. automodule:: cle.backends.elf.relocation.armhf
.. automodule:: cle.backends.elf.relocation.pcc64
.. automodule:: cle.backends.elf.relocation.i386
.. automodule:: cle.backends.elf.relocation.amd64
.. automodule:: cle.backends.elf.relocation.mips
.. automodule:: cle.backends.elf.relocation.arm
.. automodule:: cle.backends.elf.relocation.arm_cortex_m
.. automodule:: cle.backends.elf.relocation.arm64
.. automodule:: cle.backends.elf.relocation.s390x
.. automodule:: cle.backends.pe.relocation
.. automodule:: cle.backends.pe.relocation.pereloc
.. automodule:: cle.backends.pe.relocation.generic
.. automodule:: cle.backends.pe.relocation.i386
.. automodule:: cle.backends.pe.relocation.amd64
.. automodule:: cle.backends.pe.relocation.mips
.. automodule:: cle.backends.pe.relocation.arm
.. automodule:: cle.backends.pe.relocation.riscv


Thread-local storage
--------------------

.. automodule:: cle.backends.tls
.. automodule:: cle.backends.tls.elf_tls
.. automodule:: cle.backends.tls.pe_tls
.. automodule:: cle.backends.tls.elfcore_tls
.. automodule:: cle.backends.tls.minidump_tls


Misc. Utilities
---------------

.. automodule:: cle.gdb
.. automodule:: cle.memory
.. automodule:: cle.patched_stream
.. automodule:: cle.address_translator
.. automodule:: cle.utils


Errors
------

.. automodule:: cle.errors

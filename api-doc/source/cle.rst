:mod:`cle` --- Binary Loader
============================

.. automodule:: cle


Loading Interface
-----------------

.. automodule:: cle.loader


Backends
--------

.. automodule:: cle.backends
.. automodule:: cle.backends.elf
.. automodule:: cle.backends.pe
.. automodule:: cle.backends.blob
.. automodule:: cle.backends.cgc
.. automodule:: cle.backends.backedcgc
.. automodule:: cle.backends.metaelf
.. automodule:: cle.backends.elfcore
.. automodule:: cle.backends.idabin


Relocations
-----------

CLE's loader implements program relocation data on a plugin basis.
If you would like to add more relocation implementations, do so by subclassing the ``Relocation`` class and overriding any relevant methods or properties.
Put your subclasses in a module in the ``relocations`` package.
The name of the subclass will be used to determine when to use it!
Look at the existing versions for details.

.. automodule:: cle.backends.relocations


Thread-local storage
--------------------

.. automodule:: cle.tls
.. automodule:: cle.tls.elf_tls
.. automodule:: cle.tls.pe_tls


Misc. Utilities
---------------

.. automodule:: cle.errors
.. automodule:: cle.memory
.. automodule:: cle.patched_stream

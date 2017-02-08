angr API documentation
======================

angr is a multi-architecture binary analysis platform, with the capability to perform dynamic symbolic execution (like
Mayhem, KLEE, etc) and various static analyses on binaries.

**Important note for reading these docs on the web**: Autodoc has helpfully decided to link variable names to whatever it possibly can.
If you see a variable whose name is a link to something, the link is probably totally unhelpful.
Additionaly, if you see a type named lowercase ``int`` or ``bool``, and it is linked to the claripy types :class:`Int` or :class:`Bool`, this is an error.
The type should refer to the python primitive type.

.. toctree::
   :maxdepth: 2
   :glob:

   angr
   simuvex
   claripy
   cle
   pyvex
   archinfo

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


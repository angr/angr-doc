# "Help Wanted"

angr is a huge project, and it's hard to keep up.
Here, we list some big TODO items that we would love community contributions for in the hope that it can direct community involvement.
They (will) have a wide range of complexity, and there should be something for all skill levels!


## Documentation: API

We are always behind on documentation.
We've created several tracking issues on github to understand what's still missing:

1. [angr](https://github.com/angr/angr/issues/145)
2. [simuvex](https://github.com/angr/simuvex/issues/28)
3. [claripy](https://github.com/angr/claripy/issues/17)
4. [cle](https://github.com/angr/cle/issues/29)
5. [pyvex](https://github.com/angr/pyvex/issues/34)


## Documentation: gitbook

This book is missing some core areas.
Specifically, the following could be improved:

1. Finish some of the TODOs floating around the book.
2. Organize the Examples page in some way that makes sense. Right now, most of the examples are very redunant. It might be cool to have a simple table of most of them so that the page is not so overwhelming.


## Documentation/Development: The angr Course

Developing a "course" of sorts to get people started with angr would be really beneficial.
Steps have already been made in this direction [here](https://github.com/angr/angr-doc/pull/74), but more expansion would be beneficial.

Ideally, the course would have a hands-on component, of increasing difficulty, that would require people to use more and more of angr's capabilities.


## Development: angr-management

The angr GUI, [angr-management](https://github.com/angr/angr-management) needs a *lot* of work.
Exposing angr's capabilities in a usable way, graphically, would be really useful!


## Development: additional architectures

More architecture support would make angr all the more useful.
Supporting a new architecture with angr would involve:

1. Adding the architecture information to [archinfo](https://github.com/angr/archinfo)
2. Adding the IR translation to `angr.Block`.
3. Adding parsing for the IR to `simuvex` (probably as another subclass of `simuvex.SimRun`)
4. Adding a calling convention (`simuvex.SimCC`) to support SimProcedures (including system calls)
5. Adding or modifying an `angr.SimOS` to support initialization activities.
6. Creating a CLE backend to load binaries, or extending the CLE ELF backend to know about the new architecture if the binary format is ELF.

An alternative to steps 2 and 3 would be to write a lifter that lifts the architecture's native code to VEX.
This can be written in Python, if it just outputs PyVEX structures.


### Ideas for new architectures/IRs:

- PIC, AVR, other embedded architectures
- SPARC (there is some preliminary libVEX support for SPARC [here](https://bitbucket.org/iraisr/valgrind-solaris))
- LLVM IR (with this, we can extend angr from just a Binary Analysis Framework to a Program Analysis Framework and expand its capabilities in other ways!)

## Development: environment support

We use the concept of "function summaries" in angr to model the environment of operating systems (i.e., the effects of their system calls) and library functions.
Extending this would be greatly helpful in increasing angr's utility.
These function summaries can be found [here](https://github.com/angr/simuvex/tree/master/simuvex/procedures).

A specific subset of this is system calls.
Even more than library function SimProcedures (without which angr can always execute the actual function), we have very few workarounds for missing system calls.
Every implemented system call extends the set of binaries that angr can handle!

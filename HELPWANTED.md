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
- SOOT (there is no reason that angr can't analyze Java code, although doing so would require some extensions to our memory model)

## Development: environment support

We use the concept of "function summaries" in angr to model the environment of operating systems (i.e., the effects of their system calls) and library functions.
Extending this would be greatly helpful in increasing angr's utility.
These function summaries can be found [here](https://github.com/angr/simuvex/tree/master/simuvex/procedures).

A specific subset of this is system calls.
Even more than library function SimProcedures (without which angr can always execute the actual function), we have very few workarounds for missing system calls.
Every implemented system call extends the set of binaries that angr can handle!

## Development: in-vivo concolic execution

Rather than developing symbolic summaries for every system call, we can use a technique proposed by [S2E](http://dslab.epfl.ch/pubs/s2e.pdf) for concretizing necessary data and dispatching them to the OS itself.
This would make angr applicable to a *much* larger set of binaries than it can currently analyze.

While this would be most useful for system calls, once it is implemented, it could be trivially applied to any location of code (i.e., library functions).
By carefully choosing which library functions are handled like this, we can greatly increase angr's scalability.

## Design: type annotation and type information usage

angr has fledgling support for types, in the sense that it can parse them out of header files.
However, those types are not well exposed to do anything useful with.
Improving this support would make it possible to, for example, annotate certain memory regions with certain type information and interact with them intelligently.

Consider, for example, interacting with a linked list like this: `print state.memory[state.regs.rax:].next.next.value`.

## Research: semantic function identification/diffing

Current function diffing techniques (TODO: some examples) have drawbacks.
For the CGC, we created a semantic-based binary identification engine (https://github.com/angr/identifier) that can identify functions based on testcases.
There are two areas of improvement, each of which is its own research project:

1. Currently, the testcases used by this component are human-generated. However, symbolic execution can be used to automatically generate testcases that can be used to recognize instances of a given function in other binaries.
2. By creating testcases that achieve a "high-enough" code coverage of a given function, we can detect changes in functionality by applying the set of testcases to another implementation of the same function and analyzing changes in code coverage. This can then be used as a sematic function diff.

## Research: applying AFL's path selection criteria to symbolic execution

AFL does an excellent job in identifying "unique" paths during fuzzing by tracking the control flow transitions taken by every path.
This same metric can be applied to symbolic exploration, and would probably do a depressingly good job, considering how simple it is.

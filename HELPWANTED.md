# "Help Wanted"

angr is a huge project, and it's hard to keep up.  
Here, we list some big TODO items that we would love community contributions for in the hope that it can direct community involvement.  
They \(will\) have a wide range of complexity, and there should be something for all skill levels!

## Documentation

There are many parts of angr that suffer from little or no documentation.  
We desperately need community help in this area.

### API

We are always behind on documentation.  
We've created several tracking issues on github to understand what's still missing:

1. [angr](https://github.com/angr/angr/issues/145)
2. [claripy](https://github.com/angr/claripy/issues/17)
3. [cle](https://github.com/angr/cle/issues/29)
4. [pyvex](https://github.com/angr/pyvex/issues/34)

### GitBook

This book is missing some core areas.  
Specifically, the following could be improved:

1. Finish some of the TODOs floating around the book.
2. Organize the Examples page in some way that makes sense. Right now, most of the examples are very redunant. It might be cool to have a simple table of most of them so that the page is not so overwhelming.

### angr course

Developing a "course" of sorts to get people started with angr would be really beneficial.  
Steps have already been made in this direction [here](https://github.com/angr/angr-doc/pull/74), but more expansion would be beneficial.

Ideally, the course would have a hands-on component, of increasing difficulty, that would require people to use more and more of angr's capabilities.

## Research re-implementation

Unfortunately, not everyone bases their research on angr ;-\).  
Until that's remedied, we'll need to periodically implement related work, on top of angr, to make it reusable within the scope of the framework.  
This section lists some of this related work that's ripe for reimplementation in angr.

### Redundant State Detection for Dynamic Symbolic Execution

Bugrara, et al. describe a method to identify and trim redundant states, increasing the speed of symbolic execution by up to 50 times and coverage by 4%.  
This would be great to have in angr, as an ExplorationTechnique.  
The paper is here: [http://nsl.cs.columbia.edu/projects/minestrone/papers/atc13-bugrara.pdf](http://nsl.cs.columbia.edu/projects/minestrone/papers/atc13-bugrara.pdf)

### In-Vivo Multi-Path Analysis of Software Systems

Rather than developing symbolic summaries for every system call, we can use a technique proposed by [S2E](http://dslab.epfl.ch/pubs/s2e.pdf) for concretizing necessary data and dispatching them to the OS itself.  
This would make angr applicable to a _much_ larger set of binaries than it can currently analyze.

While this would be most useful for system calls, once it is implemented, it could be trivially applied to any location of code \(i.e., library functions\).  
By carefully choosing which library functions are handled like this, we can greatly increase angr's scalability.

## Development

We have several projects in mind that primarily require development effort.

### angr-management

The angr GUI, [angr-management](https://github.com/angr/angr-management) needs a _lot_ of work.  
Here is a non-exhaustive list of what is currently missing in angr-management:

* A navigator toolbar showing content in a program’s memory space, just like IDA Pro’s navigator toolbar.
* A text-based disassembly view of the program.
* Better view showing details in program states during path exploration, including modifiable register view, memory view, file descriptor view, etc.
* A GUI for cross referencing.

Exposing angr's capabilities in a usable way, graphically, would be really useful!

### IDA Plugins

Much of angr's functionality could be exposed via IDA.  
For example, angr's data dependence graph could be exposed in IDA through annotations, or obfuscated values can be resolved using symbolic execution.

### Additional architectures

More architecture support would make angr all the more useful.  
Supporting a new architecture with angr would involve:

1. Adding the architecture information to [archinfo](https://github.com/angr/archinfo)
2. Adding an IR translation. This may be either an extension to PyVEX, producing IRSBs, or another IR entirely.
3. If your IR is not VEX, add a `SimEngine` to support it.
4. Adding a calling convention \(`angr.SimCC`\) to support SimProcedures \(including system calls\)
5. Adding or modifying an `angr.SimOS` to support initialization activities.
6. Creating a CLE backend to load binaries, or extending the CLE ELF backend to know about the new architecture if the binary format is ELF.

**ideas for new architectures:**

* PIC, AVR, other embedded architectures
* SPARC \(there is some preliminary libVEX support for SPARC [here](https://bitbucket.org/iraisr/valgrind-solaris)\)

**ideas for new IRs:**

* LLVM IR \(with this, we can extend angr from just a Binary Analysis Framework to a Program Analysis Framework and expand its capabilities in other ways!\)
* SOOT \(there is no reason that angr can't analyze Java code, although doing so would require some extensions to our memory model\)

### Environment support

We use the concept of "function summaries" in angr to model the environment of operating systems \(i.e., the effects of their system calls\) and library functions. Extending this would be greatly helpful in increasing angr's utility.  
These function summaries can be found [here](https://github.com/angr/angr/tree/master/angr/procedures).

A specific subset of this is system calls. Even more than library function SimProcedures \(without which angr can always execute the actual function\), we have very few workarounds for missing system calls. Every implemented system call extends the set of binaries that angr can handle!

## Design Problems

There are some outstanding design challenges regarding the integration of additional functionalities into angr.

### Type annotation and type information usage

angr has fledgling support for types, in the sense that it can parse them out of header files. However, those types are not well exposed to do anything useful with. Improving this support would make it possible to, for example, annotate certain memory regions with certain type information and interact with them intelligently.

Consider, for example, interacting with a linked list like this: `print state.memory[state.regs.rax].next.next.value`.

## Research Challenges

Historically, angr has progressed in the course of research into novel areas of program analysis. Here, we list several self-contained research projects that can be tackled.

### Semantic function identification/diffing

Current function diffing techniques \(TODO: some examples\) have drawbacks. For the CGC, we created a semantic-based binary identification engine \([https://github.com/angr/identifier](https://github.com/angr/identifier)\) that can identify functions based on testcases. There are two areas of improvement, each of which is its own research project:

1. Currently, the testcases used by this component are human-generated. However, symbolic execution can be used to automatically generate testcases that can be used to recognize instances of a given function in other binaries.
2. By creating testcases that achieve a "high-enough" code coverage of a given function, we can detect changes in functionality by applying the set of testcases to another implementation of the same function and analyzing changes in code coverage. This can then be used as a sematic function diff.

### Applying AFL's path selection criteria to symbolic execution

AFL does an excellent job in identifying "unique" paths during fuzzing by tracking the control flow transitions taken by every path.  
This same metric can be applied to symbolic exploration, and would probably do a depressingly good job, considering how simple it is.

## Overarching Research Directions

There are areas of program analysis that are not well explored. We list general directions of research here, but readers should keep in mind that these directions likely describe potential undertakings of entire PhD dissertations.

### Process interactions

Almost all work in the field of binary analysis deals with single binaries, but this is often unrealistic in the real world. For example, the type of input that can be passed to a CGI program depend on pre-processing by a web server. Currently, there is no way to support the analysis of multiple concurrent processes in angr, and many open questions in the field \(i.e., how to model concurrent actions\).

### Intra-process concurrency

Similar to the modeling of interactions between processes, little work has been done in understanding the interaction of concurrent threads in the same process. Currently, angr has no way to reason about this, and it is unclear from the theoretical perspective how to approach this.

A subset of this problem is the analysis of signal handlers \(or hardware interrupts\). Each signal handler can be modeled as a thread that can be executed at any time that a signal can be triggered. Understanding when it is meaningful to analyze these handlers is an open problem. One system that does reason about the effect of interrupts is [FIE](http://pages.cs.wisc.edu/~davidson/fie/).

### Path explosion

Many approaches \(such as [Veritesting](https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos et al._2014_Enhancing Symbolic Execution with Veritesting.pdf)\) attempt to mitigate the path explosion problem in symbolic execution. However, despite these efforts, path explosion is still _the_ main problem preventing symbolic execution from being mainstream.

angr provides an excellent base to implement new techniques to control path explosion. Most approaches can be easily implemented as [Exploration Techniques](http://angr.io/api-doc/angr.html#angr.exploration_techniques.ExplorationTechnique) and quickly evaluated \(for example, on the [CGC dataset](https://github.com/CyberGrandChallenge/samples).


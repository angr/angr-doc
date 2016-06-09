# What is angr?

angr is a multi-architecture binary analysis platform, with the capability to perform dynamic symbolic execution (like Mayhem, KLEE, etc.) and various static analyses on binaries.
 Several challenges must be overcome to do this. 
 They are, roughly:

- Loading a binary into the analysis program.
- Translating a binary into an intermediate representation (IR).
- Translating that IR into a semantic representation (i.e., what it *does*, not just what it *is*).
- Performing the actual analysis. This could be:
 - A partial or full-program static analysis (i.e., dependency analysis, program slicing).
 - A symbolic exploration of the program's state space (i.e., "Can we execute it until we find an overflow?").
 - Some combination of the above (i.e., "Let's execute only program slices that lead to a memory write, to find an overflow.")

angr has components that meet all of these challenges. 
This book will explain how each one works, and how they can all be used to accomplish your evil goals.

## Loading a Binary

After angr is installed, you can load a binary for analysis.
This process, and the angr component that powers it (called CLE) is described [here](./loading.md).

## Intermediate Representation

angr uses an intermediate representation (specifically, VEX) to enable it to run analyses on binaries of different architectures.
This IR is described [here](./ir.md).

## Solver Engine

Constraint solving and other computational needs are provided by an angr sub-module called Claripy.
Most users of angr will not need to know anything about Claripy, but documentation is provided in case it is needed.
Claripy is detailed [here](./claripy.md).

## Program States

angr provides an interface to the emulated machine states.
Understanding this is critical to successfully using angr.
It is detailed [here](./states.md).

## Program Paths

Programs can be analyzed in terms of the possible *path* that execution takes through them.
angr exposes information about what the paths execute and *do*.
[This section](./paths.md) gives an overview of how to use this capability of angr.

## Semantic Representation

A powerful feature of angr is the ability to represent basic blocks in terms of their effects on a program state.
In other words, angr can reason about what basic blocks *do*, not just what they *are*.
This is accomplished by a module named SimuVEX, further described [here](./simuvex.md).

## Symbolic Execution

angr provides a capable symbolic execution engine.
The interface to this engine, and how to use it, is described [here](./surveyors.md).

## Full-program Analysis

All of the above components come together to enable complex, full-program analyses to be easily run with angr.
The mechanism for running and writing these analyses is detailed [here](./analyses.md).

# Examples

We've written some examples for using angr!
You can read more [here](./examples.md).

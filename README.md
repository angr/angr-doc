# How to be Angry

This is a collection of documentation for angr. By reading this, you'll become and angr pro and will be able to fold binaries to your whim.

# What is Angr?

Angr is a multi-architecture binary analysis platform, with the capability to perform dynamic symbolic execution (like Mayhem, KLEE, etc) and various static analyses on binaries. Several challenges must be overcome to do this. They are, roughly:

- Loading a binary into the analysis program.
- Translating a binary into an intermediate representation (IR).
- Translating that IR into a semantic representation (i.e., what it *does*, not just what it *is*).
- Performing the actual analysis. This could be:
 - A full-program static analysis (i.e., type inference, program slicing).
 - A symbolic exploration of the program's state space (i.e., "Can we execute it until we find an overflow?").
 - Some combination of the above (i.e., "Let's execute only program slices that lead to a memory write, to find an overflow.")

Angr has components that meet all of these challenges. This document will explain how each one works, and how they can all be used to accomplish your evil goals.

# Using Angr

We've tried to make using Angr as pain-free as possible.
Our goal is to create the most user-friendly binary analysis platform, allowing one to simply start up iPython and easily perform extremely complex binary analyses with a couple of commands.
That being said, binary analysis is complex, which makes Angr complex.
We've tried to make life easier by providing this documentation, split into several sections for easier consumption.

## Installing Angr

Before Angr can be used, it must be installed.
Because Angr has **many** components and requires cross-compilers to be installed, this part has historically been rather tricky.
The best, modern, option is to install Angr through the use of the Angr Dockerfile.
This is detailed [here](https://git.seclab.cs.ucsb.edu/gitlab/angr/angr_docker/blob/master/README.md).

## Loading a Binary

After Angr is installed, you can load a binary for analysis.
This process, and the Angr component that powers it (called CLE) is described [here](./loading.md).

## Intermediate Representation

Angr uses an intermediate representation (specificaly, VEX) to enable it to run analyses on binaries of different architectures.
This IR is described [here](./ir.md)

## Solver Engine

Constraint solving and other computational needs are provided by an Angr sub-module called Claripy.
Most users of Angr will not need to know anything about Claripy, but documentation is provided in case it is needed.
Claripy is detailed [here](./claripy.md).

## Program States

Angr provides an interface to the emulated machine state.
Understanding this is critical to successfully using angr.
It is detailed [here](./states.md).

## Program Paths

Programs can be analyzed in terms of the possible *path* that execution takes through them.
Angr exposes information about what the paths execute and *do*.
[This section](./paths.md) gives an overview of how to use this capability of angr.

## Semantic Representation

A powerful feature of Angr is the ability to represent basic blocks in terms of their effects on a program state.
In other words, Angr can reason about what basic blocks *do*, not just what they *are*.
This is accomplished by a module named SimuVEX, further described [here](./simuvex.md).

## Symbolic Execution

Angr provides a capable symbolc execution engine.
The interface to this engine, and how to use it, is described [here](./surveyors.md).

## Full-program Analysis

All of the above components come together to enable complex, full-program analyses to be easily runnable in Angr.
The mechanism for running and writing these analyses is detailed [here](./analyses.md).

## Distributed Analysis

Angr comes with the ability to perform distributed analysis, with directions [here](./orgy.md).

## Coding rules
We try to get as close as the [PEP8 code convention](http://legacy.python.org/dev/peps/pep-0008/) as is reasonable without being dumb.
If you use Vim, the [python-mode](https://github.com/klen/python-mode) plugin does all you need. You can also [manually configure](https://wiki.python.org/moin/Vim) vim to adopt this behavior.

Most importantly, please consider the following when writing code as part of Angr:

- Try to use attribute access (see the `@property` decorator) instead of getters and setters wherever you can. This isn't Java, and attributes enable tab completion in iPython.
- DO NOT, under ANY circumstances, `raise Exception`. **Use the right exception type**. If there isn't a correct exception type, subclass the core exception of the module that you're working in (i.e. AngrError in Angr, SimError in SimuVEX, etc) and raise that. Note that the `assert` statement falls under this as well. We catch, and properly handle, the right types of errors in the right places, but AssertionError and Exception are not handled anywhere and force-terminate analyses.
- Avoid tabs, use space indentation instead. Even though it's wrong, the de-facto standard is 4 spaces. It is a good idea to adopt this from the beginning, as merging code that mixes both tab and space indentation is awful.
- Avoid super long lines. PEP8 recommends 80 character long lines. It's okay to have longer lines, but keep in mind that long lines are harder to read and should be avoided.
- Avoid extremely long functions, it is often better to break them up into smaller functions.
- Prefer _ to __ for private members (so that we can access them when debugging). *You* might not think that anyone has a need to call a given function, but trust us, you're wrong.
- **Document** your code. Every *class definition* and *public function definition* should have some description of:
 - What it does.
 - What are the type and the meaning of the parameters.
 - What it returns.
- If you're pushing a new feature, and it is not accompanied by a testcase, it **will be broken** in very short order. Please write testcases for your stuff.


# FAQ

We've collected miscellaneous questions about Angr, and answers to them, in a [FAQ](./faq.md).


# NOTE: this page is largely superfluous and exists more or less as a staging ground for the wip/the\_end\_times rewrite. It should not exist by the time we're done.

These are blurbs describing each of the sections that need to be rewritten.

### Solver Engine

angr's power comes not from it being an emulator, but from being able to execute with what we call _symbolic variables_. Instead of saying that a variable has a _concrete_ numerical value, we can say that it holds a _symbol_, effectively just a name. Then, performing arithmetic operations with that variable will yield a tree of operations \(termed an _abstract syntax tree \_or \_AST_, from compiler theory\). ASTs can be translated into constraints for an _SMT solver_, like z3, in order to ask questions like _"given the output of this sequence of operations, what must the input have been?"_ Here, you'll learn how to use angr to answer this.

### Program States

So far, we've only used angr's simulated program states \(SimState objects\) in the barest possible way in order to demonstrate basic concepts about angr's operation. Here, you'll learn about the structure of a state object and how to interact with it in a variety of useful ways.

### The Simulation Manager

The most important control interface in angr is the SimulationManager, which allows you to control symbolic execution over groups of states simultaneously, applying search strategies to explore a program's state space. Here, you'll learn how to use it.

### Intermediate Representation

In order to be able to analyze and execute machine code from different CPU architectures, such as MIPS, ARM, and PowerPC in addition to the classic x86, angr performs most of its analysis on an _intermediate representation_, a structured description of the fundamental actions performed by each CPU instruction. By understanding angr's IR, VEX \(which we borrowed from Valgrind\), you will be able to write very quick static analyses and have a better understanding of how angr works.


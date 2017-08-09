# NOTE: this page is largely superfluous and exists more or less as a staging ground for the wip/the\_end\_times rewrite. It should not exist by the time we're done.

These are blurbs describing each of the sections that need to be rewritten.

### Program States

So far, we've only used angr's simulated program states \(SimState objects\) in the barest possible way in order to demonstrate basic concepts about angr's operation. Here, you'll learn about the structure of a state object and how to interact with it in a variety of useful ways.

### The Simulation Manager

The most important control interface in angr is the SimulationManager, which allows you to control symbolic execution over groups of states simultaneously, applying search strategies to explore a program's state space. Here, you'll learn how to use it.

### Intermediate Representation

In order to be able to analyze and execute machine code from different CPU architectures, such as MIPS, ARM, and PowerPC in addition to the classic x86, angr performs most of its analysis on an _intermediate representation_, a structured description of the fundamental actions performed by each CPU instruction. By understanding angr's IR, VEX \(which we borrowed from Valgrind\), you will be able to write very quick static analyses and have a better understanding of how angr works.


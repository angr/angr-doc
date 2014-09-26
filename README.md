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

# Next steps

- [loading a binary](./loading.md)
- [Intermediate representation (IR)](./ir.md)
- [Semantic meaning](./semantic_meaning.md)c:w
- [FAQ](./faq.md)




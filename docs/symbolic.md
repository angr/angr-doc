Symbolic Execution
==================

Symbolic execution allows at a time T to determine for a branch all conditions
necessary to take the branch or not. Every variable is represented as a symbolic
value, and each branch as a constraint. Thus, symbolic execution allows us to
see which conditions allows the program to go from a point A to a point B, by
resolving the constraints.

Basic architecture of angr's symbolic execution:

- simuvex.md is the core engine and provides the concept of a [symbolic machine state](states.md)
- Also the [means to tick that state forward](simuvex.md) through simulating VEX or running python code
- Use [Paths](paths.md) to control execution easily and also to track history
- Use [Path Groups](pathgroups.md) to bulk-control execution

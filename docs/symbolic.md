Symbolic Execution
==================

TODO: would someone write an intro to the concept of symbolic execution, maybe just copy paste it from some paper

Basic archetecture of angr's symbolic execution:

- simuvex.md is the core engine and provides the concept of a [symbolic machine state](states.md)
- Also the [means to tick that state forward](simuvex.md) through simulating VEX or running python code
- Use [Paths](paths.md) to control execution easily and also to track history
- Use [Path Groups](pathgroups.md) to bulk-control execution

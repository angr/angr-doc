# Migrating to angr 7

The release of angr 7 introduces several departures from long-standing angr-isms.
While the community has created a compatibility layer to give external code written for angr 6 a good chance of working on angr 7, the best thing to do is to port it to the new version.
This document serves as a guide for this.

## SimuVEX is gone

angr versions up through angr 6 split the program analysis into two modules: `simuvex`, which was responsible for analyzing the effects of a single piece of code (whether a basic block or a SimProcedure) on a program state, and `angr`, which aggregated analyses of these basic blocks into program-level analysis such as control-flow recovery, symbolic execution, and so forth.
In theory, this would encourage for the encapsulation of block-level analyses, and allow other program analysis frameworks to build upon `simuvex` for their needs.
In practice, no one (to our knowledge) used `simuvex` without `angr`, and the separation introduced frustrating limitations (such as not being able to reference the history of a state from a SimInspect breakpoint) and duplication of code (such as the need to synchronize data from `state.scratch` into `path.history`).

Realizing that SimuVEX wasn't a usable independent package, we brainstormed about merging it into angr and further noticed that this would allow us to address the frustrations resulting from their separation.

All of the SimuVEX concepts (SimStates, SimProcedures, calling conventions, types, etc) have been migrated into angr.
The migration guide for common classes is bellow:

| Before | After |
|--------|-------|
| simuvex.SimState | angr.SimState |
| simuvex.SimProcedure | angr.SimProcedure |
| TODO: add more | |

## Removal of angr.Path

In angr, a Path object maintained references to a SimState and its history.
The fact that the history was separated from the state caused a lot of headaches when trying to analyze states inside a breakpoint, and caused overhead in synchronizing data from the state to its history.

In the new model, a state's history is maintained in a SimState plugin: `state.history`.
Since the path would now simply point to the state, we got rid of it.
The mapping of concepts is roughly as follows:

| Before | After |
|--------|-------|
| path | state |
| path.state | state |
| path.history | state.history |
| TODO: add more | |

## SimLibraries

TODO

## Changes in hooking

TODO

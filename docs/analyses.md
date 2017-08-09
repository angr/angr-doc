# Analyses

angr's goal is to make it easy to carry out useful analyses on binary programs.
This section will discuss how to run and create these analyses.

## Built-in Analyses

angr comes with several built-in analyses:

| Name                                        | Description                                                                                                                               |
| --------                                    | -------------                                                                                                                             |
| CFGFast                                     | Constructs a fast *Control Flow Graph* of the program. `b.analyses.CFG()` is what you want.                                               |
| [CFGAccurate](analyses/cfg_accurate.md)     | Constructs an accurate *Control Flow Graph* of the program. The simple way to do is via `b.analyses.CFGAccurate()`.                       |
| VFG                                         | Performs VSA on every function of the program, creating a *Value Flow Graph* and detecting stack variables.                               |
| DDG                                         | Calculates a data dependency graph, allowing one to determine what statements a given value depends on.                                   |
| [DFG](analyses/dfg.md)                      | Constructs a *Data Flow Graph* for each basic block present in the CFG                                                                    |
| [BackwardSlice](analyses/backward_slice.md) | Computes a backward slice of a program w.r.t. a certain target.                                                                           |
| [Identifier](analyses/identifier.md)        | Identifies common library functions in CGC binaries. |
| More!                                       | angr has quite a few analyses, most of which work! If you'd like to know how to use one, please submit an issue requesting documentation. |

### Resilience

Analyses can be written to be resilient, and catch and log basically any error.
These errors, depending on how they're caught, are logged to the `errors` or `named_errors` attribute of the analysis.
However, you might want to run an analysis in "fail fast" mode, so that errors are not handled.
To do this, the argument `fail_fast=True` can be passed into the analysis constructor.

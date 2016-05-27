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
| More!                                       | angr has quite a few analyses, most of which work! If you'd like to know how to use one, please submit an issue requesting documentation. |

### VFG

TODO

### DDG

TODO

## Running Analyses

Now that you understand how to load binaries in angr, and have some idea of angr's internals, we can discuss how to carry out analyses!
angr provides a standardized interface to perform analyses.

### Resilience

Analyses can be written to be resilient, and catch and log basically any error.
These errors, depending on how they're caught, are logged to the `errors` or `named_errors` attribute of the analysis.
However, you might want to run an analysis in "fail fast" mode, so that errors are not handled.
To do this, the `fail_fast` keyword argument can be passed into `analyze`.

```python
>> b.analyses.CFG(fail_fast=True)
```

## Creating Analyses

An analysis can be created by subclassing the `Analysis` class.
In this section, we'll create a mock analysis to show off the various features.
Let's start with something simple:

```python
>>> import angr

>>> class MockAnalysis(angr.Analysis):
... 	def __init__(self, option):
... 		self.option = option

>>> angr.register_analysis(MockAnalysis, 'MockAnalysis')
```

This is a quite simple analysis -- it takes an option, and stores it.
Of course, it's not useful, but what can you do?
Let's see how to call:

```python
>>> b = angr.Project("/bin/true")
>>> mock = b.analyses.MockAnalysis('this is my option')
>>> assert mock.option == 'this is my option'
```

### Working with projects

Via some python magic, your analysis will automatically have the project upon which you are running it under the `self.project` property.
Use this to interact with your project and analyze it!

```python
>>> class ProjectSummary(angr.Analysis):
...     def __init__(self):
...         self.result = 'This project is a %s binary with an entry point at %#x.' % (self.project.arch.name, self.project.entry)

>>> angr.register_analysis(ProjectSummary, 'ProjectSummary')
>>> b = angr.Project("/bin/true")

>>> summary = b.analyses.ProjectSummary()
>>> print summary.result
# 'This project is a AMD64 binary with an entry point at 0x401410.'
```



### Naming Analyses

The `register_analysis` call is what actually adds the analysis to angr.
Its arguments are the actual analysis class and the name of the analysis.
The name is how it appears under the `project.analyses` object.
Usually, you should use the same name as the analysis class, but if you want to use a shorter name, you can.

```python
>>> class FunctionBlockAverage(angr.Analysis):
...     def __init__(self):
...         self._cfg = self.project.analyses.CFG()
...         self.avg = len(self._cfg.nodes()) / len(self._cfg.function_manager.functions)

>>> angr.register_analysis(FunctionBlockAverage, 'FuncSize')
```

After this, you can call this analysis using it's specified name. For example, `b.analyses.FuncSize()`.

If you've registered a new analysis since loading the project, refresh the list of registered analyses on your project with `b.analyses.reload_analyses()`.

### Analysis Resilience

Sometimes, your (or our) code might suck and analyses might throw exceptions.
We understand, and we also understand that oftentimes a partial result is better than nothing.
This is specifically true when, for example, running an analysis on all of the functions in a program.
Even if some of the functions fails, we still want to know the results of the functions that do not.

To facilitate this, the `Analysis` base class provides a resilience context manager under `self._resilience`.
Here's an example:

```python
>>> class ComplexFunctionAnalysis(angr.Analysis):
...     def __init__(self):
...         self._cfg = self.project.analyses.CFG()
...         self.results = { }
...         for addr, func in self._cfg.function_manager.functions.iteritems():
...             with self._resilience():
...                 if addr % 2 == 0:
...                     raise ValueError("can't handle functions at even addresses")
...                 else:
...                     self.results[addr] = "GOOD"
```

The context manager catches any exceptions thrown and logs them (as a tuple of the exception type, message, and traceback) to `self.errors`.
These are also saved and loaded when the analysis is saved and loaded (although the traceback is discarded, as it is not picklable).

You can tune the effects of the resilience with two optional keyword parameters to `self._resilience()`.

The first is `name`, which affects where the error is logged.
By default, errors are placed in `self.errors`, but if `name` is provided, then instead the error is logged to `self.named_errors`, which is a dict mapping `name` to a list of all the errors that were caught under that name.
This allows you to easily tell where thrown without examining its traceback.

The second argument is `exception`, which should be the type of the exception that `_resilience` should catch.
This defaults to `Exception`, which handles (and logs) almost anything that could go wrong.
You can also pass a tuple of exception types to this option, in which case all of them will be caught.

Using `_resilience` has a few advantages:

1. Your exceptions are gracefully logged and easily accessible afterwards. This is really nice for writing testcases.
2. When creating your analysis, the user can pass `fail_fast=True`, which transparently disable the resilience, which is really nice for manual testing.
3. It's prettier than having `try`/`except` everywhere.

Have fun with analyses! Once you master the rest of angr, you can use analyses to understand anything computable!

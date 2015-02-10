# Analyses

Angr's goal is to make it easy to carry out useful analyses on binary programs.
These analyses might be complicated to run, so angr makes sure to save them when a project is saved and load them when it is loaded.
This section will discuss how to run and create these analyses.

## Running Analyses

Now that you understand how to load binaries in angr, and have some idea of angr's internals, we can discuss how to carry out analyses!
Angr provides a standardized interface to perform analyses. Specifically, it is:

```python
# load your project
p = angr.Project('/path/to/bin')

# generate a CFG
cfg = p.analyze('CFG')

# analyses are keyed by the analyses, and some options to the analysis
cfg_same = p.analyze('CFG')
assert cfg is cfg_same

# this means that you can track results for the same analysis with different options
context_sensitive_cfg = p.analyze('CFG', context_sensitivity=2)
context_sensitive_cfg_reference = p.analyze('CFG', context_sensitivity=2)
context_sensitive_cfg_copy = context_sensitive_cfg.copy()
assert context_sensitive_cfg is context_sensitive_cfg_reference
assert context_sensitive_cfg is not context_sensitive_cfg_copy
assert cfg is not context_sensitive_cfg
```

Results of analyses can be accessed by using the `Project.results` attribute.
If an analysis that hasn't been run is accessed, it will be automatically run with default options.
For example:

```python
cfg = p.analyze('CFG')
assert cfg is p.results.CFG

print "About to run the VSA analysis!"
print p.results.VSA
```

### Resilience

Analyses can be written to be resilient, and catch and log basically any error.
These errors, depending on how they're caught, are logged to the `errors` or `named_errors` attribute of the analysis.
However, you might want to run an analysis in "fail fast" mode, so that errors are not handled.
To do this, the `fail_fast` keyword argument can be passed into `analyze`.

```python
p.analyze('CFG', fail_fast=True)
```

### Built-in Analyses

Angr comes with several built-in analyses:

| Name | Description |
|------|-------------|
| CFG  | Constructs a *Control Flow Graph* of the program. The results are accessible via `p.analyze('CFG').cfg`. |
| VSA  | Performs VSA on every function of the program, creating a *Value Flow Graph* and detecting stack variables. |

## Creating Analyses

An analysis can be created by subclassing the `Analysis` class.
In this section, we'll create a mock analysis to show off the various features.
Let's start with something simple:

```python
class MockAnalysis(angr.Analysis):
	def __init__(self, option):
		self.option = option
```

This is a quite simple analysis -- it takes an option, and stores it.
Of course, it's not useful, but what can you do?
Let's see how to call:

```python
mock = p.analyze('MockAnalysis', 'this is my option')
assert mock.option == 'this is my option'
```

### Naming Analyses

By default, an analysis is named the same as the class.
However, sometimes you might want a shorter name.
You can do this by defining a `__name__` attribute:

```python
class FunctionBlockAverage(angr.Analysis):
	__name__ = 'FuncSize'

	def __init__(self):
		self._cfg = self._p.analyze('CFG')
		self.avg = len(self._cfg.nodes) / len(self._cfg.function_manager.functions)
```

After this, you can call this analysis using it's specified name. For example, `p.analyze('FuncSize')`.

### Analysis Resilience

Sometimes, your (or our) code might suck and analyses might throw exceptions.
We understand, and we also understand that oftentimes, a partial result is better than nothing.
This is specifically true when, for example, running an analysis on all of the functions of a class.
Even if some of the functions fails, we still want to know the results of the functions that do not.

To facilitate this, the `Analysis` base class provides a resilience context manager.
Here's an example:

```python
class ComplexFunctionAnalysis(angr.Analysis):
	def __init__(self):
		self._cfg = self._p.analyze('CFG')
		self.results = { }
		for addr,func in self._cfg.function_manager.functions.items():
			with self._resilience():
				if addr % 2 == 0:
					raise ValueError("can't handle functions at even addresses")
				else:
					self.results[addr] = "GOOD"
```

The context manager catches any exceptions thrown and logs them (as a tuple of the exception type, message, and traceback) to `self.errors`.
These are also saved and loaded when the analysis is saved and loaded (although the traceback is discarded, as it is not picklable).
`Analysis._resilience()` takes two optional keyword parameters.
The first is `name`, which is the name of the potential error.
If `name` is provided to `_resilience`, the error is placed in `self.named_errors[name]`.
The second argument is `exception`, which should be the type of the exception that `_resilience` should catch.
This defaults to `Exception`, which handles (and logs) almost anything that could go wrong.
You can also pass a tuple of exception types to this option, in which case all of them will be caught.

Using `_resilience` has a few advantages:

1. Your exceptions are gracefully logged and easily accessible afterwards. This is really nice for writing testcases.
2. When creating your analysis, the user can pass `fail_fast=True`, which transparently disable the resilience, which is really nice for manual testing.
3. It's prettier than having `try`/`except` everywhere.

### Analysis Functions

You might not be into the whole OO thing.
We still got your back.
You can implement analyses as functions and register them manually, like so.
Unfortunately, if you choose this route, you must handle all the options that angr pushes through the analyses (which are otherwise transparently handled).

```python
# define your function
def block_counter(project, deps, fail_fast, min_addr=0, max_addr=0xffffffff):
	return len([ irsb for irsb in deps[0].cfg.nodes if irsb.addr >= min_addr and irsb.addr < max_addr ])

# register the analysis
angr.registered_analyses['blocks'] = block_counter

# and run them!
p.analyze('block_counter', min_addr=0x100, max_addr=0x400000)
```

However, this doesn't provide any resilience and so forth.

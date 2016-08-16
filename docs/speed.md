# Speed considerations

The speed of angr as an analysis tool or emulator is greatly handicapped by the fact that it is written in python.
Regardless, there are a lot of optimizations and tweaks you can use to make angr faster.

## General tips

- *Use pypy*.
  [Pypy](http://pypy.org/) is an alternate python interpreter that performs optimized jitting of python code.
  In our tests, it's a 10x speedup out of the box.
- *Don't load shared libraries unless you need them*.
  The default setting in angr is to try at all costs to find shared libraries that are compatible with the binary you've loaded, including loading them straight out of your OS libraries.
  This can complicate things in a lot of scenarios.
  If you're performing an analysis that's anything more abstract than bare-bones symbolic execution, you might want to make the tradeoff of sacrificing accuracy for tractability.
  angr does a reasonable job of making sane things happen when library calls to functions that don't exist try to happen.
- *Use hooking and SimProcedures*.
  If you're enabling shared libraries, then you definitely want to have SimProcedures written for any complicated library function you're jumping into.
  If there's no autonomy requirement for this project, you can often isolate individual problem spots where analysis hangs up and summarize them with a hook.
- *Use SimInspect*.
  [SimInspect](simuvex.html#breakpoints) is the most underused and one of the most powerful features of angr.
  You can hook and modify almost any behavior of angr, including memory index resolution (which is often the slowest part of any angr analysis).
- *Write a concretization strategy*.
  A more powerful solution to the problem of memory index resolution is a [concretization strategy](https://git.seclab.cs.ucsb.edu/angr/simuvex/tree/master/simuvex/concretization_strategies).
- *Use the Replacement Solver*.
  You can enable it with the `simuvex.o.REPLACEMENT_SOLVER` state option.
  The replacement solver allows you to specify AST replacements that are applied at solve-time.
  If you add replacements so that all symbolic data is replaced with concrete data when it comes time to do the solve, the runtime is greatly increased.
  The API for adding a replacement is `state.se._solver.add_replacement(old, new)`.
  The replacement solver is a bit finicky, so there are some gotchas, but it'll definitely help.

## If you're performing lots of concrete or partially-concrete execution

- *Use the unicorn engine*.
  If you have [unicorn engine](https://github.com/unicorn/unicorn-engine) installed, Simuvex can be built to take advantage of it for concrete emulation.
  To enable it, add the options in the set `simuvex.o.unicorn` to your state.
  Keep in mind that while most items under `simuvex.o` are individual options, `simuvex.o.unicorn` is a bundle of options, and is thus a set.
  *NOTE*: At time of writing the official version of unicorn engine will not work with angr - we have a lot of patches to it to make it work well with angr.
  They're all pending pull requests at this time, so sit tight. If you're really impatient, ping us about uploading our fork!
- *Enable fast memory and fast registers*.
  The state options `simuvex.o.FAST_MEMORY` and `simuvex.o.FAST_REGISTERS` will do this.
  These will switch the memory/registers over to a less intensive memory model that sacrifices accuracy for speed.
  TODO: document the specific sacrifices. Should be safe for mostly concrete access though.
  NOTE: not compatible with concretization strategies.
- *Concretize your input ahead of time*.
  This is the approach taken by [driller](https://www.internetsociety.org/sites/default/files/blogs-media/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf).
  Before execution begins, we fill state.posix.files[0] with symbolic data representing the input, then constrain that symbolic data to what we want the input to be, then set a concrete file size (state.posix.files[0].size = whatever).
  If you don't require any tracking of the data coming from stdin, you can forego the symbolic part and just fill it with concrete data.
  If there are other sources of input besides standard input, do the same for those.
- *Use the afterburner*.
  While using unicorn, if you add the `UNICORN_THRESHOLD_CONCRETIZATION` state option, SimuVEX will accept thresholds after which it causes symbolic values to be concretized so that execution can spend more time in Unicorn. Specifically, the following thresholds exist:

  - `state.se.unicorn.concretization_threshold_memory` - this is the number of times a symbolic variable, stored in memory, is allowed to kick execution out of Unicorn before it is forcefully concretized and forced into Unicorn anyways.
  - `state.se.unicorn.concretization_threshold_registers` - this is the number of times a symbolic variable, stored in a register, is allowed to kick execution out of Unicorn before it is forcefully concretized and forced into Unicorn anyways.
  - `state.se.unicorn.concretization_threshold_instruction` - this is the number of times that any given instruction can force execution out of Unicorn (by running into symbolic data) before any symbolic data encountered at that instruction is concretized to force execution into Unicorn.

  You can get further control of what is and isn't concretized with the following sets:

  - `state.se.unicorn.always_concretize` - a set of variable names that will always be concretized to force execution into unicorn (in fact, the memory and register thresholds just end up causing variables to be added to this list).
  - `state.se.unicorn.never_concretize` - a set of variable names that will never be concretized and forced into Unicorn under any condition.
  - `state.se.unicorn.concretize_at` - a set of instruction addresses at which data should be concretized and forced into Unicorn. The instruction threshold causes addresses to be added to this set.

  Once something is concretized with the afterburner, you will lose track of that variable.
  The state will still be consistent, but you'll lose dependencies, as the stuff that comes out of Unicorn is just concrete bits with no memory of what variables they came from.
  Still, this might be worth it for the speed in some cases, if you know what you want to (or do not want to) concretize.
